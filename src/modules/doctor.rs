//! `anonify doctor`: preflight de **solo lectura**.
//!
//! `check` responde “¿hay fugas ahora mismo?”; `doctor` responde “¿puede este
//! sistema ejecutar el motor sin romper nada?”. Distingue tres cosas que suelen
//! confundirse:
//!
//! - **Fail**: el motor no puede funcionar correctamente en este estado (falta
//!   `nft`, el estado está corrupto o quedó una tabla huérfana que todavía
//!   filtra tráfico). Sale con código 1.
//! - **Warn**: el motor funcionaría, pero algo degrada la privacidad o la
//!   reversibilidad (swap en claro, `/etc/resolv.conf` gestionado por
//!   `systemd-resolved`, un SOCKS ajeno ocupando el 9050, sysctl no
//!   escribible). Sale con código 0.
//! - **Note**: dependencia opcional ausente; solo afecta a los módulos que la
//!   usan.
//!
//! Nada de lo que hace este módulo cambia el sistema: lee `/proc` y `/etc`,
//! busca binarios en `PATH`, abre un socket loopback y, como mucho, abre un
//! `sysctl` en modo escritura sin escribir nada. No se ejecutan `nft`, `tor`,
//! `nmcli` ni se crean archivos. Por eso `doctor` no exige root (aunque sin
//! root avisa de que `enable`/`restore` fallarán).
use crate::{
    i18n::{Lang, tr},
    mem,
    modules::{Module, killswitch, lan, tor},
    state::State,
    sys,
};
use anyhow::{Result, bail};
use serde::Serialize;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Severidad de un hallazgo. El orden es el de la gravedad.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Note,
    Warn,
    Fail,
}

impl Level {
    fn symbol(self) -> &'static str {
        match self {
            Level::Ok => "[\u{2713}]",
            Level::Note => "[*]",
            Level::Warn => "[!]",
            Level::Fail => "[\u{2717}]",
        }
    }
}

/// Un resultado del preflight. `id` es estable y forma parte del contrato de
/// `doctor --json` (se serializa como `code`, ver `docs/stability.md`);
/// `detail` es texto humano (en inglés, como el resto de los diagnósticos de
/// `check`).
#[derive(Serialize, Debug)]
pub struct Finding {
    #[serde(rename = "code")]
    pub id: &'static str,
    pub level: Level,
    pub detail: String,
}

impl Finding {
    fn ok(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            id,
            level: Level::Ok,
            detail: detail.into(),
        }
    }

    fn note(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            id,
            level: Level::Note,
            detail: detail.into(),
        }
    }

    fn warn(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            id,
            level: Level::Warn,
            detail: detail.into(),
        }
    }

    fn fail(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            id,
            level: Level::Fail,
            detail: detail.into(),
        }
    }
}

/// Hechos recogidos del sistema, sin interpretación. Separarlos de
/// [`evaluate`] permite probar la lógica de diagnóstico con sistemas
/// inventados, sin tocar la máquina que ejecuta los tests.
///
/// Los `bool` son observaciones independientes del entorno, no las variables
/// de una máquina de estados: agruparlas en enums solo escondería el hecho de
/// que cada una se comprueba por separado.
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct Facts {
    root: bool,
    kernel: String,
    distro: Option<String>,
    nft: bool,
    tor_binary: bool,
    tor_user: bool,
    wg_quick: bool,
    curl: bool,
    bwrap: bool,
    nmcli: bool,
    /// Claves de `sysctl::HARDEN` que no se pueden abrir en modo escritura.
    /// Listarlas (en vez de un solo `bool`) permite decir *cuáles* bloquean el
    /// módulo, que en un contenedor suelen ser las globales del kernel.
    sysctl_blocked: Vec<&'static str>,
    state_error: Option<String>,
    pending: Vec<String>,
    active: Vec<String>,
    orphan_tables: Vec<String>,
    resolved_stub: bool,
    socks_busy: bool,
    plain_swap: Vec<String>,
}

fn kernel_release() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn distro_name() -> Option<String> {
    let text = fs::read_to_string("/etc/os-release").ok()?;
    text.lines().find_map(|line| {
        line.strip_prefix("PRETTY_NAME=")
            .map(|v| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    })
}

/// Abrir un `sysctl` en modo escritura no cambia su valor: solo comprueba que
/// el módulo `sysctl` podrá aplicarlo. Se comprueba **la lista real** que el
/// módulo escribe, no una muestra: `sysctl` falla y revierte si una sola clave
/// no queda aplicada, así que un "listo" basado en dos claves de red sería
/// mentira en un contenedor, donde `kernel.*` es de solo lectura.
fn sysctl_blocked() -> Vec<&'static str> {
    crate::modules::sysctl::HARDEN
        .iter()
        .filter(|(key, _)| {
            let path = format!("/proc/sys/{}", key.replace('.', "/"));
            fs::OpenOptions::new().write(true).open(path).is_err()
        })
        .map(|(key, _)| *key)
        .collect()
}

/// `systemd-resolved` deja `/etc/resolv.conf` como symlink a su stub. El
/// módulo `dns` monta encima del archivo resuelto, pero resolved puede
/// reescribir el destino: conviene saberlo antes, no después.
fn resolved_stub() -> bool {
    fs::read_link("/etc/resolv.conf")
        .is_ok_and(|target| target.to_string_lossy().contains("systemd/resolve"))
}

/// ¿Hay alguien escuchando en el SOCKS de Tor? Solo un `connect` loopback, sin
/// enviar datos ni resolver nombres. Si además `tor` no está activo, es un
/// conflicto que el módulo tor rechazará al arrancar (`AddrInUse`).
fn socks_busy() -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], 9050));
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}

/// Tablas de anonify presentes en el kernel que ningún módulo activo reclama.
/// Suelen ser el resto de un `enable` interrumpido; si son `policy drop`,
/// pueden estar bloqueando tráfico sin que `status` lo muestre.
fn orphan_tables(st: &State) -> Vec<String> {
    [
        (Module::Tor, "inet anonify_tor", tor::present()),
        (Module::Killswitch, "inet anonify_ks", killswitch::present()),
        (Module::Lan, "inet anonify_lan", lan::present()),
    ]
    .into_iter()
    .filter(|(module, _, present)| *present && !st.active.contains(module))
    .map(|(_, name, _)| name.to_string())
    .collect()
}

fn names<'a>(mods: impl Iterator<Item = &'a Module>) -> Vec<String> {
    mods.map(|m| format!("{m:?}").to_lowercase()).collect()
}

fn collect() -> Facts {
    let mut facts = Facts {
        root: sys::is_root(),
        kernel: kernel_release().unwrap_or_else(|| "unknown".to_string()),
        distro: distro_name(),
        nft: sys::have("nft"),
        tor_binary: sys::have("tor"),
        tor_user: sys::run("id", &["-u", "tor"]).is_ok(),
        wg_quick: sys::have("wg-quick"),
        curl: sys::have("curl"),
        bwrap: sys::have("bwrap"),
        nmcli: sys::have("nmcli"),
        sysctl_blocked: sysctl_blocked(),
        resolved_stub: resolved_stub(),
        socks_busy: socks_busy(),
        plain_swap: mem::swap_warnings(),
        ..Facts::default()
    };
    match State::load() {
        Ok(st) => {
            facts.active = names(st.active.iter());
            facts.pending = names(st.pending.iter());
            // `nft` ausente ya es un blocker propio; no hace falta además
            // inventariar tablas que no se pueden consultar.
            if facts.nft {
                facts.orphan_tables = orphan_tables(&st);
            }
        }
        Err(e) => facts.state_error = Some(format!("{e:#}")),
    }
    facts
}

/// Estado propio: lo que puede impedir restaurar el sistema original.
fn state_findings(f: &Facts) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    if let Some(err) = &f.state_error {
        out.push(Finding::fail(
            "state",
            format!(
                "state is unreadable or corrupt ({err}); the original MAC/hostname/sysctl values \
                 may be lost. Reboot to drop the volatile changes before enabling anything."
            ),
        ));
    }
    if !f.pending.is_empty() {
        out.push(Finding::fail(
            "pending",
            format!(
                "modules {} have pending cleanup from a failed change; run `sudo anonify restore`",
                f.pending.join(", ")
            ),
        ));
    }
    if !f.orphan_tables.is_empty() {
        out.push(Finding::fail(
            "orphan-tables",
            format!(
                "nftables tables {} exist but no active module owns them; they may still be \
                 filtering traffic. Run `sudo anonify restore`.",
                f.orphan_tables.join(", ")
            ),
        ));
    }
    if f.active.is_empty() && f.state_error.is_none() {
        out.push(Finding::note(
            "active",
            "no module is active: the system is in its original configuration",
        ));
    } else if !f.active.is_empty() {
        out.push(Finding::ok(
            "active",
            format!("active modules: {}", f.active.join(", ")),
        ));
    }
    out
}

fn platform_findings(f: &Facts) -> Vec<Finding> {
    let mut out = vec![Finding::ok(
        "kernel",
        format!(
            "Linux {} ({})",
            f.kernel,
            f.distro.as_deref().unwrap_or("unknown distribution")
        ),
    )];
    if f.root {
        out.push(Finding::ok(
            "privileges",
            "running as root: the engine can apply changes",
        ));
    } else {
        out.push(Finding::warn(
            "privileges",
            "not running as root: enable/disable/restore/watch need root (`sudo anonify doctor`); \
             launch and anonify-browser do not",
        ));
    }
    out
}

fn dependency_findings(f: &Facts) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    if f.nft {
        out.push(Finding::ok("nft", "nftables found"));
    } else {
        out.push(Finding::fail(
            "nft",
            "nftables (`nft`) not found: the tor, killswitch and lan modules cannot be applied. \
             Install the nftables package.",
        ));
    }
    if f.tor_binary {
        out.push(Finding::ok("tor", "tor found"));
    } else {
        out.push(Finding::note(
            "tor",
            "tor not installed: the tor and dns modules will fail (optional unless you use them)",
        ));
    }
    if f.tor_binary && !f.tor_user {
        out.push(Finding::warn(
            "tor-user",
            "there is no `tor` system user: the tor module starts Tor as `tor` and will fail. \
             Install the distribution's tor package.",
        ));
    }
    if f.wg_quick {
        out.push(Finding::ok("wireguard", "wg-quick found"));
    } else {
        out.push(Finding::note(
            "wireguard",
            "wg-quick not installed: only the vpn module needs it (wireguard-tools)",
        ));
    }
    if f.curl {
        out.push(Finding::ok(
            "curl",
            "curl found: check can verify the Tor exit IP",
        ));
    } else {
        out.push(Finding::note(
            "curl",
            "curl not installed: check skips the Tor exit-IP verification (optional)",
        ));
    }
    if f.bwrap {
        out.push(Finding::ok(
            "bwrap",
            "bubblewrap found: launch --isolate is available",
        ));
    } else {
        out.push(Finding::note(
            "bwrap",
            "bubblewrap not installed: launch --isolate is unavailable (optional)",
        ));
    }
    if f.nmcli {
        out.push(Finding::ok("nmcli", "NetworkManager CLI found"));
    } else {
        out.push(Finding::note(
            "nmcli",
            "nmcli not found: the ipv6 module cannot enumerate NetworkManager devices (optional)",
        ));
    }
    out
}

/// Entorno que degrada privacidad o reversibilidad sin impedir el motor.
fn environment_findings(f: &Facts) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    if f.sysctl_blocked.is_empty() {
        out.push(Finding::ok(
            "sysctl",
            "every sysctl the module writes is writable: it can be applied and reverted",
        ));
    } else if !f.root {
        out.push(Finding::warn(
            "sysctl",
            "running without root: the sysctl module cannot write /proc/sys. Run \
             `sudo anonify enable ...` (this warning disappears once you do)",
        ));
    } else {
        let mut blocked = f.sysctl_blocked.join(", ");
        if f.sysctl_blocked.len() > 3 {
            blocked = format!(
                "{}, +{} more",
                f.sysctl_blocked[..3].join(", "),
                f.sysctl_blocked.len() - 3
            );
        }
        out.push(Finding::warn(
            "sysctl",
            format!(
                "cannot write {blocked}: read-only /proc or missing privileges (common in \
                 containers). The sysctl module refuses to apply partially, so it will fail \
                 and roll back instead of claiming it hardened the stack"
            ),
        ));
    }
    if f.resolved_stub {
        out.push(Finding::warn(
            "resolved",
            "/etc/resolv.conf points at systemd-resolved's stub: the dns module bind-mounts the \
             resolved file, but resolved may rewrite its target. Consider disabling the stub or \
             using tor without the dns module.",
        ));
    }
    if f.socks_busy && !f.active.iter().any(|m| m == "tor") {
        out.push(Finding::warn(
            "socks",
            "something is already listening on 127.0.0.1:9050 while the tor module is not active: \
             `enable tor` will refuse to start (another Tor, or a leftover process)",
        ));
    }
    for warning in &f.plain_swap {
        out.push(Finding::warn("swap", warning.clone()));
    }
    out
}

fn evaluate(f: &Facts) -> Vec<Finding> {
    let mut out = state_findings(f);
    out.extend(platform_findings(f));
    out.extend(dependency_findings(f));
    out.extend(environment_findings(f));

    let fails = out.iter().filter(|f| f.level == Level::Fail).count();
    let warns = out.iter().filter(|f| f.level == Level::Warn).count();
    if fails == 0 && warns == 0 {
        out.push(Finding::ok(
            "ready",
            "ready: this system can run every module it has dependencies for",
        ));
    }
    out
}

/// Forma estable de `anonify doctor --json`.
#[derive(Serialize)]
struct Report {
    ok: bool,
    kernel: String,
    distro: Option<String>,
    root: bool,
    active: Vec<String>,
    blockers: usize,
    warnings: usize,
    findings: Vec<Finding>,
}

pub fn run(lang: Lang, json: bool) -> Result<()> {
    let facts = collect();
    let findings = evaluate(&facts);
    let blockers = findings.iter().filter(|f| f.level == Level::Fail).count();
    let warnings = findings.iter().filter(|f| f.level == Level::Warn).count();

    if json {
        let report = Report {
            ok: blockers == 0,
            kernel: facts.kernel.clone(),
            distro: facts.distro.clone(),
            root: facts.root,
            active: facts.active.clone(),
            blockers,
            warnings,
            findings,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{}",
            tr(
                lang,
                "preflight (read-only): nothing was changed",
                "preflight (solo lectura): no se cambió nada"
            )
        );
        for finding in &findings {
            println!(
                "{} {:<14} {}",
                finding.level.symbol(),
                finding.id,
                finding.detail
            );
        }
        if blockers == 0 {
            let summary = tr(lang, "no blockers found.", "no se encontraron bloqueos.");
            if warnings == 0 {
                println!("{summary}");
            } else {
                println!(
                    "{summary} {warnings} {}",
                    tr(lang, "warning(s) above.", "aviso(s) arriba.")
                );
            }
        }
    }

    if blockers > 0 {
        bail!(
            "{} {}",
            blockers,
            tr(lang, "blocker(s) found", "bloqueo(s) encontrado(s)")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Facts {
        Facts {
            root: true,
            kernel: "6.12.0-test".to_string(),
            distro: Some("Arch Linux".to_string()),
            nft: true,
            tor_binary: true,
            tor_user: true,
            wg_quick: true,
            curl: true,
            bwrap: true,
            nmcli: true,
            ..Facts::default()
        }
    }

    fn levels(findings: &[Finding], level: Level) -> Vec<&'static str> {
        findings
            .iter()
            .filter(|f| f.level == level)
            .map(|f| f.id)
            .collect()
    }

    #[test]
    fn healthy_system_is_ready() {
        let findings = evaluate(&healthy());
        assert!(levels(&findings, Level::Fail).is_empty());
        assert!(levels(&findings, Level::Warn).is_empty());
        assert!(levels(&findings, Level::Ok).contains(&"ready"));
    }

    #[test]
    fn missing_nftables_is_a_blocker() {
        let mut facts = healthy();
        facts.nft = false;
        let findings = evaluate(&facts);
        assert_eq!(levels(&findings, Level::Fail), vec!["nft"]);
        assert!(!levels(&findings, Level::Ok).contains(&"ready"));
    }

    #[test]
    fn pending_cleanup_and_orphan_tables_are_blockers() {
        let mut facts = healthy();
        facts.pending = vec!["dns".to_string()];
        facts.orphan_tables = vec!["inet anonify_tor".to_string()];
        let findings = evaluate(&facts);
        let fails = levels(&findings, Level::Fail);
        assert!(fails.contains(&"pending"));
        assert!(fails.contains(&"orphan-tables"));
    }

    #[test]
    fn corrupt_state_is_a_blocker() {
        let mut facts = healthy();
        facts.state_error = Some("state.json está corrupto".to_string());
        let findings = evaluate(&facts);
        assert_eq!(levels(&findings, Level::Fail), vec!["state"]);
    }

    #[test]
    fn non_root_is_only_a_warning() {
        let mut facts = healthy();
        facts.root = false;
        let findings = evaluate(&facts);
        assert!(levels(&findings, Level::Fail).is_empty());
        assert!(levels(&findings, Level::Warn).contains(&"privileges"));
    }

    #[test]
    fn optional_tools_are_notes_not_warnings() {
        let mut facts = healthy();
        facts.wg_quick = false;
        facts.curl = false;
        facts.bwrap = false;
        facts.nmcli = false;
        facts.tor_binary = false;
        let findings = evaluate(&facts);
        assert!(levels(&findings, Level::Fail).is_empty());
        assert!(levels(&findings, Level::Warn).is_empty());
        for id in ["wireguard", "curl", "bwrap"] {
            assert!(levels(&findings, Level::Note).contains(&id), "{id}");
        }
    }

    #[test]
    fn environment_hazards_are_warnings() {
        let mut facts = healthy();
        facts.sysctl_blocked = vec!["kernel.kptr_restrict"];
        facts.resolved_stub = true;
        facts.socks_busy = true;
        facts.plain_swap = vec!["swap is active on /dev/sda2 without verified encryption".into()];
        let findings = evaluate(&facts);
        assert!(levels(&findings, Level::Fail).is_empty());
        let warns = levels(&findings, Level::Warn);
        for id in ["sysctl", "resolved", "socks", "swap"] {
            assert!(warns.contains(&id), "{id}");
        }
    }

    #[test]
    fn busy_socks_is_fine_when_tor_is_active() {
        let mut facts = healthy();
        facts.socks_busy = true;
        facts.active = vec!["tor".to_string()];
        let findings = evaluate(&facts);
        assert!(!levels(&findings, Level::Warn).contains(&"socks"));
    }

    #[test]
    fn missing_tor_user_is_a_warning() {
        let mut facts = healthy();
        facts.tor_user = false;
        let findings = evaluate(&facts);
        assert!(levels(&findings, Level::Warn).contains(&"tor-user"));
    }

    #[test]
    fn json_levels_are_stable_and_lowercase() {
        let value = serde_json::to_value(Finding::fail("x", "y")).expect("json");
        assert_eq!(value["level"], "fail");
        assert_eq!(value["code"], "x");
        let value = serde_json::to_value(Finding::note("x", "y")).expect("json");
        assert_eq!(value["level"], "note");
    }
}
