mod banner;
mod i18n;
mod mem;
mod modules;
mod state;
mod sys;
mod watch;
mod watchdog;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use i18n::{tr, Lang};
use modules::{check, dns, hostname, ipv6, killswitch, launch, mac, sysctl, tor, vpn, Module};
use state::State;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "anonify",
    version,
    about = "Temporary, reversible network privacy hardening for Linux"
)]
struct Cli {
    /// Force a language instead of auto-detecting from the OS locale (en, es)
    #[arg(long, global = true)]
    lang: Option<String>,

    /// Suppress the startup banner and decorative status output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Safety net: automatically run `restore` after N seconds, no matter
    /// what. Use this while testing modules that can cut your own network
    /// (tor, dns, killswitch) so a mistake can't lock you out for good.
    #[arg(long, global = true, value_name = "SECONDS")]
    timeout: Option<u64>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enable modules (--all = mac, hostname, sysctl, ipv6, tor, dns)
    Enable {
        modules: Vec<Module>,
        #[arg(long)]
        all: bool,
        /// `WireGuard` config for the `vpn` module
        #[arg(long)]
        vpn_conf: Option<PathBuf>,
        /// MAC policy for the `mac` module: local (default), random vendor,
        /// or a specific OUI family (intel, apple, cisco, dell, samsung,
        /// tp-link, realtek, raspberry)
        #[arg(long, value_enum, value_name = "VENDOR")]
        mac_vendor: Option<mac::Vendor>,
    },
    /// Disable modules (no arguments: all active ones)
    Disable { modules: Vec<Module> },
    /// Revert everything to its original state
    Restore,
    /// Re-randomize the MAC addresses and hostname of the active `mac` and
    /// `hostname` modules without touching the saved originals
    Rotate,
    /// Show active modules and detect drift
    Status {
        /// Machine-readable JSON on stdout (stable field names)
        #[arg(long)]
        json: bool,
    },
    /// Fail-closed leak checks (no clear-net requests)
    Check {
        /// Machine-readable JSON on stdout (stable field names)
        #[arg(long)]
        json: bool,
    },
    /// Watch for configuration drift and optionally restore on the first hit
    Watch(WatchArgs),
    /// Launch apps (`VirtualBox`, `Proton VPN`, or an arbitrary command)
    /// with a sanitized environment and dropped privileges
    Launch(LaunchArgs),
}

#[derive(clap::Args)]
struct WatchArgs {
    /// Seconds between checks (minimum 1)
    #[arg(long, default_value_t = 10, value_name = "SECONDS")]
    interval: u64,
    /// Run a full restore and exit on the first drift
    #[arg(long)]
    restore: bool,
    /// Check once and exit (status 1 when there is drift)
    #[arg(long)]
    once: bool,
}

#[derive(clap::Args)]
struct LaunchArgs {
    /// Timezone for the launched app only (TZ); never touches the system clock
    #[arg(long, default_value = "UTC", value_name = "ZONE")]
    tz: String,
    /// Locale for the launched app only (`LANG`/`LC_ALL`)
    #[arg(long, default_value = "C.UTF-8", value_name = "LOCALE")]
    lang: String,
    /// Skip environment masking and capability hardening (still never root under sudo)
    #[arg(long)]
    no_sandbox: bool,
    /// Run inside a bubblewrap sandbox: read-only /usr and /etc, private /tmp
    /// and HOME, own hostname, and no network unless --allow-net
    #[arg(long)]
    isolate: bool,
    /// Keep host network access inside the sandbox (default: offline)
    #[arg(long)]
    allow_net: bool,
    /// Hostname inside the sandbox (default: random `host-xxxxxxxx`)
    #[arg(long, value_name = "NAME")]
    hostname: Option<String>,
    /// Bind this directory read-write as HOME instead of an empty tmpfs
    #[arg(long, value_name = "PATH")]
    home: Option<PathBuf>,
    #[command(subcommand)]
    action: LaunchAction,
}

#[derive(Subcommand)]
enum LaunchAction {
    Vbox {
        vm: Option<String>,
    },
    Proton,
    Exec {
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
}

/// Best-effort: keep this process out of swap. Not a system change and not
/// fatal if the kernel refuses (for example, a low `RLIMIT_MEMLOCK`).
fn lock_memory(lang: Lang) {
    if let Err(e) = mem::lock_process() {
        eprintln!(
            "[!] {}: {e:#}",
            tr(
                lang,
                "could not lock memory pages in RAM",
                "no se pudo fijar la memoria del proceso en RAM"
            )
        );
    }
}

fn run_launch(lang: Lang, args: LaunchArgs) -> Result<()> {
    if !args.isolate && (args.allow_net || args.hostname.is_some() || args.home.is_some()) {
        bail!(
            "{}",
            tr(
                lang,
                "--allow-net, --hostname and --home only make sense together with --isolate",
                "--allow-net, --hostname y --home solo tienen sentido junto a --isolate"
            )
        );
    }
    let sandbox = launch::Sandbox {
        tz: args.tz,
        lang: args.lang,
        enabled: !args.no_sandbox,
    };
    // `--allow-net` entrega la red del host tal cual: si no hay una capa de
    // anonimato activa, la app sale en claro. Aviso, no bloqueo: puede ser
    // intencionado (probar algo local), pero no debe pasar desapercibido.
    if args.isolate && args.allow_net {
        let protected = State::load().is_ok_and(|st| {
            [Module::Tor, Module::Vpn, Module::Killswitch]
                .iter()
                .any(|m| st.active.contains(m))
        });
        if !protected {
            eprintln!(
                "[!] {}",
                tr(
                    lang,
                    "--allow-net gives the sandbox your real network with no tor/vpn/killswitch active: the app will leak your IP",
                    "--allow-net le da al sandbox tu red real sin tor/vpn/killswitch activos: la app filtrará tu IP"
                )
            );
        }
    }
    let isolate = args.isolate.then(|| launch::Isolate {
        net: args.allow_net,
        hostname: args.hostname.clone(),
        home: args.home.clone(),
    });
    let iso = isolate.as_ref();
    match args.action {
        LaunchAction::Vbox { vm } => launch::vbox(vm.as_deref(), &sandbox, iso),
        LaunchAction::Proton => launch::proton(&sandbox, iso),
        LaunchAction::Exec { cmd } => launch::spawn(&cmd[0], &cmd[1..], &sandbox, iso),
    }
}

fn activate(m: Module, st: &mut State, conf: Option<&Path>, vendor: mac::Vendor) -> Result<()> {
    match m {
        Module::Mac => mac::enable(st, vendor),
        Module::Hostname => hostname::enable(st),
        Module::Sysctl => sysctl::apply(st, sysctl::HARDEN),
        Module::Ipv6 => ipv6::enable(st),
        Module::Vpn => vpn::enable(st, conf),
        Module::Dns => dns::enable(st),
        Module::Tor => tor::enable(),
        Module::Killswitch => killswitch::enable(st),
    }
}

fn deactivate(m: Module, st: &mut State) -> Result<()> {
    match m {
        Module::Mac => mac::disable(st),
        Module::Hostname => hostname::disable(st),
        Module::Sysctl => sysctl::revert(st, sysctl::HARDEN),
        Module::Ipv6 => ipv6::disable(st),
        Module::Vpn => vpn::disable(st),
        Module::Dns => dns::disable(st),
        Module::Tor => tor::disable(),
        Module::Killswitch => killswitch::disable(),
    }
}

fn save_or_warn(st: &State, context: &str) {
    if let Err(e) = st.save() {
        eprintln!("[!] {context}: {e:#}");
    }
}

/// Intenta limpiar módulos que quedaron a medias en una ejecución anterior.
/// Si no se puede, se aborta antes de añadir más cambios encima.
fn cleanup_pending(lang: Lang, st: &mut State) -> Result<()> {
    if st.pending.is_empty() {
        return Ok(());
    }
    println!(
        "[*] {}: {:?}",
        tr(lang, "cleaning pending state", "limpiando estado pendiente"),
        st.pending
    );
    let pending: Vec<Module> = Module::ALL
        .iter()
        .rev()
        .copied()
        .filter(|m| st.pending.contains(m))
        .collect();
    for m in pending {
        deactivate(m, st).map_err(|e| {
            anyhow::anyhow!(
                "{m:?} {}: {e:#}. {}",
                tr(
                    lang,
                    "pending cleanup failed",
                    "falló la limpieza pendiente"
                ),
                tr(
                    lang,
                    "run `sudo anonify restore` and inspect the system.",
                    "Ejecuta `sudo anonify restore` e inspecciona el sistema."
                )
            )
        })?;
        st.active.remove(&m);
        st.pending.remove(&m);
        st.save()?;
    }
    Ok(())
}

fn rollback(st: &mut State, mods: &[Module]) -> Vec<String> {
    let mut errors = vec![];
    for m in mods.iter().rev().copied() {
        match deactivate(m, st) {
            Ok(()) => {
                st.active.remove(&m);
                st.pending.remove(&m);
            }
            Err(e) => {
                st.pending.insert(m);
                errors.push(format!("{m:?}: {e:#}"));
            }
        }
    }
    errors
}

fn enable(
    lang: Lang,
    mut mods: Vec<Module>,
    all: bool,
    conf: Option<&Path>,
    vendor: mac::Vendor,
) -> Result<()> {
    if all {
        mods.extend_from_slice(Module::DEFAULT_SET);
    }
    if mods.is_empty() {
        bail!(
            "{}",
            tr(
                lang,
                "specify modules or use --all (see `anonify enable --help`)",
                "indica módulos o usa --all (ver `anonify enable --help`)"
            )
        );
    }
    mods.sort();
    mods.dedup();

    // Held for the whole function so a watchdog trip (Ctrl+C / SIGTERM /
    // --timeout) running `disable()` on another thread can't read or write
    // state.json while we're mid-sequence here.
    let _lock = state::Lock::acquire()?;
    let mut st = State::load()?;
    cleanup_pending(lang, &mut st)?;

    let mut activated_now: Vec<Module> = vec![];
    for m in mods {
        if st.active.contains(&m) {
            println!("[=] {m:?} {}", tr(lang, "already active", "ya activo"));
            continue;
        }
        println!(
            "[+] {} {m:?}: {}",
            tr(lang, "enabling", "activando"),
            m.desc(lang)
        );
        if let Err(e) = activate(m, &mut st, conf, vendor) {
            // The failed module may have left partial state; clean it too.
            let mut to_rollback = activated_now.clone();
            to_rollback.push(m);
            let rollback_errors = rollback(&mut st, &to_rollback);
            save_or_warn(&st, "no se pudo guardar el estado tras el rollback");
            if rollback_errors.is_empty() {
                bail!(
                    "{m:?} {}: {e:#}\n    {}",
                    tr(lang, "failed", "falló"),
                    tr(
                        lang,
                        "all changes from this run were rolled back.",
                        "todos los cambios de esta ejecución se revirtieron."
                    )
                );
            }
            bail!(
                "{m:?} {}: {e:#}\n    {}: {}\n    {}",
                tr(lang, "failed", "falló"),
                tr(lang, "rollback incomplete", "rollback incompleto"),
                rollback_errors.join("; "),
                tr(
                    lang,
                    "run `sudo anonify restore` and inspect the system.",
                    "Ejecuta `sudo anonify restore` e inspecciona el sistema."
                )
            );
        }
        st.active.insert(m);
        if let Err(e) = st.save() {
            // We cannot leave a module active without its original values on
            // disk: roll back everything from this run before bailing.
            let mut to_rollback = activated_now.clone();
            to_rollback.push(m);
            let rollback_errors = rollback(&mut st, &to_rollback);
            save_or_warn(&st, "no se pudo guardar el estado tras el rollback");
            bail!(
                "{}: {e:#}{}",
                tr(
                    lang,
                    "could not save restore state; rolled back this run",
                    "no se pudo guardar el estado de restauración; se revirtió esta ejecución"
                ),
                if rollback_errors.is_empty() {
                    String::new()
                } else {
                    format!(
                        "\n    {}: {}",
                        tr(lang, "rollback incomplete", "rollback incompleto"),
                        rollback_errors.join("; ")
                    )
                }
            );
        }
        activated_now.push(m);
    }
    if st.active.contains(&Module::Vpn) && !st.active.contains(&Module::Killswitch) {
        eprintln!(
            "[!] {}",
            tr(
                lang,
                "VPN is active without `killswitch`: traffic can escape outside the tunnel. Run `anonify enable killswitch` to enforce it.",
                "la VPN está activa sin `killswitch`: el tráfico puede salir fuera del túnel. Ejecuta `anonify enable killswitch` para forzarlo."
            )
        );
    }
    Ok(())
}

fn disable(lang: Lang, mods: Vec<Module>) -> Result<()> {
    // Same reasoning as in `enable()`: serialize against a concurrent
    // watchdog-triggered restore.
    let _lock = state::Lock::acquire()?;
    let (mut st, corrupt) = match State::load() {
        Ok(st) => (st, false),
        Err(e) => {
            eprintln!("[!] {e:#}");
            eprintln!(
                "[!] {}",
                tr(
                    lang,
                    "attempting best-effort cleanup of firewall/DNS/Tor; original MAC/hostname/sysctl values are unavailable. Reboot to fully reset them.",
                    "intentando limpieza best-effort de firewall/DNS/Tor; los valores originales de MAC/hostname/sysctl no están disponibles. Reinicia para resetearlos por completo."
                )
            );
            (State::default(), true)
        }
    };
    let mut list: Vec<Module> = if mods.is_empty() {
        Module::ALL.to_vec()
    } else {
        mods
    };
    list.sort();
    list.dedup();
    // DNS depends on Tor's DNSPort. If Tor goes away, leaving the bind mount
    // behind would break resolution and leave a stale active module.
    if list.contains(&Module::Tor) && !list.contains(&Module::Dns) {
        println!(
            "[*] {}",
            tr(
                lang,
                "tor is being disabled; dns will be disabled first",
                "se desactiva tor; dns se desactivará primero"
            )
        );
        list.push(Module::Dns);
        list.sort();
        list.dedup();
    }

    let mut errors: Vec<String> = vec![];
    for m in list.into_iter().rev() {
        println!("[-] {} {m:?}", tr(lang, "disabling", "desactivando"));
        match deactivate(m, &mut st) {
            Ok(()) => {
                st.active.remove(&m);
                st.pending.remove(&m);
                if !corrupt {
                    save_or_warn(&st, "no se pudo guardar el estado");
                }
            }
            Err(e) => {
                eprintln!("    {}: {e:#}", tr(lang, "warning", "aviso"));
                st.pending.insert(m);
                errors.push(format!("{m:?}: {e:#}"));
                if !corrupt {
                    save_or_warn(&st, "no se pudo guardar el estado pendiente");
                }
            }
        }
    }
    if !corrupt {
        save_or_warn(&st, "no se pudo guardar el estado final");
    }
    if st.active.contains(&Module::Killswitch)
        && !st.active.contains(&Module::Vpn)
        && !st.active.contains(&Module::Tor)
    {
        eprintln!(
            "[!] {}",
            tr(
                lang,
                "killswitch remains active without VPN/Tor: all non-loopback traffic is blocked.",
                "killswitch sigue activo sin VPN/Tor: todo el tráfico no-loopback está bloqueado."
            )
        );
    }
    if !errors.is_empty() {
        bail!(
            "{}: {}",
            tr(
                lang,
                "some modules could not be restored",
                "algunos módulos no se pudieron restaurar"
            ),
            errors.join("; ")
        );
    }
    Ok(())
}

/// Re-randomizes the identities of the active `mac`/`hostname` modules
/// without losing the saved originals, so `restore` still works.
///
/// Useful between sessions on the same network (longer-lived observers can
/// correlate a MAC or hostname over time). Only volatile identifier state is
/// touched; nothing is written to disk.
fn rotate(lang: Lang) -> Result<()> {
    let _lock = state::Lock::acquire()?;
    let mut st = State::load()?;
    let rotate_mac = st.active.contains(&Module::Mac);
    let rotate_hostname = st.active.contains(&Module::Hostname);
    if !rotate_mac && !rotate_hostname {
        bail!(
            "{}",
            tr(
                lang,
                "nothing to rotate: enable `mac` or `hostname` first",
                "nada que rotar: activa `mac` o `hostname` primero"
            )
        );
    }
    if rotate_mac {
        // Misma política que en `enable mac --mac-vendor`; el estado viejo
        // (sin el campo) cae en `local`.
        let vendor = st
            .mac_vendor
            .as_deref()
            .and_then(mac::Vendor::parse)
            .unwrap_or_default();
        println!(
            "[*] {}",
            tr(lang, "rotating MAC addresses", "rotando direcciones MAC")
        );
        mac::enable(&mut st, vendor)?;
        st.save()?;
    }
    if rotate_hostname {
        println!("[*] {}", tr(lang, "rotating hostname", "rotando hostname"));
        hostname::enable(&mut st)?;
        st.save()?;
    }
    println!(
        "[\u{2713}] {}",
        tr(lang, "identities rotated", "identidades rotadas")
    );
    Ok(())
}

fn check(lang: Lang, json: bool) -> Result<()> {
    check::run(lang, json)
}

/// Parses argv, showing the banner even on clap's early-exit paths.
///
/// clap handles `--help`/`-h`, `--version`, and a missing/invalid subcommand
/// internally and exits before ever returning a `Cli` value. To still show the
/// banner there (bare `anonify`, `anonify -h`), we pre-scan the raw args for
/// `--quiet`/`-q` and `--lang` — the only flags the banner needs — and print
/// it ourselves before handing off to clap's own exit.
fn parse_cli() -> Cli {
    let raw: Vec<String> = std::env::args().collect();
    let quiet_pre = raw.iter().any(|a| a == "-q" || a == "--quiet");
    let lang_pre = raw
        .iter()
        .position(|a| a == "--lang")
        .and_then(|i| raw.get(i + 1))
        .cloned()
        .or_else(|| {
            raw.iter().find_map(|a| {
                a.strip_prefix("--lang=")
                    .map(std::string::ToString::to_string)
            })
        });
    let lang_pre = Lang::resolve(lang_pre.as_deref());

    match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            banner::show(lang_pre, quiet_pre);
            e.exit();
        }
    }
}

/// Armed for every command that can leave network state half-applied if
/// interrupted (enable/disable/restore). Status/check/watch/launch don't
/// change state on their own, so Ctrl+C there can use the default behavior.
fn arm_safety_net(lang: Lang, timeout: Option<u64>, cmd: &Cmd) {
    if !matches!(
        cmd,
        Cmd::Enable { .. } | Cmd::Disable { .. } | Cmd::Rotate | Cmd::Restore
    ) {
        return;
    }
    let timeout = timeout.map(Duration::from_secs);
    watchdog::arm(lang, timeout, move |trip| {
        let reason = match trip {
            watchdog::Trip::Signal => tr(lang, "interrupted", "interrumpido"),
            watchdog::Trip::Timeout => tr(lang, "timeout reached", "tiempo límite alcanzado"),
        };
        eprintln!(
            "\n[!] {reason} \u{2014} {}",
            tr(lang, "running restore...", "ejecutando restore...")
        );
        // Blocks on the state lock until whatever module step is currently in
        // flight on the main thread finishes — this can't preempt a blocking
        // syscall mid-flight, only guarantee cleanup runs right after it. See
        // module docs in watchdog.rs.
        match disable(lang, vec![]) {
            Ok(()) => eprintln!(
                "[\u{2713}] {}",
                tr(
                    lang,
                    "restore complete, exiting",
                    "restore completo, saliendo"
                )
            ),
            Err(e) => eprintln!(
                "[\u{2717}] {}: {e:#}",
                tr(
                    lang,
                    "restore incomplete, inspect the system",
                    "restore incompleto, inspecciona el sistema"
                )
            ),
        }
        std::process::exit(130);
    });
}

fn main() -> Result<()> {
    let cli = parse_cli();
    let lang = Lang::resolve(cli.lang.as_deref());
    banner::show(lang, cli.quiet);

    lock_memory(lang);

    if !matches!(cli.cmd, Cmd::Launch(_)) && !sys::is_root() {
        bail!(
            "{}",
            tr(
                lang,
                "anonify requires root: use `sudo anonify ...`",
                "anonify necesita root: usa `sudo anonify ...`"
            )
        );
    }
    arm_safety_net(lang, cli.timeout, &cli.cmd);
    dispatch(cli.cmd, lang)
}

fn dispatch(cmd: Cmd, lang: Lang) -> Result<()> {
    match cmd {
        Cmd::Enable {
            modules,
            all,
            vpn_conf,
            mac_vendor,
        } => {
            let wants = |m: Module| all || modules.contains(&m);
            if mac_vendor.is_some() && !wants(Module::Mac) {
                eprintln!(
                    "[!] {}",
                    tr(
                        lang,
                        "--mac-vendor is ignored because the mac module is not being enabled",
                        "--mac-vendor se ignora porque el módulo mac no se está activando"
                    )
                );
            }
            if vpn_conf.is_some() && !wants(Module::Vpn) {
                eprintln!(
                    "[!] {}",
                    tr(
                        lang,
                        "--vpn-conf is ignored because the vpn module is not being enabled",
                        "--vpn-conf se ignora porque el módulo vpn no se está activando"
                    )
                );
            }
            enable(
                lang,
                modules,
                all,
                vpn_conf.as_deref(),
                mac_vendor.unwrap_or_default(),
            )?;
            settle_check(lang)
        }
        Cmd::Disable { modules } => disable(lang, modules),
        Cmd::Rotate => rotate(lang),
        Cmd::Restore => {
            disable(lang, vec![])?;
            println!(
                "[\u{2713}] {}",
                tr(
                    lang,
                    "system restored to its original configuration",
                    "sistema restaurado a su configuración original"
                )
            );
            Ok(())
        }
        Cmd::Status { json } => status(lang, json),
        Cmd::Check { json } => check(lang, json),
        Cmd::Watch(args) => watch::run(
            lang,
            &watch::Options {
                interval: args.interval,
                restore: args.restore,
                once: args.once,
            },
            || disable(lang, vec![]),
        ),
        Cmd::Launch(args) => run_launch(lang, args),
    }
}

/// `NetworkManager` and other daemons can revert changes seconds later: wait and re-verify.
fn settle_check(lang: Lang) -> Result<()> {
    std::thread::sleep(std::time::Duration::from_secs(20));
    let st = State::load()?;
    if !st.pending.is_empty() {
        bail!(
            "{}: {:?}",
            tr(lang, "pending cleanup remains", "queda limpieza pendiente"),
            st.pending
        );
    }
    let lost: Vec<String> = st
        .active
        .iter()
        .filter(|m| !m.holds(&st))
        .map(|m| format!("{m:?}"))
        .collect();
    if !lost.is_empty() {
        bail!(
            "{}: {}. {}",
            tr(
                lang,
                "WARNING: no longer applied",
                "ATENCIÓN: ya no están aplicados"
            ),
            lost.join(", "),
            tr(
                lang,
                "Something on the system reverted them; run `anonify status`.",
                "Algo del sistema los revirtió; ejecuta `anonify status`."
            )
        );
    }
    println!(
        "[\u{2713}] {}",
        tr(
            lang,
            "verified: everything still applied after 20s",
            "verificado: todo sigue aplicado tras 20 s"
        )
    );
    Ok(())
}

#[derive(serde::Serialize)]
struct StatusModule {
    module: String,
    active: bool,
    pending: bool,
    applied: bool,
}

/// Forma estable de `anonify status --json`.
#[derive(serde::Serialize)]
struct StatusReport {
    drift: bool,
    active: Vec<String>,
    pending: Vec<String>,
    modules: Vec<StatusModule>,
}

fn status(lang: Lang, json: bool) -> Result<()> {
    let st = State::load()?;
    let mut drift = false;
    let mut modules: Vec<StatusModule> = Vec::new();
    for &m in Module::ALL {
        let active = st.active.contains(&m);
        let pending = st.pending.contains(&m);
        let applied = active && m.holds(&st);
        if pending || (active && !applied) {
            drift = true;
        }
        modules.push(StatusModule {
            module: format!("{m:?}").to_lowercase(),
            active,
            pending,
            applied,
        });
        if json {
            continue;
        }
        let tag = if pending {
            "!!"
        } else if !active {
            "off"
        } else if applied {
            "ON "
        } else {
            "ON!"
        };
        println!(
            "[{tag}] {:<11} {}",
            format!("{m:?}").to_lowercase(),
            m.desc(lang)
        );
        if pending {
            println!(
                "        \u{26a0} {}",
                tr(
                    lang,
                    "partial state from a failed change; run `anonify restore`",
                    "estado parcial de un cambio fallido; ejecuta `anonify restore`"
                )
            );
        } else if active && !applied {
            println!(
                "        \u{26a0} {}",
                tr(
                    lang,
                    "listed as active but the system no longer has it applied",
                    "figura activo pero el sistema ya NO lo tiene aplicado"
                )
            );
        }
    }
    if json {
        let report = StatusReport {
            drift,
            active: modules
                .iter()
                .filter(|m| m.active)
                .map(|m| m.module.clone())
                .collect(),
            pending: modules
                .iter()
                .filter(|m| m.pending)
                .map(|m| m.module.clone())
                .collect(),
            modules,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    if drift {
        std::process::exit(1);
    }
    Ok(())
}
