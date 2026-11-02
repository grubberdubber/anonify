mod banner;
mod i18n;
mod modules;
mod state;
mod sys;
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
    },
    /// Disable modules (no arguments: all active ones)
    Disable { modules: Vec<Module> },
    /// Revert everything to its original state
    Restore,
    /// Show active modules and detect drift
    Status,
    /// Fail-closed leak checks (no clear-net requests)
    Check,
    /// Launch apps (`VirtualBox`, `Proton VPN`, or an arbitrary command)
    #[command(subcommand)]
    Launch(Launch),
}

#[derive(Subcommand)]
enum Launch {
    Vbox {
        vm: Option<String>,
    },
    Proton,
    Exec {
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
}

fn activate(m: Module, st: &mut State, conf: Option<&Path>) -> Result<()> {
    match m {
        Module::Mac => mac::enable(st),
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

fn enable(lang: Lang, mut mods: Vec<Module>, all: bool, conf: Option<&Path>) -> Result<()> {
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
        if let Err(e) = activate(m, &mut st, conf) {
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

fn check(lang: Lang) -> Result<()> {
    check::run(lang)
}

fn main() -> Result<()> {
    // clap handles `--help`/`-h`, `--version`, and a missing/invalid
    // subcommand internally and exits before ever returning a `Cli` value.
    // To still show the banner on those paths (bare `anonify`, `anonify -h`),
    // we pre-scan the raw args for `--quiet`/`-q` and `--lang` — the only
    // flags the banner needs — and print it ourselves before handing off to
    // clap's own exit.
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

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            banner::show(lang_pre, quiet_pre);
            e.exit();
        }
    };
    let lang = Lang::resolve(cli.lang.as_deref());
    banner::show(lang, cli.quiet);

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
    // Armed for every command that can leave network state half-applied if
    // interrupted (enable/disable/restore). Status/check/launch don't touch
    // system state, so Ctrl+C there can just use the default behavior.
    if matches!(
        cli.cmd,
        Cmd::Enable { .. } | Cmd::Disable { .. } | Cmd::Restore
    ) {
        let timeout = cli.timeout.map(Duration::from_secs);
        watchdog::arm(lang, timeout, move |trip| {
            let reason = match trip {
                watchdog::Trip::Signal => tr(lang, "interrupted", "interrumpido"),
                watchdog::Trip::Timeout => tr(lang, "timeout reached", "tiempo límite alcanzado"),
            };
            eprintln!(
                "\n[!] {reason} \u{2014} {}",
                tr(lang, "running restore...", "ejecutando restore...")
            );
            // Blocks on the state lock until whatever module step is
            // currently in flight on the main thread finishes — this can't
            // preempt a blocking syscall mid-flight, only guarantee cleanup
            // runs right after it. See module docs in watchdog.rs.
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

    match cli.cmd {
        Cmd::Enable {
            modules,
            all,
            vpn_conf,
        } => {
            enable(lang, modules, all, vpn_conf.as_deref())?;
            settle_check(lang)
        }
        Cmd::Disable { modules } => disable(lang, modules),
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
        Cmd::Status => status(lang),
        Cmd::Check => check(lang),
        Cmd::Launch(Launch::Vbox { vm }) => launch::vbox(vm.as_deref()),
        Cmd::Launch(Launch::Proton) => launch::proton(),
        Cmd::Launch(Launch::Exec { cmd }) => launch::spawn(&cmd[0], &cmd[1..]),
    }
}

/// Checks against the REAL system state (not the saved state) that the module is still applied.
fn holds(m: Module, st: &State) -> bool {
    match m {
        Module::Mac => mac::holds(st),
        Module::Hostname => hostname::holds(st),
        Module::Sysctl => sysctl::holds(sysctl::HARDEN),
        Module::Ipv6 => ipv6::holds(),
        Module::Vpn => vpn::holds(st),
        Module::Dns => dns::holds(st),
        Module::Tor => tor::alive(),
        Module::Killswitch => killswitch::holds(st),
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
        .filter(|m| !holds(**m, &st))
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

fn status(lang: Lang) -> Result<()> {
    let st = State::load()?;
    let mut drift = false;
    for &m in Module::ALL {
        let active = st.active.contains(&m);
        let pending = st.pending.contains(&m);
        let applied = active && holds(m, &st);
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
            drift = true;
            println!(
                "        \u{26a0} {}",
                tr(
                    lang,
                    "partial state from a failed change; run `anonify restore`",
                    "estado parcial de un cambio fallido; ejecuta `anonify restore`"
                )
            );
        } else if active && !applied {
            drift = true;
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
    if drift {
        std::process::exit(1);
    }
    Ok(())
}
