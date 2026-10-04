mod i18n;
mod modules;
mod state;
mod sys;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use i18n::{tr, Lang};
use modules::{dns, hostname, ipv6, killswitch, launch, mac, sysctl, tor, vpn, Module};
use state::State;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "anonify",
    version,
    about = "Temporary, reversible network-anonymity hardening for Linux"
)]
struct Cli {
    /// Force a language instead of auto-detecting from the OS locale (en, es)
    #[arg(long, global = true)]
    lang: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enable modules (--all = mac, hostname, sysctl, ipv6, dns, tor)
    Enable {
        modules: Vec<Module>,
        #[arg(long)]
        all: bool,
        /// WireGuard config for the `vpn` module
        #[arg(long)]
        vpn_conf: Option<PathBuf>,
    },
    /// Disable modules (no arguments: all active ones)
    Disable { modules: Vec<Module> },
    /// Revert everything to its original state
    Restore,
    /// Show active modules
    Status,
    /// Basic leak checks
    Check,
    /// Launch apps (VirtualBox, Proton VPN, or an arbitrary command)
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

fn activate(m: Module, st: &mut State, conf: Option<&PathBuf>) -> Result<()> {
    match m {
        Module::Mac => mac::enable(st),
        Module::Hostname => hostname::enable(st),
        Module::Sysctl => sysctl::apply(st, sysctl::HARDEN),
        Module::Ipv6 => ipv6::enable(st),
        Module::Vpn => vpn::enable(st, conf.map(|p| p.as_path())),
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

fn enable(lang: Lang, mut mods: Vec<Module>, all: bool, conf: Option<PathBuf>) -> Result<()> {
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
    let mut st = State::load()?;
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
        if let Err(e) = activate(m, &mut st, conf.as_ref()) {
            st.save()?;
            bail!(
                "{m:?} {}: {e:#}\n    {}",
                tr(lang, "failed", "falló"),
                tr(
                    lang,
                    "run `sudo anonify restore` to leave everything clean.",
                    "Ejecuta `sudo anonify restore` para dejar todo limpio."
                )
            );
        }
        st.active.insert(m);
        st.save()?;
    }
    Ok(())
}

fn disable(lang: Lang, mods: Vec<Module>) -> Result<()> {
    let mut st = State::load()?;
    let mut list: Vec<Module> = if mods.is_empty() {
        vec![
            Module::Mac,
            Module::Hostname,
            Module::Sysctl,
            Module::Ipv6,
            Module::Vpn,
            Module::Dns,
            Module::Tor,
            Module::Killswitch,
        ]
    } else {
        mods
    };
    list.sort();
    list.dedup();
    for m in list.into_iter().rev() {
        println!("[-] {} {m:?}", tr(lang, "disabling", "desactivando"));
        if let Err(e) = deactivate(m, &mut st) {
            eprintln!("    {}: {e:#}", tr(lang, "warning", "aviso"));
        }
        st.active.remove(&m);
        st.save()?;
    }
    Ok(())
}

fn check(lang: Lang) -> Result<()> {
    println!(
        "resolv.conf:\n{}",
        std::fs::read_to_string("/etc/resolv.conf")?
    );
    let v6 = sys::read_trim("/proc/sys/net/ipv6/conf/all/disable_ipv6").unwrap_or_default();
    println!(
        "{}: {}",
        tr(lang, "IPv6 disabled", "IPv6 deshabilitado"),
        v6 == "1"
    );
    if sys::have("curl") {
        match sys::run(
            "curl",
            &[
                "-sS",
                "--max-time",
                "20",
                "https://check.torproject.org/api/ip",
            ],
        ) {
            Ok(j) => println!("check.torproject.org: {j}"),
            Err(e) => println!(
                "{}: {e:#} ({})",
                tr(lang, "no outbound internet", "sin salida a internet"),
                tr(
                    lang,
                    "expected if the kill switch is blocking it",
                    "esperado si el kill switch bloquea"
                )
            ),
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let lang = Lang::resolve(cli.lang.as_deref());

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
    match cli.cmd {
        Cmd::Enable {
            modules,
            all,
            vpn_conf,
        } => {
            enable(lang, modules, all, vpn_conf)?;
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
        Module::Mac => st.macs.iter().all(|(i, orig)| {
            sys::read_trim(&format!("/sys/class/net/{i}/address"))
                .map(|c| &c != orig)
                .unwrap_or(true)
        }),
        Module::Hostname => st
            .hostname_applied
            .as_deref()
            .map(|h| {
                sys::read_trim("/proc/sys/kernel/hostname")
                    .map(|c| c == h)
                    .unwrap_or(false)
            })
            .unwrap_or(false),
        Module::Sysctl => sysctl::holds(sysctl::HARDEN),
        Module::Ipv6 => sysctl::holds(sysctl::IPV6),
        Module::Vpn => st
            .vpn_conf
            .as_ref()
            .map(|c| {
                let iface = std::path::Path::new(c)
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                std::path::Path::new(&format!("/sys/class/net/{iface}")).exists()
            })
            .unwrap_or(false),
        Module::Dns => std::fs::read_to_string("/etc/resolv.conf")
            .map(|s| s.contains("anonify"))
            .unwrap_or(false),
        Module::Tor => tor::alive(),
        Module::Killswitch => killswitch::present(),
    }
}

/// NetworkManager and other daemons can revert changes seconds later: wait and re-verify.
fn settle_check(lang: Lang) -> Result<()> {
    std::thread::sleep(std::time::Duration::from_secs(20));
    let st = State::load()?;
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
                "Something on the system reverted them.",
                "Algo del sistema los revirtió."
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
    for m in [
        Module::Mac,
        Module::Hostname,
        Module::Sysctl,
        Module::Ipv6,
        Module::Vpn,
        Module::Dns,
        Module::Tor,
        Module::Killswitch,
    ] {
        let active = st.active.contains(&m);
        let tag = if !active {
            "off"
        } else if holds(m, &st) {
            "ON "
        } else {
            "ON!"
        };
        println!(
            "[{tag}] {:<11} {}",
            format!("{m:?}").to_lowercase(),
            m.desc(lang)
        );
        if tag == "ON!" {
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
