mod modules;
mod state;
mod sys;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use modules::{dns, hostname, killswitch, launch, mac, sysctl, tor, vpn, Module};
use state::State;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "anonify", version, about = "Anonimato/hardening temporal y reversible para Arch Linux")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Activa módulos (--all = mac, hostname, sysctl, ipv6, dns, tor)
    Enable {
        modules: Vec<Module>,
        #[arg(long)]
        all: bool,
        /// Config WireGuard para el módulo `vpn`
        #[arg(long)]
        vpn_conf: Option<PathBuf>,
    },
    /// Desactiva módulos (sin argumentos: todos los activos)
    Disable { modules: Vec<Module> },
    /// Vuelve todo a como estaba
    Restore,
    /// Muestra módulos activos
    Status,
    /// Chequeos básicos de fuga
    Check,
    /// Lanza apps (VirtualBox, Proton VPN, o un comando)
    #[command(subcommand)]
    Launch(Launch),
}

#[derive(Subcommand)]
enum Launch {
    Vbox { vm: Option<String> },
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
        Module::Ipv6 => sysctl::apply(st, sysctl::IPV6),
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
        Module::Ipv6 => sysctl::revert(st, sysctl::IPV6),
        Module::Vpn => vpn::disable(st),
        Module::Dns => dns::disable(st),
        Module::Tor => tor::disable(),
        Module::Killswitch => killswitch::disable(),
    }
}

fn enable(mut mods: Vec<Module>, all: bool, conf: Option<PathBuf>) -> Result<()> {
    if all {
        mods.extend_from_slice(Module::DEFAULT_SET);
    }
    if mods.is_empty() {
        bail!("indica módulos o usa --all (ver `anonify enable --help`)");
    }
    mods.sort();
    mods.dedup();
    let mut st = State::load()?;
    for m in mods {
        if st.active.contains(&m) {
            println!("[=] {m:?} ya activo");
            continue;
        }
        println!("[+] activando {m:?}: {}", m.desc());
        if let Err(e) = activate(m, &mut st, conf.as_ref()) {
            st.save()?;
            bail!("{m:?} falló: {e:#}\n    Ejecuta `sudo anonify restore` para dejar todo limpio.");
        }
        st.active.insert(m);
        st.save()?;
    }
    Ok(())
}

fn disable(mods: Vec<Module>) -> Result<()> {
    let mut st = State::load()?;
    let mut list: Vec<Module> = if mods.is_empty() { vec![Module::Mac, Module::Hostname, Module::Sysctl, Module::Ipv6, Module::Vpn, Module::Dns, Module::Tor, Module::Killswitch] } else { mods };
    list.sort();
    list.dedup();
    for m in list.into_iter().rev() {
        println!("[-] desactivando {m:?}");
        if let Err(e) = deactivate(m, &mut st) {
            eprintln!("    aviso: {e:#}");
        }
        st.active.remove(&m);
        st.save()?;
    }
    Ok(())
}


fn check() -> Result<()> {
    println!("resolv.conf:\n{}", std::fs::read_to_string("/etc/resolv.conf")?);
    let v6 = sys::read_trim("/proc/sys/net/ipv6/conf/all/disable_ipv6").unwrap_or_default();
    println!("IPv6 deshabilitado: {}", v6 == "1");
    if sys::have("curl") {
        match sys::run("curl", &["-sS", "--max-time", "20", "https://check.torproject.org/api/ip"]) {
            Ok(j) => println!("check.torproject.org: {j}"),
            Err(e) => println!("sin salida a internet: {e:#} (esperado si el kill switch bloquea)"),
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if !matches!(cli.cmd, Cmd::Launch(_)) && !sys::is_root() {
        bail!("anonify necesita root: usa `sudo anonify ...`");
    }
    match cli.cmd {
        Cmd::Enable { modules, all, vpn_conf } => { enable(modules, all, vpn_conf)?; settle_check() }
        Cmd::Disable { modules } => disable(modules),
        Cmd::Restore => {
            disable(vec![])?;
            println!("[✓] sistema restaurado a su configuración original");
            Ok(())
        }
        Cmd::Status => status(),
        Cmd::Check => check(),
        Cmd::Launch(Launch::Vbox { vm }) => launch::vbox(vm.as_deref()),
        Cmd::Launch(Launch::Proton) => launch::proton(),
        Cmd::Launch(Launch::Exec { cmd }) => launch::spawn(&cmd[0], &cmd[1..]),
    }
}

/// Comprueba contra el SISTEMA REAL (no contra el estado guardado) que el módulo sigue aplicado.
fn holds(m: Module, st: &State) -> bool {
    match m {
        Module::Mac => st.macs.iter().all(|(i, orig)| {
            sys::read_trim(&format!("/sys/class/net/{i}/address")).map(|c| &c != orig).unwrap_or(true)
        }),
        Module::Hostname => st
            .hostname_applied
            .as_deref()
            .map(|h| sys::read_trim("/proc/sys/kernel/hostname").map(|c| c == h).unwrap_or(false))
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
        Module::Dns => std::fs::read_to_string("/etc/resolv.conf").map(|s| s.contains("anonify")).unwrap_or(false),
        Module::Tor => tor::alive(),
        Module::Killswitch => killswitch::present(),
    }
}

/// NetworkManager y otros pueden revertir cambios segundos después: esperar y re-verificar.
fn settle_check() -> Result<()> {
    std::thread::sleep(std::time::Duration::from_secs(5));
    let st = State::load()?;
    let lost: Vec<String> = st.active.iter().filter(|m| !holds(**m, &st)).map(|m| format!("{m:?}")).collect();
    if !lost.is_empty() {
        bail!("ATENCIÓN: ya no están aplicados: {}. Algo del sistema los revirtió.", lost.join(", "));
    }
    println!("[✓] verificado: todo sigue aplicado tras 5 s");
    Ok(())
}

fn status() -> Result<()> {
    let st = State::load()?;
    let mut drift = false;
    for m in [Module::Mac, Module::Hostname, Module::Sysctl, Module::Ipv6, Module::Vpn, Module::Dns, Module::Tor, Module::Killswitch] {
        let active = st.active.contains(&m);
        let tag = if !active { "off" } else if holds(m, &st) { "ON " } else { "ON!" };
        println!("[{tag}] {:<11} {}", format!("{m:?}").to_lowercase(), m.desc());
        if tag == "ON!" {
            drift = true;
            println!("        ⚠ figura activo pero el sistema ya NO lo tiene aplicado");
        }
    }
    if drift {
        std::process::exit(1);
    }
    Ok(())
}
