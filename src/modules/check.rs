//! Auditoría de fugas de solo lectura.
//!
//! Principio fail-closed: si no hay una capa de anonimato activa, `check` no
//! hace peticiones a Internet en claro para “descubrir” la IP pública. La
//! comprobación de circuito Tor usa el SOCKS local (`--socks5-hostname`), de
//! modo que también la resolución DNS ocurre dentro de Tor.
//!
//! `--json` imprime un objeto estable en stdout para integrarlo desde scripts;
//! los mismos datos se muestran en texto cuando no se pide JSON. Las líneas
//! informativas (IP de salida, comprobaciones omitidas) van a `notes`, nunca a
//! `leaks`: una comprobación omitida no es una fuga demostrada.
use crate::{
    i18n::{tr, Lang},
    mem,
    modules::{dns, hostname, ipv6, killswitch, mac, sysctl, tor, vpn, Module},
    state::State,
    sys,
};
use anyhow::{bail, Result};
use serde::Serialize;
use std::fs;
use std::net::IpAddr;

fn nameservers() -> Vec<String> {
    fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut fields = l.split_whitespace();
            (fields.next() == Some("nameserver"))
                .then(|| fields.next().map(ToString::to_string))
                .flatten()
        })
        .collect()
}

fn global_ipv6() -> Vec<String> {
    fs::read_to_string("/proc/net/if_inet6")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            let _addr = p.next()?;
            let _idx = p.next()?;
            let _plen = p.next()?;
            let scope = p.next()?;
            let _flags = p.next()?;
            let ifname = p.next()?;
            (ifname != "lo" && scope == "00").then(|| ifname.to_string())
        })
        .collect()
}

fn tor_public_ip() -> Result<(bool, Option<String>)> {
    let out = sys::run(
        "curl",
        &[
            "-q",
            "-sS",
            "--max-time",
            "20",
            "--socks5-hostname",
            "127.0.0.1:9050",
            "https://check.torproject.org/api/ip",
        ],
    )?;
    let v: serde_json::Value = serde_json::from_str(&out)?;
    let is_tor = v.get("IsTor").and_then(serde_json::Value::as_bool) == Some(true);
    let ip = v
        .get("IP")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    Ok((is_tor, ip))
}

fn check_dns(st: &State, leaks: &mut Vec<String>, warnings: &mut Vec<String>) {
    let ns = nameservers();
    if ns.is_empty() {
        warnings.push("no nameserver found in /etc/resolv.conf".into());
    }
    for server in &ns {
        let loopback =
            server == "localhost" || server.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !loopback {
            // With no anonymity layer this is simply the system resolver; with
            // Tor active, port 53 is redirected by nftables. Treat it as
            // context, not a leak, so `check` is usable on a normal system.
            warnings.push(format!(
                "DNS nameserver {server} is not loopback; DNS depends on the network resolver or Tor redirection"
            ));
        }
    }
    if st.active.contains(&Module::Dns) {
        if !dns::holds(st) {
            leaks.push("/etc/resolv.conf is not the anonify bind mount".into());
        }
        if !st.active.contains(&Module::Tor) {
            leaks.push("dns is active without tor; resolution would not be anonymized".into());
        }
    }
}

fn check_ipv6(st: &State, leaks: &mut Vec<String>, warnings: &mut Vec<String>) {
    let v6_globals = global_ipv6();
    if st.active.contains(&Module::Ipv6) {
        if !ipv6::holds() {
            leaks.push("IPv6 is not disabled on every interface".into());
        }
        if !v6_globals.is_empty() {
            leaks.push(format!(
                "global IPv6 addresses still present on: {}",
                v6_globals.join(", ")
            ));
        }
    } else if !v6_globals.is_empty() {
        warnings.push(format!(
            "IPv6 global addresses present on {} (module `ipv6` is off)",
            v6_globals.join(", ")
        ));
    }
}

fn check_identity(st: &State, leaks: &mut Vec<String>) {
    if st.active.contains(&Module::Mac) && !mac::holds(st) {
        leaks.push("one or more physical interfaces still use the original MAC".into());
    }
    if st.active.contains(&Module::Hostname) && !hostname::holds(st) {
        leaks.push("hostname is not the ephemeral value".into());
    }
    if st.active.contains(&Module::Sysctl) && !sysctl::holds(sysctl::HARDEN) {
        leaks.push("kernel/network sysctl hardening is no longer applied".into());
    }
}

/// Swap is not a network leak, but it is a privacy one: tmpfs pages (and
/// therefore `/run/anonify` with the original MAC/hostname) can be written to
/// an unencrypted swap device. Read-only audit; nothing is disabled.
fn check_memory(warnings: &mut Vec<String>) {
    warnings.extend(mem::swap_warnings());
}

/// Interfaz de la ruta por defecto IPv4 según `/proc/net/route`.
/// El kernel marca la ruta por defecto con destino y máscara a cero.
fn default_route_iface(text: &str) -> Option<String> {
    text.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            return None;
        }
        (fields[1] == "00000000" && fields[7] == "00000000").then(|| fields[0].to_string())
    })
}

/// Interfaz de la ruta por defecto IPv6 según `/proc/net/ipv6_route`:
/// destino a cero y longitud de prefijo `00`.
fn ipv6_default_iface(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            return None;
        }
        let zero_dest = fields[0].bytes().all(|b| b == b'0');
        (zero_dest && fields[1] == "00").then(|| fields[9].to_string())
    })
}

fn is_tunnel(dev: &str) -> bool {
    ["wg", "tun", "proton"].iter().any(|p| dev.starts_with(p))
}

/// `IFF_UP` (0x1) leído de `/sys/class/net/<dev>/flags`.
fn link_is_up(dev: &str) -> bool {
    let Ok(raw) = fs::read_to_string(format!("/sys/class/net/{dev}/flags")) else {
        return false;
    };
    let raw = raw.trim();
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    u32::from_str_radix(hex, 16).is_ok_and(|flags| flags & 0x1 != 0)
}

/// Fugas por rutas: una VPN activa con la ruta por defecto aún en una interfaz
/// física deja escapar tráfico; una interfaz física extra encendida es una vía
/// de salida alternativa. Solo lectura: se avisa, no se apaga nada.
fn check_routes(st: &State, leaks: &mut Vec<String>, warnings: &mut Vec<String>) {
    if st.active.contains(&Module::Vpn) {
        match default_route_iface(&fs::read_to_string("/proc/net/route").unwrap_or_default()) {
            Some(dev) if is_tunnel(&dev) => {}
            Some(dev) => leaks.push(format!(
                "VPN is active but the IPv4 default route still goes through `{dev}`"
            )),
            None => warnings.push("VPN is active but no IPv4 default route was found".into()),
        }
    }

    if let Some(dev) =
        ipv6_default_iface(&fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default())
    {
        if st.active.contains(&Module::Ipv6) {
            leaks.push(format!(
                "IPv6 is disabled but `{dev}` still has a default route"
            ));
        } else if st.active.contains(&Module::Vpn) && !is_tunnel(&dev) {
            leaks.push(format!(
                "VPN is active but the IPv6 default route goes through `{dev}`"
            ));
        }
    }

    let up: Vec<String> = mac::physical_ifaces()
        .into_iter()
        .filter(|dev| link_is_up(dev))
        .collect();
    if up.len() > 1 {
        warnings.push(format!(
            "multiple physical interfaces are up ({}); traffic can egress through any of them",
            up.join(", ")
        ));
    }
}

fn check_tunnel(st: &State, leaks: &mut Vec<String>, warnings: &mut Vec<String>) {
    if st.active.contains(&Module::Vpn) && !vpn::holds(st) {
        leaks.push("VPN interface is missing or not a WireGuard interface".into());
    }
    if st.active.contains(&Module::Vpn) && !st.active.contains(&Module::Killswitch) {
        warnings
            .push("VPN is active without killswitch; traffic may escape outside the tunnel".into());
    }
    if st.active.contains(&Module::Killswitch) && !killswitch::holds(st) {
        leaks.push("kill switch table is missing or no longer fail-closed".into());
    }
    if st.active.contains(&Module::Killswitch)
        && !st.active.contains(&Module::Vpn)
        && !st.active.contains(&Module::Tor)
    {
        warnings.push(
            "kill switch is active without VPN/Tor; all non-loopback traffic is blocked".into(),
        );
    }
}

fn check_tor(
    st: &State,
    lang: Lang,
    leaks: &mut Vec<String>,
    warnings: &mut Vec<String>,
    notes: &mut Vec<String>,
) {
    if !st.active.contains(&Module::Tor) {
        notes.push(
            tr(
                lang,
                "public IP check skipped: no Tor session (refusing a clear-net request)",
                "comprobación de IP pública omitida: no hay sesión Tor (no se hace una petición en claro)",
            )
            .to_string(),
        );
        return;
    }
    if !tor::alive() {
        leaks.push("Tor process/table is not alive".into());
        return;
    }
    if !sys::have("curl") {
        warnings.push("curl is not installed; Tor circuit check skipped".into());
        return;
    }
    match tor_public_ip() {
        Ok((true, ip)) => notes.push(format!(
            "{}: {}",
            tr(lang, "Tor exit IP", "IP de salida Tor"),
            ip.as_deref().unwrap_or("?")
        )),
        Ok((false, ip)) => leaks.push(format!(
            "check.torproject.org says this is not Tor (IP: {})",
            ip.as_deref().unwrap_or("?")
        )),
        Err(e) => leaks.push(format!("Tor SOCKS check failed: {e:#}")),
    }
}

/// Resultado serializable de `anonify check --json`. El orden de los campos y
/// la forma (`active`, `pending`, `leaks`, `warnings`, `notes`, `ok`) son
/// estables: pensados para que un script no tenga que parsear texto.
#[derive(Serialize)]
struct Report {
    active: Vec<String>,
    pending: Vec<String>,
    leaks: Vec<String>,
    warnings: Vec<String>,
    notes: Vec<String>,
    ok: bool,
}

fn module_names<'a>(mods: impl Iterator<Item = &'a Module>) -> Vec<String> {
    mods.map(|m| format!("{m:?}").to_lowercase()).collect()
}

pub fn run(lang: Lang, json: bool) -> Result<()> {
    let st = State::load()?;
    let mut leaks: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    let active = module_names(st.active.iter());
    for m in &st.pending {
        leaks.push(format!(
            "module {m:?} has pending cleanup; run `anonify restore`"
        ));
    }

    check_dns(&st, &mut leaks, &mut warnings);
    check_ipv6(&st, &mut leaks, &mut warnings);
    check_identity(&st, &mut leaks);
    check_memory(&mut warnings);
    check_tunnel(&st, &mut leaks, &mut warnings);
    check_routes(&st, &mut leaks, &mut warnings);
    check_tor(&st, lang, &mut leaks, &mut warnings, &mut notes);

    let report = Report {
        active: active.clone(),
        pending: module_names(st.pending.iter()),
        leaks: leaks.clone(),
        warnings: warnings.clone(),
        notes: notes.clone(),
        ok: leaks.is_empty(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{}: {}",
            tr(lang, "active modules", "módulos activos"),
            if active.is_empty() {
                tr(lang, "none", "ninguno").to_string()
            } else {
                active.join(", ")
            }
        );
        for note in &notes {
            println!("[*] {note}");
        }
        for warning in &warnings {
            eprintln!("[!] {warning}");
        }
        if leaks.is_empty() {
            println!(
                "[\u{2713}] {}",
                tr(lang, "no leaks detected", "no se detectaron fugas")
            );
        } else {
            for leak in &leaks {
                eprintln!("[\u{2717}] {leak}");
            }
        }
    }

    if !leaks.is_empty() {
        bail!(
            "{} {}",
            leaks.len(),
            tr(lang, "leak(s) detected", "fuga(s) detectada(s)")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ipv4_default_route() {
        let text =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                    wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                    wlan0\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(default_route_iface(text).as_deref(), Some("wlan0"));
    }

    #[test]
    fn no_default_route_is_none() {
        let text =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                    wlan0\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n";
        assert!(default_route_iface(text).is_none());
    }

    #[test]
    fn finds_ipv6_default_route() {
        let text = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
                    00000000000000000000000000000000 00000400 00000001 00000000 00000003 wg0\n\
                    20010db8000000000000000000000001 80 00000000000000000000000000000000 00 \
                    00000000000000000000000000000000 00000400 00000001 00000000 00000001 wlan0\n";
        assert_eq!(ipv6_default_iface(text).as_deref(), Some("wg0"));
    }

    #[test]
    fn only_tunnel_names_are_tunnels() {
        assert!(is_tunnel("wg0"));
        assert!(is_tunnel("tun0"));
        assert!(is_tunnel("proton0"));
        assert!(!is_tunnel("wlan0"));
        assert!(!is_tunnel("enp3s0"));
    }
}
