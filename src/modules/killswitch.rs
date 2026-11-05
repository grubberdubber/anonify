//! Kill switch: solo se permite tráfico por loopback, DHCP, interfaces de
//! túnel (`wg*`, `proton*`, `tun*`), el endpoint exacto del VPN (IP + puerto
//! UDP) y el UID del daemon Tor. Si el túnel cae, no hay red.
//!
//! El endpoint se resuelve a IPs numéricas en `vpn::enable`/`vpn::ensure_endpoint`;
//! nunca se interpola un hostname ni texto arbitrario en las reglas.
use crate::{modules::vpn, state::State, sys};
use anyhow::{Context, Result, bail};
use std::fmt::Write as _;
use std::net::IpAddr;

const TABLE: &str = "anonify_ks";

fn endpoint_lines(st: &State) -> Result<String> {
    if st.vpn_endpoint_addrs.is_empty() {
        if st.vpn_endpoint_port.is_some() {
            bail!("estado inconsistente: hay puerto de VPN pero no direcciones");
        }
        return Ok(String::new());
    }
    let port = st
        .vpn_endpoint_port
        .context("estado inconsistente: hay direcciones de VPN pero no puerto")?;
    let mut out = String::new();
    for raw in &st.vpn_endpoint_addrs {
        let ip: IpAddr = raw
            .parse()
            .with_context(|| format!("dirección de endpoint VPN inválida: {raw}"))?;
        match ip {
            IpAddr::V4(_) => writeln!(out, "    ip daddr {ip} udp dport {port} accept")?,
            IpAddr::V6(_) => writeln!(out, "    ip6 daddr {ip} udp dport {port} accept")?,
        }
    }
    Ok(out)
}

fn tor_uid() -> Option<u32> {
    sys::run("id", &["-u", "tor"])
        .ok()
        .and_then(|u| u.parse::<u32>().ok())
}

fn rules(st: &State) -> Result<String> {
    let endpoint = endpoint_lines(st)?;
    let tor = tor_uid()
        .map(|u| format!("    meta skuid {u} accept\n"))
        .unwrap_or_default();
    Ok(format!(
        r#"table inet {TABLE} {{
  chain out {{
    type filter hook output priority 1; policy drop;
    oifname "lo" accept
    ip daddr 127.0.0.0/8 accept
    oifname {{ "wg*", "proton*", "tun*" }} accept
{endpoint}{tor}    udp sport 68 udp dport 67 ip daddr 255.255.255.255 accept
  }}
}}
"#
    ))
}

pub fn enable(st: &mut State) -> Result<()> {
    if !sys::have("nft") {
        bail!("falta nftables: sudo pacman -S nftables");
    }
    vpn::ensure_endpoint(st)?;
    if present() {
        if holds(st) {
            // Idempotente: la tabla ya está bloqueando con las reglas
            // esperadas. Si el endpoint cambió, `restore` + `enable`.
            return Ok(());
        }
        bail!(
            "la tabla inet {TABLE} existe pero no cumple la política fail-closed; \
             ejecuta `anonify restore` y vuelve a activarla"
        );
    }
    let rules = rules(st)?;
    sys::run_stdin("nft", &["-f", "-"], &rules)
}

pub fn disable() -> Result<()> {
    if !present() {
        return Ok(());
    }
    let _ = sys::run("nft", &["delete", "table", "inet", TABLE]);
    if present() {
        bail!("no se pudo eliminar la tabla inet {TABLE}");
    }
    Ok(())
}

pub fn present() -> bool {
    sys::run("nft", &["list", "table", "inet", TABLE]).is_ok()
}

/// La tabla existe y mantiene la política fail-closed. `present()` solo
/// comprueba el nombre, que otra herramienta podría haber reutilizado.
pub fn holds(st: &State) -> bool {
    let Ok(out) = sys::run("nft", &["list", "table", "inet", TABLE]) else {
        return false;
    };
    if !out.contains("policy drop")
        || !out.contains("oifname \"lo\" accept")
        || !out.contains("\"wg*\"")
        || !out.contains("\"tun*\"")
    {
        return false;
    }
    endpoint_lines(st).is_ok_and(|expected| expected.lines().all(|line| out.contains(line.trim())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with(addrs: &[&str], port: Option<u16>) -> State {
        State {
            vpn_endpoint_addrs: addrs.iter().map(|s| (*s).to_string()).collect(),
            vpn_endpoint_port: port,
            ..State::default()
        }
    }

    #[test]
    fn rules_allow_only_resolved_endpoint() {
        let st = state_with(&["203.0.113.7", "2001:db8::1"], Some(51820));
        let r = rules(&st).expect("reglas");
        assert!(r.contains("ip daddr 203.0.113.7 udp dport 51820 accept"));
        assert!(r.contains("ip6 daddr 2001:db8::1 udp dport 51820 accept"));
        assert!(r.contains("policy drop"));
        assert!(!r.contains("0.0.0.0/0"));
    }

    #[test]
    fn rules_without_vpn_still_fail_closed() {
        let st = state_with(&[], None);
        let r = rules(&st).expect("reglas");
        assert!(r.contains("policy drop"));
        assert!(!r.contains("udp dport 51820"));
    }

    #[test]
    fn rejects_invalid_endpoint() {
        let st = state_with(&["not-an-ip"], Some(51820));
        assert!(rules(&st).is_err());
    }

    #[test]
    fn nft_accepts_generated_rules_when_privileged() {
        if !sys::have("nft") || sys::run("nft", &["list", "tables"]).is_err() {
            eprintln!("skip: nft/CAP_NET_ADMIN no disponible");
            return;
        }
        let st = state_with(&["203.0.113.7", "2001:db8::1"], Some(51820));
        let rules = rules(&st).expect("reglas");
        sys::run_stdin("nft", &["-c", "-f", "-"], &rules)
            .expect("nft debe aceptar la sintaxis de las reglas");
        if !sys::in_isolated_netns() {
            eprintln!("skip install: no estamos en un netns aislado");
            return;
        }
        sys::run_stdin("nft", &["-f", "-"], &rules).expect("instalar tabla de prueba");
        assert!(present(), "la tabla de prueba debe existir");
        assert!(holds(&st), "la tabla debe conservar las reglas esperadas");
        sys::run("nft", &["delete", "table", "inet", TABLE]).expect("limpiar tabla de prueba");
    }
}
