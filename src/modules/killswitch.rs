//! Kill switch: solo se permite tráfico por loopback, interfaces de túnel
//! (wg*, proton*, tun*), Tor y el endpoint del VPN. Si el túnel cae, no hay red.
use crate::{state::State, sys};
use anyhow::{bail, Result};

const TABLE: &str = "anonify_ks";

pub fn enable(st: &State) -> Result<()> {
    if !sys::have("nft") {
        bail!("falta nftables: sudo pacman -S nftables");
    }
    let ep = st
        .vpn_endpoint
        .as_ref()
        .map(|e| format!("    ip daddr {e} accept\n"))
        .unwrap_or_default();
    let tor_uid = sys::run("id", &["-u", "tor"]).ok();
    let tor = tor_uid.map(|u| format!("    meta skuid {u} accept\n")).unwrap_or_default();
    let rules = format!(
        r#"table inet {TABLE} {{
  chain out {{
    type filter hook output priority 1; policy drop;
    oifname "lo" accept
    oifname {{ "wg*", "proton*", "tun*" }} accept
{ep}{tor}    udp dport 67 accept
  }}
}}
"#
    );
    sys::run_stdin("nft", &["-f", "-"], &rules)
}

pub fn disable() -> Result<()> {
    let _ = sys::run("nft", &["delete", "table", "inet", TABLE]);
    Ok(())
}

pub fn present() -> bool {
    sys::run("nft", &["list", "table", "inet", TABLE]).is_ok()
}
