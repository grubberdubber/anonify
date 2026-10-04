use crate::{state::State, sys};
use anyhow::{bail, Result};
use std::{fs, path::Path};

pub fn enable(st: &mut State, conf: Option<&Path>) -> Result<()> {
    let Some(conf) = conf else {
        bail!("el módulo vpn necesita --vpn-conf /ruta/a/wg.conf (Proton, Mullvad, etc.)");
    };
    if !sys::have("wg-quick") {
        bail!("falta wireguard-tools: sudo pacman -S wireguard-tools");
    }
    let conf = fs::canonicalize(conf)?;
    let text = fs::read_to_string(&conf)?;
    st.vpn_endpoint = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("Endpoint"))
        .and_then(|l| l.split('=').nth(1))
        .and_then(|e| e.trim().rsplit_once(':').map(|(h, _)| h.trim().to_string()));
    let c = conf.to_string_lossy().to_string();
    sys::run("wg-quick", &["up", &c])?;
    st.vpn_conf = Some(c);
    Ok(())
}

pub fn disable(st: &mut State) -> Result<()> {
    if let Some(c) = st.vpn_conf.take() {
        sys::run("wg-quick", &["down", &c])?;
    }
    st.vpn_endpoint = None;
    Ok(())
}
