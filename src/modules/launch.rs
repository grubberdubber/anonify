//! Lanzadores. Si corres con sudo, la app se abre como tu usuario (no root).
use crate::sys;
use anyhow::{bail, Result};
use std::process::{Command, Stdio};

pub fn spawn(prog: &str, args: &[String]) -> Result<()> {
    let mut cmd = match (sys::is_root(), std::env::var("SUDO_USER")) {
        (true, Ok(u)) => {
            let mut c = Command::new("sudo");
            c.args(["-u", &u, "-E", prog]);
            c
        }
        _ => Command::new(prog),
    };
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    cmd.spawn().map_err(|e| anyhow::anyhow!("no se pudo lanzar {prog}: {e}"))?;
    println!("[+] lanzado: {prog}");
    Ok(())
}

pub fn vbox(vm: Option<&str>) -> Result<()> {
    match vm {
        Some(v) => spawn("VBoxManage", &["startvm".into(), v.into(), "--type".into(), "gui".into()]),
        None => spawn("VirtualBox", &[]),
    }
}

pub fn proton() -> Result<()> {
    for c in ["protonvpn-app", "proton-vpn-gtk-app", "protonvpn-gui"] {
        if sys::have(c) {
            return spawn(c, &[]);
        }
    }
    bail!("no encontré app de Proton VPN (AUR: proton-vpn-gtk-app). Alternativa: --vpn-conf con un .conf WireGuard")
}
