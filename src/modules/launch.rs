//! Lanzadores. Si corres con sudo, la app se abre como tu usuario (no root).
//!
//! No se usa `sudo -E`: preservar todo el entorno de root puede colar
//! `HOME=/root`, `LD_PRELOAD` o variables de sesión incorrectas. Solo se
//! conservan las variables necesarias para una app gráfica y se usa `-H` para
//! que `HOME` sea el del usuario destino.
use crate::sys;
use anyhow::{bail, Result};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

fn build(prog: &str, args: &[String]) -> Command {
    match (sys::is_root(), std::env::var("SUDO_USER")) {
        (true, Ok(u)) if u != "root" => {
            let mut c = Command::new("sudo");
            c.args([
                "-u",
                &u,
                "-H",
                "--preserve-env=DISPLAY,WAYLAND_DISPLAY,XAUTHORITY,DBUS_SESSION_BUS_ADDRESS,XDG_RUNTIME_DIR,XDG_SESSION_TYPE,XDG_CURRENT_DESKTOP",
                "--",
                prog,
            ]);
            c.args(args);
            c
        }
        _ => {
            let mut c = Command::new(prog);
            c.args(args);
            c
        }
    }
}

fn inherit(cmd: &mut Command) {
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
}

fn spawn_detached(prog: &str, args: &[String]) -> Result<()> {
    let mut cmd = build(prog, args);
    inherit(&mut cmd);
    cmd.spawn()
        .map_err(|e| anyhow::anyhow!("no se pudo lanzar {prog}: {e}"))?;
    println!("[+] lanzado: {prog}");
    Ok(())
}

fn exec_replace(prog: &str, args: &[String]) -> Result<()> {
    let mut cmd = build(prog, args);
    inherit(&mut cmd);
    // `exec` reemplaza este proceso: el hijo conserva el terminal y el código
    // de salida correcto. Solo retorna si falla.
    let e = cmd.exec();
    bail!("no se pudo lanzar {prog}: {e}")
}

pub fn spawn(prog: &str, args: &[String]) -> Result<()> {
    exec_replace(prog, args)
}

pub fn vbox(vm: Option<&str>) -> Result<()> {
    match vm {
        Some(v) => spawn_detached(
            "VBoxManage",
            &["startvm".into(), v.into(), "--type".into(), "gui".into()],
        ),
        None => spawn_detached("VirtualBox", &[]),
    }
}

pub fn proton() -> Result<()> {
    for c in ["protonvpn-app", "proton-vpn-gtk-app", "protonvpn-gui"] {
        if sys::have(c) {
            return spawn_detached(c, &[]);
        }
    }
    bail!("no encontré app de Proton VPN (AUR: proton-vpn-gtk-app). Alternativa: --vpn-conf con un .conf WireGuard")
}
