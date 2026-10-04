//! IPv6 off = sysctl + avisar a NetworkManager (solo en vivo, no se guarda).
//! Sin el aviso, NM reintenta crear su dirección IPv6 cada ~15 s y, de paso,
//! revierte el hostname transitorio.
use super::sysctl;
use crate::{state::State, sys};
use anyhow::Result;

/// Dispositivos Ethernet/WiFi que NetworkManager tiene conectados ahora mismo.
fn nm_devices() -> Vec<String> {
    if !sys::have("nmcli") {
        return vec![];
    }
    let Ok(out) = sys::run("nmcli", &["-t", "-f", "DEVICE,TYPE,STATE", "device"]) else {
        return vec![];
    };
    out.lines()
        .filter_map(|l| {
            let mut p = l.split(':');
            let (dev, typ, state) = (p.next()?, p.next()?, p.next()?);
            (matches!(typ, "wifi" | "ethernet") && state == "connected").then(|| dev.to_string())
        })
        .collect()
}

pub fn enable(st: &mut State) -> Result<()> {
    sysctl::apply(st, sysctl::IPV6)?;
    for d in nm_devices() {
        match sys::run("nmcli", &["device", "modify", &d, "ipv6.method", "disabled"]) {
            Ok(_) => {
                println!("    NetworkManager: IPv6 desactivado en vivo en {d}");
                if !st.nm_devices.contains(&d) {
                    st.nm_devices.push(d);
                }
            }
            Err(e) => println!("    aviso: nmcli no pudo en {d}: {e:#}"),
        }
    }
    if !st.nm_devices.is_empty() {
        std::thread::sleep(std::time::Duration::from_secs(3)); // dejar que NM procese el reapply
    }
    Ok(())
}

pub fn disable(st: &mut State) -> Result<()> {
    let r = sysctl::revert(st, sysctl::IPV6);
    for d in std::mem::take(&mut st.nm_devices) {
        if let Err(e) = sys::run("nmcli", &["device", "reapply", &d]) {
            println!("    aviso: no se pudo restaurar NetworkManager en {d}: {e:#} (prueba: nmcli device connect {d})");
        }
    }
    r
}
