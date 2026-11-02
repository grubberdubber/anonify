//! IPv6 off = sysctl + aviso runtime a `NetworkManager` (sin modificar el
//! perfil persistente). Sin el aviso, NM puede reintentar crear su dirección
//! IPv6 cada ~15 s y, de paso, revertir el hostname transitorio.
//!
//! `nmcli device modify` cambia solo la configuración activa del dispositivo;
//! no escribe el perfil en disco. `nmcli device reapply` vuelve a aplicar el
//! perfil original al restaurar.
use super::sysctl;
use crate::{state::State, sys};
use anyhow::{bail, Result};
use std::fs;

/// Dispositivos Ethernet/WiFi que `NetworkManager` tiene conectados ahora mismo.
fn nm_devices() -> Vec<String> {
    if !sys::have("nmcli") {
        return vec![];
    }
    let Ok(out) = sys::run("nmcli", &["-t", "-f", "DEVICE,TYPE,STATE", "device"]) else {
        return vec![];
    };
    parse_nm_devices(&out)
}

fn parse_nm_devices(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| {
            let mut p = l.split(':');
            let (dev, typ, state) = (p.next()?, p.next()?, p.next()?);
            (matches!(typ, "wifi" | "ethernet") && state.starts_with("connected"))
                .then(|| dev.to_string())
        })
        .collect()
}

pub fn enable(st: &mut State) -> Result<()> {
    sysctl::apply(st, sysctl::IPV6)?;
    for d in nm_devices() {
        match sys::run(
            "nmcli",
            &["device", "modify", &d, "ipv6.method", "disabled"],
        ) {
            Ok(_) => {
                println!("    NetworkManager: IPv6 desactivado en vivo en {d}");
                if !st.nm_devices.contains(&d) {
                    st.nm_devices.push(d);
                }
            }
            Err(e) => println!("    aviso: nmcli no pudo desactivar IPv6 en {d}: {e:#}"),
        }
    }
    // Verificación real: `all.disable_ipv6` debe cubrir también las interfaces
    // que ya existían. Si alguna quedó con IPv6, el módulo no está aplicado.
    if !holds() {
        let _ = sysctl::revert(st, sysctl::IPV6);
        bail!("IPv6 sigue habilitado en alguna interfaz tras aplicar sysctl");
    }
    if !st.nm_devices.is_empty() {
        std::thread::sleep(std::time::Duration::from_secs(3)); // dejar que NM procese
    }
    Ok(())
}

pub fn disable(st: &mut State) -> Result<()> {
    let sysctl_result = sysctl::revert(st, sysctl::IPV6);
    let mut stuck: Vec<String> = vec![];
    for d in st.nm_devices.clone() {
        if fs::metadata(format!("/sys/class/net/{d}")).is_err() {
            st.nm_devices.retain(|x| x != &d);
            continue;
        }
        match sys::run("nmcli", &["device", "reapply", &d]) {
            Ok(_) => {
                st.nm_devices.retain(|x| x != &d);
            }
            Err(e) => {
                println!(
                    "    aviso: no se pudo restaurar NetworkManager en {d}: {e:#} \
                     (prueba: nmcli device connect {d})"
                );
                stuck.push(d);
            }
        }
    }
    if !stuck.is_empty() {
        bail!(
            "NetworkManager sin restaurar en: {} (se conserva para reintentar)",
            stuck.join(", ")
        );
    }
    sysctl_result
}

/// `all`/`default` + cada interfaz existente deben tener IPv6 deshabilitado.
pub fn holds() -> bool {
    if !sysctl::holds(sysctl::IPV6) {
        return false;
    }
    let Ok(rd) = fs::read_dir("/proc/sys/net/ipv6/conf") else {
        return false;
    };
    rd.flatten()
        .all(|e| fs::read_to_string(e.path().join("disable_ipv6")).is_ok_and(|s| s.trim() == "1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connected_physical_devices_only() {
        let out = "wlan0:wifi:connected\neth0:ethernet:connected (externally)\n\
                   docker0:bridge:connected\nlo:loopback:unmanaged\n";
        assert_eq!(parse_nm_devices(out), vec!["wlan0", "eth0"]);
    }

    #[test]
    fn ignores_disconnected_devices() {
        let out = "wlan0:wifi:disconnected\neth0:ethernet:unavailable\n";
        assert!(parse_nm_devices(out).is_empty());
    }
}
