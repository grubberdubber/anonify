//! Silencia el descubrimiento de servicios en la LAN (`mDNS`, `LLMNR`,
//! `SSDP`, `NetBIOS` y `WS-Discovery`).
//!
//! Estos protocolos existen para que la red local encuentre la máquina y sus
//! servicios: emiten el hostname, el nombre de trabajo, impresoras, medios y
//! a veces el modelo del dispositivo. Frente al observador del modelo de
//! amenaza (vecino, punto de acceso, LAN compartida) son una fuga gratuita,
//! aunque el tráfico a Internet esté dentro de Tor.
//!
//! Qué cambia: una tabla `nftables` propia (`inet anonify_lan`) con reglas de
//! **salida** que descartan los puertos de descubrimiento. La política de la
//! cadena es `accept`: esto no es un firewall fail-closed y no puede cortar
//! la conexión. No se detienen daemons, no se edita su configuración y no se
//! toca ningún log.
//!
//! Qué no protege: DHCP sigue enviando el hostname si el cliente lo pide
//! (`dhclient`/`NetworkManager`), y un escaneo activo de la LAN puede inferir
//! la presencia del equipo por ARP. Eso requeriría configuración persistente
//! del cliente DHCP, que este proyecto evita a propósito.
use crate::sys;
use anyhow::{Result, bail};

pub const TABLE: &str = "anonify_lan";

/// Puertos de descubrimiento local. `policy accept`: solo se recortan estos
/// flujos, nunca el resto de la red.
fn rules() -> String {
    format!(
        r"table inet {TABLE} {{
  chain out {{
    type filter hook output priority 0; policy accept;
    udp dport {{ 5353, 5355, 1900, 137, 138, 3702 }} drop
    tcp dport {{ 5355, 139, 3702 }} drop
  }}
}}"
    )
}

pub fn enable() -> Result<()> {
    if present() {
        bail!("la tabla inet {TABLE} ya existe; ejecuta `anonify restore` antes de reactivar lan");
    }
    sys::run_stdin("nft", &["-f", "-"], &rules())?;
    if !holds() {
        let _ = sys::run("nft", &["delete", "table", "inet", TABLE]);
        bail!("las reglas de {TABLE} no quedaron aplicadas; se revirtió el intento");
    }
    println!("    mDNS/LLMNR/SSDP/NetBIOS/WS-Discovery bloqueados en salida");
    Ok(())
}

pub fn disable() -> Result<()> {
    if present() {
        sys::run("nft", &["delete", "table", "inet", TABLE])?;
    }
    if present() {
        bail!("no se pudo eliminar la tabla inet {TABLE}");
    }
    Ok(())
}

/// La tabla existe y contiene los descartes esperados (no basta el nombre).
pub fn holds() -> bool {
    sys::run("nft", &["list", "table", "inet", TABLE]).is_ok_and(|out| {
        ["5353", "5355", "1900", "137", "138", "3702"]
            .iter()
            .all(|port| out.contains(port))
            && out.contains("drop")
    })
}

pub fn present() -> bool {
    sys::run("nft", &["list", "table", "inet", TABLE]).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_the_discovery_ports_only() {
        let r = rules();
        assert!(r.contains("table inet anonify_lan"));
        assert!(r.contains("policy accept"));
        for port in [5353, 5355, 1900, 137, 138, 3702] {
            assert!(r.contains(&port.to_string()), "falta el puerto {port}");
        }
    }

    #[test]
    fn nft_accepts_generated_rules_when_privileged() {
        if !sys::have("nft") || sys::run("nft", &["list", "tables"]).is_err() {
            eprintln!("skip: nft/CAP_NET_ADMIN no disponible");
            return;
        }
        sys::run_stdin("nft", &["-c", "-f", "-"], &rules())
            .expect("nft debe aceptar la sintaxis de las reglas");
        if !sys::in_isolated_netns() {
            eprintln!("skip install: no estamos en un netns aislado");
            return;
        }
        sys::run_stdin("nft", &["-f", "-"], &rules()).expect("instalar tabla de prueba");
        assert!(holds(), "la tabla de prueba debe contener los descartes");
        sys::run("nft", &["delete", "table", "inet", TABLE]).expect("limpiar tabla de prueba");
    }

    #[test]
    fn never_becomes_a_drop_all_ruleset() {
        let r = rules();
        assert!(!r.contains("policy drop"));
        assert_eq!(r.matches("drop").count(), 2);
    }
}
