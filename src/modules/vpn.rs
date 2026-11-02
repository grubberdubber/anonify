//! WireGuard/ProtonVPN vía `wg-quick`.
//!
//! El endpoint se resuelve a direcciones numéricas IPv4/IPv6 antes de levantar
//! el túnel. El kill switch necesita esas direcciones exactas para permitir
//! solo el handshake del VPN, no todo el tráfico hacia el host del endpoint.
//!
//! `wg-quick` es una herramienta de terceros: puede tocar rutas, DNS y
//! `sysctl` runtime. anonify documenta ese efecto y ejecuta `wg-quick down` al
//! restaurar; no modifica perfiles persistentes de `NetworkManager`.
use crate::{state::State, sys};
use anyhow::{bail, Context, Result};
use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const RESOLV_CONF: &str = "/etc/resolv.conf";

pub fn iface_name(conf: &str) -> String {
    Path::new(conf)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn endpoint_value(text: &str) -> Option<&str> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("Endpoint")
            .then(|| value.trim())
    })
}

/// Resuelve `Endpoint = host:port` (o `[::1]:port`) a IPs numéricas.
/// La resolución inicial usa el resolver del sistema; si eso es un problema
/// de metadatos, usa una IP literal en el `.conf`.
pub fn resolve_endpoint(conf: &Path) -> Result<(Vec<IpAddr>, u16)> {
    let text = fs::read_to_string(conf)
        .with_context(|| format!("leyendo configuración WireGuard {}", conf.display()))?;
    let value = endpoint_value(&text).with_context(|| {
        format!(
            "{} no contiene una línea `Endpoint = host:puerto`",
            conf.display()
        )
    })?;
    let mut addrs = value
        .to_socket_addrs()
        .with_context(|| format!("resolviendo Endpoint `{value}`"))?
        .collect::<Vec<_>>();
    addrs.sort_by_key(std::net::SocketAddr::ip);
    addrs.dedup_by_key(|a| a.ip());
    let Some(first) = addrs.first() else {
        bail!("Endpoint `{value}` no resolvió a ninguna dirección");
    };
    let port = first.port();
    if addrs.iter().any(|a| a.port() != port) {
        bail!("Endpoint `{value}` resolvió a puertos distintos; usa una IP:puerto explícita");
    }
    Ok((addrs.iter().map(std::net::SocketAddr::ip).collect(), port))
}

fn check_config_permissions(path: &Path) -> Result<()> {
    let mode = fs::metadata(path)
        .with_context(|| format!("leyendo permisos de {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} es legible por otros usuarios (modo {:o}); contiene una clave privada. Ejecuta `chmod 600 {}`",
            path.display(),
            mode,
            path.display()
        );
    }
    Ok(())
}

fn hook_keys(text: &str) -> Vec<&str> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, _)| key.trim())
        .filter(|key| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "preup" | "postup" | "predown" | "postdown" | "saveconfig"
            )
        })
        .collect()
}

fn warn_about_hooks(conf: &Path, text: &str) {
    let hooks = hook_keys(text);
    if !hooks.is_empty() {
        eprintln!(
            "    aviso: {} contiene `{}`; wg-quick puede ejecutar comandos como root \
             o reescribir el archivo. Revisa la configuración antes de continuar.",
            conf.display(),
            hooks.join("`, `")
        );
    }
}

fn warn_about_dns(conf: &Path, text: &str) {
    if !text.lines().any(|l| {
        l.split_once('=')
            .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("DNS"))
    }) {
        return;
    }
    let symlink = fs::symlink_metadata(RESOLV_CONF).is_ok_and(|m| m.file_type().is_symlink());
    if !symlink {
        eprintln!(
            "    aviso: {} contiene DNS= y {RESOLV_CONF} es un archivo normal. \
             `wg-quick` puede reescribirlo; considera habilitar el módulo `dns` \
             o usar systemd-resolved.",
            conf.display()
        );
    }
}

pub fn enable(st: &mut State, conf: Option<&Path>) -> Result<()> {
    let Some(conf) = conf else {
        bail!("el módulo vpn necesita --vpn-conf /ruta/a/wg.conf (Proton, Mullvad, etc.)");
    };
    if !sys::have("wg-quick") {
        bail!("falta wireguard-tools: sudo pacman -S wireguard-tools");
    }
    let conf =
        fs::canonicalize(conf).with_context(|| format!("no se pudo abrir {}", conf.display()))?;
    if !conf.is_file() {
        bail!(
            "{} no es un archivo de configuración válido",
            conf.display()
        );
    }
    check_config_permissions(&conf)?;
    let text = fs::read_to_string(&conf)?;
    let (addrs, port) = resolve_endpoint(&conf)?;
    warn_about_dns(&conf, &text);
    warn_about_hooks(&conf, &text);
    if let Some(endpoint) = endpoint_value(&text) {
        if endpoint.parse::<SocketAddr>().is_err() {
            eprintln!(
                "    aviso: Endpoint `{endpoint}` no es una IP literal; resolverlo ahora \
                 puede revelar el host del VPN a tu DNS/ISP. Para evitarlo, usa \
                 `Endpoint = <IP>:<puerto>` en el .conf."
            );
        }
    }

    let c = conf.to_string_lossy().to_string();
    let iface = iface_name(&c);
    // No tocar una interfaz que ya existía: podría ser un túnel del usuario o
    // de otro gestor. `wg-quick down` sobre ella destruiría estado ajeno.
    if Path::new(&format!("/sys/class/net/{iface}")).exists() {
        bail!(
            "la interfaz {iface} ya existe; anonify no toca túneles que no inició. \
             Bájala explícitamente o ejecuta `anonify restore` si es un resto de anonify."
        );
    }
    if let Err(e) = sys::run("wg-quick", &["up", &c]) {
        // wg-quick puede haber creado una interfaz parcial antes de fallar.
        let _ = sys::run("wg-quick", &["down", &c]);
        return Err(e.context("wg-quick up falló"));
    }

    if !Path::new(&format!("/sys/class/net/{iface}")).exists() {
        let _ = sys::run("wg-quick", &["down", &c]);
        bail!("wg-quick up terminó pero la interfaz {iface} no existe");
    }

    st.vpn_conf = Some(c);
    st.vpn_endpoint_addrs = addrs.iter().map(ToString::to_string).collect();
    st.vpn_endpoint_port = Some(port);
    st.vpn_endpoint = None;
    Ok(())
}

pub fn disable(st: &mut State) -> Result<()> {
    let Some(c) = st.vpn_conf.clone() else {
        st.vpn_endpoint_addrs.clear();
        st.vpn_endpoint_port = None;
        st.vpn_endpoint = None;
        return Ok(());
    };
    let iface = iface_name(&c);
    if Path::new(&format!("/sys/class/net/{iface}")).exists() {
        sys::run("wg-quick", &["down", &c]).with_context(|| {
            format!("no se pudo bajar el VPN {iface}; se conserva el estado para reintentar")
        })?;
    }
    st.vpn_conf = None;
    st.vpn_endpoint_addrs.clear();
    st.vpn_endpoint_port = None;
    st.vpn_endpoint = None;
    Ok(())
}

/// Rellena el endpoint en el estado si falta (por ejemplo, tras actualizar
/// desde una versión anterior que solo guardaba un host).
pub fn ensure_endpoint(st: &mut State) -> Result<()> {
    let Some(c) = st.vpn_conf.clone() else {
        st.vpn_endpoint_addrs.clear();
        st.vpn_endpoint_port = None;
        return Ok(());
    };
    if !st.vpn_endpoint_addrs.is_empty() && st.vpn_endpoint_port.is_some() {
        return Ok(());
    }
    let (addrs, port) = resolve_endpoint(Path::new(&c))?;
    st.vpn_endpoint_addrs = addrs.iter().map(ToString::to_string).collect();
    st.vpn_endpoint_port = Some(port);
    Ok(())
}

pub fn holds(st: &State) -> bool {
    let Some(c) = st.vpn_conf.as_ref() else {
        return false;
    };
    let iface = iface_name(c);
    if !Path::new(&format!("/sys/class/net/{iface}")).exists() {
        return false;
    }
    sys::run("wg", &["show", &iface]).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_endpoint_case_insensitively() {
        let text =
            "[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\nEndpoint = 203.0.113.7:51820\n";
        assert_eq!(endpoint_value(text), Some("203.0.113.7:51820"));
        let text = "[Peer]\nendpoint=[2001:db8::1]:51820\n";
        assert_eq!(endpoint_value(text), Some("[2001:db8::1]:51820"));
    }

    #[test]
    fn rejects_missing_endpoint() {
        assert_eq!(endpoint_value("[Peer]\nPublicKey = y\n"), None);
    }

    #[test]
    fn interface_name_is_file_stem() {
        assert_eq!(iface_name("/etc/wireguard/mullvad-es.conf"), "mullvad-es");
    }

    #[test]
    fn detects_wg_quick_hooks_case_insensitively() {
        assert!(hook_keys("[Interface]\nPostUp = echo hi\n").contains(&"PostUp"));
        assert!(hook_keys("[Interface]\nsaveconfig=true\n").contains(&"saveconfig"));
        assert!(hook_keys("[Interface]\nPrivateKey = x\n").is_empty());
    }
}
