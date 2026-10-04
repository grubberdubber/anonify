use crate::state::State;
use anyhow::{bail, Result};
use std::fs;

pub const HARDEN: &[(&str, &str)] = &[
    ("net.ipv4.tcp_timestamps", "0"),
    ("net.ipv4.conf.all.accept_redirects", "0"),
    ("net.ipv4.conf.default.accept_redirects", "0"),
    ("net.ipv4.conf.all.send_redirects", "0"),
    ("net.ipv4.conf.all.accept_source_route", "0"),
    ("net.ipv4.icmp_echo_ignore_all", "1"),
    ("kernel.kptr_restrict", "2"),
    ("kernel.dmesg_restrict", "1"),
    ("kernel.unprivileged_bpf_disabled", "2"),
];

pub const IPV6: &[(&str, &str)] = &[
    ("net.ipv6.conf.all.disable_ipv6", "1"),
    ("net.ipv6.conf.default.disable_ipv6", "1"),
];

fn path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}

/// Aplica cada clave y VERIFICA leyéndola de vuelta. Si alguna no queda
/// aplicada, falla: el módulo no debe figurar como activo sin estarlo.
pub fn apply(st: &mut State, list: &[(&str, &str)]) -> Result<()> {
    let mut failed: Vec<&str> = vec![];
    for (k, v) in list {
        let p = path(k);
        let Ok(old) = fs::read_to_string(&p) else {
            failed.push(*k);
            continue;
        };
        let old = old.trim().to_string();
        if old == *v {
            continue;
        }
        st.sysctl.entry(k.to_string()).or_insert(old);
        let applied = fs::write(&p, v).is_ok()
            && fs::read_to_string(&p).map(|s| s.trim() == *v).unwrap_or(false);
        if !applied {
            failed.push(*k);
        }
    }
    if !failed.is_empty() {
        bail!("no se pudo aplicar: {} (¿contenedor sin permiso o kernel sin esa clave?)", failed.join(", "));
    }
    Ok(())
}

pub fn revert(st: &mut State, list: &[(&str, &str)]) -> Result<()> {
    let mut stuck: Vec<&str> = vec![];
    for (k, _) in list {
        if let Some(old) = st.sysctl.remove(*k) {
            let p = path(k);
            let ok = fs::write(&p, &old).is_ok()
                && fs::read_to_string(&p).map(|s| s.trim() == old).unwrap_or(false);
            if !ok {
                stuck.push(*k);
            }
        }
    }
    if !stuck.is_empty() {
        bail!("no se pudo restaurar: {} (vuelve al reiniciar)", stuck.join(", "));
    }
    Ok(())
}

pub fn holds(list: &[(&str, &str)]) -> bool {
    list.iter()
        .all(|(k, v)| fs::read_to_string(path(k)).map(|s| s.trim() == *v).unwrap_or(false))
}
