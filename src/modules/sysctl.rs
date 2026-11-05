//! Hardening de red a nivel de kernel (`sysctl`), reversible y verificado.
//!
//! Cada clave se lee antes de escribirla. Si una aplicación falla a mitad,
//! se revierten las claves ya tocadas para no dejar un estado parcial. Si una
//! restauración falla, el valor original permanece en `State` para reintentar
//! con `anonify restore`.
use crate::state::State;
use anyhow::{Result, bail};
use std::fs;
use std::path::{Path, PathBuf};

/// Hardening conservador de red. Todas las claves son runtime y reversibles.
pub const HARDEN: &[(&str, &str)] = &[
    // Fingerprinting de stack / timestamps.
    ("net.ipv4.tcp_timestamps", "0"),
    // ICMP: no responder echo, ignorar respuestas bogus.
    ("net.ipv4.icmp_echo_ignore_all", "1"),
    ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
    // Redirects y source routing (IPv4).
    ("net.ipv4.conf.all.accept_redirects", "0"),
    ("net.ipv4.conf.default.accept_redirects", "0"),
    ("net.ipv4.conf.all.send_redirects", "0"),
    ("net.ipv4.conf.default.send_redirects", "0"),
    ("net.ipv4.conf.all.secure_redirects", "0"),
    ("net.ipv4.conf.default.secure_redirects", "0"),
    ("net.ipv4.conf.all.accept_source_route", "0"),
    ("net.ipv4.conf.default.accept_source_route", "0"),
    // Exposición de información del kernel. No se toca `dmesg_restrict`:
    // restringir el acceso a `dmesg` puede obstruir diagnóstico forense y
    // queda fuera del alcance de esta herramienta (ver AGENTS.md).
    ("kernel.kptr_restrict", "2"),
    ("kernel.unprivileged_bpf_disabled", "2"),
];

/// IPv6 apagado + hardening de redirects/source routing por si algún día se
/// vuelve a habilitar dentro de la misma sesión.
pub const IPV6: &[(&str, &str)] = &[
    ("net.ipv6.conf.all.disable_ipv6", "1"),
    ("net.ipv6.conf.default.disable_ipv6", "1"),
    ("net.ipv6.conf.all.accept_redirects", "0"),
    ("net.ipv6.conf.default.accept_redirects", "0"),
    ("net.ipv6.conf.all.accept_source_route", "0"),
    ("net.ipv6.conf.default.accept_source_route", "0"),
];

const SYSCTL_ROOT: &str = "/proc/sys";

fn path_at(base: &Path, key: &str) -> PathBuf {
    base.join(key.replace('.', "/"))
}

fn read_key(base: &Path, key: &str) -> Option<String> {
    fs::read_to_string(path_at(base, key))
        .ok()
        .map(|s| s.trim().to_string())
}

fn write_key(base: &Path, key: &str, value: &str) -> bool {
    let p = path_at(base, key);
    fs::write(&p, value).is_ok() && read_key(base, key).as_deref() == Some(value)
}

/// Aplica cada clave y VERIFICA leyéndola de vuelta. Si alguna no queda
/// aplicada, revierte las anteriores y falla: el módulo no debe figurar como
/// activo sin estarlo, ni dejar un hardening a medias.
pub fn apply(st: &mut State, list: &[(&str, &str)]) -> Result<()> {
    apply_at(Path::new(SYSCTL_ROOT), st, list)
}

fn apply_at(base: &Path, st: &mut State, list: &[(&str, &str)]) -> Result<()> {
    let mut touched: Vec<(&str, String)> = Vec::new();
    for (k, v) in list {
        let Some(old) = read_key(base, k) else {
            let stuck = rollback(base, st, &touched);
            bail!(
                "no se pudo leer {k} en {} (¿contenedor sin permiso o kernel sin esa clave?){}",
                base.display(),
                stuck_suffix(&stuck)
            );
        };
        if old == *v {
            continue;
        }
        // Guardar el original ANTES de escribir: si el write deja un valor
        // intermedio, el rollback y `restore` saben qué restaurar.
        st.sysctl.insert((*k).to_string(), old.clone());
        touched.push((k, old));
        if !write_key(base, k, v) {
            let stuck = rollback(base, st, &touched);
            bail!(
                "no se pudo aplicar {k}={v} en {} (¿contenedor sin permiso?){}",
                base.display(),
                stuck_suffix(&stuck)
            );
        }
    }
    Ok(())
}

/// Restaura una clave y decide si el valor original ya está garantizado.
///
/// `write_key` puede fallar porque la clave es de solo lectura (por ejemplo,
/// un sysctl global dentro de un contenedor rootless). Si al releerla el valor
/// sigue siendo el original, el sistema nunca cambió: no hay nada pendiente y
/// conservarla en `State` bloquearía `cleanup_pending` para siempre.
fn restore_key(base: &Path, key: &str, old: &str) -> bool {
    write_key(base, key, old) || read_key(base, key).as_deref() == Some(old)
}

fn rollback(base: &Path, st: &mut State, touched: &[(&str, String)]) -> Vec<String> {
    let mut stuck = Vec::new();
    for (k, old) in touched.iter().rev() {
        if restore_key(base, k, old) {
            st.sysctl.remove(*k);
        } else {
            stuck.push((*k).to_string());
        }
    }
    stuck
}

fn stuck_suffix(stuck: &[String]) -> String {
    if stuck.is_empty() {
        "; cambios revertidos".to_string()
    } else {
        format!(
            "; ATENCIÓN: no se pudieron revertir {} (se reintentará con `anonify restore`)",
            stuck.join(", ")
        )
    }
}

pub fn revert(st: &mut State, list: &[(&str, &str)]) -> Result<()> {
    revert_at(Path::new(SYSCTL_ROOT), st, list)
}

fn revert_at(base: &Path, st: &mut State, list: &[(&str, &str)]) -> Result<()> {
    let mut stuck: Vec<String> = Vec::new();
    for (k, _) in list {
        let Some(old) = st.sysctl.get(*k).cloned() else {
            continue;
        };
        if restore_key(base, k, &old) {
            st.sysctl.remove(*k);
        } else {
            stuck.push((*k).to_string());
        }
    }
    if !stuck.is_empty() {
        bail!(
            "no se pudo restaurar: {} (el valor original se conserva; reintenta `anonify restore`)",
            stuck.join(", ")
        );
    }
    Ok(())
}

pub fn holds(list: &[(&str, &str)]) -> bool {
    holds_at(Path::new(SYSCTL_ROOT), list)
}

fn holds_at(base: &Path, list: &[(&str, &str)]) -> bool {
    list.iter()
        .all(|(k, v)| read_key(base, k).as_deref() == Some(*v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anonify-sysctl-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).expect("crear directorio de test");
        dir
    }

    fn seed(base: &Path, key: &str, value: &str) {
        let p = path_at(base, key);
        fs::create_dir_all(p.parent().expect("padre")).expect("crear padre");
        fs::write(p, format!("{value}\n")).expect("sembrar");
    }

    #[test]
    fn apply_and_revert_roundtrip() {
        let base = tempdir();
        seed(&base, "net.ipv4.tcp_timestamps", "1");
        seed(&base, "net.ipv4.icmp_echo_ignore_all", "0");
        let list = &[
            ("net.ipv4.tcp_timestamps", "0"),
            ("net.ipv4.icmp_echo_ignore_all", "1"),
        ];
        let mut st = State::default();
        apply_at(&base, &mut st, list).expect("aplicar");
        assert!(holds_at(&base, list));
        assert_eq!(st.sysctl.len(), 2);
        revert_at(&base, &mut st, list).expect("revertir");
        assert_eq!(
            read_key(&base, "net.ipv4.tcp_timestamps").as_deref(),
            Some("1")
        );
        assert_eq!(
            read_key(&base, "net.ipv4.icmp_echo_ignore_all").as_deref(),
            Some("0")
        );
        assert!(st.sysctl.is_empty());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn partial_failure_rolls_back_touched_keys() {
        let base = tempdir();
        seed(&base, "net.ipv4.tcp_timestamps", "1");
        // The second key is missing: apply must restore the first one.
        let list = &[
            ("net.ipv4.tcp_timestamps", "0"),
            ("net.ipv4.does_not_exist", "1"),
        ];
        let mut st = State::default();
        let err = apply_at(&base, &mut st, list).expect_err("debe fallar");
        assert!(format!("{err:#}").contains("does_not_exist"));
        assert_eq!(
            read_key(&base, "net.ipv4.tcp_timestamps").as_deref(),
            Some("1")
        );
        assert!(st.sysctl.is_empty());
        let _ = fs::remove_dir_all(base);
    }
}
