//! `/etc/resolv.conf` temporal en tmpfs, apuntando a `127.0.0.1`.
//!
//! El puerto 53 no se puede expresar en `resolv.conf`; la resolución real la
//! hace la tabla `nftables` de Tor, que redirige UDP/53 al `DNSPort` local
//! (5353). Por eso este módulo exige que `tor` esté activo: sin esa capa,
//! cambiar `resolv.conf` a 127.0.0.1 dejaría el DNS roto (fail-closed) o,
//! peor, apuntaría a un resolver local no anónimo.
use super::tor;
use crate::{
    state::{DIR, State},
    sys,
};
use anyhow::{Result, bail};
use std::fs;
use std::path::{Path, PathBuf};

const TARGET: &str = "/etc/resolv.conf";
const MARKER: &str = "anonify";
const MOUNTINFO: &str = "/proc/self/mountinfo";

fn content() -> String {
    format!("# {MARKER} (temporal)\nnameserver 127.0.0.1\noptions edns0 trust-ad\n")
}

/// `mountinfo` escapa espacios, tabs, saltos de línea y `\` como `\040`,
/// `\011`, `\012` y `\134`. Decodificarlos permite comparar rutas reales.
fn unescape_mountinfo(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let octal = std::str::from_utf8(&bytes[i + 1..i + 4])
                .ok()
                .and_then(|s| u8::from_str_radix(s, 8).ok());
            if let Some(value) = octal {
                out.push(value);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn mountinfo_contains(info: &str, target: &Path) -> bool {
    let target = target.to_string_lossy();
    info.lines().any(|line| {
        line.split_whitespace()
            .nth(4)
            .is_some_and(|field| unescape_mountinfo(field) == target)
    })
}

fn resolved_target() -> Option<PathBuf> {
    fs::canonicalize(TARGET).ok()
}

fn is_mounted() -> bool {
    let Some(target) = resolved_target() else {
        return false;
    };
    fs::read_to_string(MOUNTINFO).is_ok_and(|info| mountinfo_contains(&info, &target))
}

/// Nuestro bind mount se reconoce por el marcador **y** por ser un montaje
/// real. Un archivo normal con la palabra "anonify" no basta.
fn is_ours() -> bool {
    is_mounted() && fs::read_to_string(TARGET).is_ok_and(|s| s.contains(MARKER))
}

pub fn enable(st: &mut State) -> Result<()> {
    if is_ours() {
        // Puede ser un estado recuperado tras un crash: el bind mount sigue
        // ahí y no hay que montarlo dos veces.
        st.dns_bound = true;
        return Ok(());
    }
    if is_mounted() {
        bail!(
            "{TARGET} ya es un punto de montaje ajeno a anonify; no se sobrescribe. \
             Restaura ese montaje o usa `anonify restore` para limpiar el estado."
        );
    }
    if st.dns_bound {
        bail!(
            "el estado dice que DNS está montado pero {TARGET} no es de anonify; \
             ejecuta `anonify restore`"
        );
    }
    if !tor::alive() {
        bail!("el módulo dns requiere Tor activo (`anonify enable tor dns`) para no filtrar DNS");
    }
    fs::create_dir_all(DIR)?;
    let tmp = format!("{DIR}/resolv.conf");
    fs::write(&tmp, content())?;
    sys::run("mount", &["--bind", &tmp, TARGET])?;
    if !is_ours() {
        let _ = sys::run("umount", &[TARGET]);
        bail!("el bind mount de {TARGET} no quedó aplicado");
    }
    st.dns_bound = true;
    Ok(())
}

pub fn disable(st: &mut State) -> Result<()> {
    if !st.dns_bound && !is_ours() {
        return Ok(());
    }
    if !is_mounted() {
        // Alguien desmontó el archivo por fuera: no hay nada que deshacer y
        // no se toca ningún montaje ajeno.
        st.dns_bound = false;
        return Ok(());
    }
    if !is_ours() {
        bail!(
            "{TARGET} está montado pero no es el archivo de anonify; no se desmonta. \
             Inspecciona el montaje manualmente."
        );
    }
    sys::run("umount", &[TARGET])?;
    if is_mounted() {
        bail!("{TARGET} sigue montado tras umount; reintenta `anonify restore`");
    }
    st.dns_bound = false;
    Ok(())
}

pub fn holds(st: &State) -> bool {
    st.dns_bound && is_ours()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_resolver_is_loopback_only() {
        let c = content();
        assert!(c.contains("nameserver 127.0.0.1"));
        assert!(c.contains(MARKER));
        assert!(!c.contains("8.8.8.8"));
        assert!(!c.contains("1.1.1.1"));
    }

    #[test]
    fn decodes_mountinfo_escapes() {
        assert_eq!(unescape_mountinfo(r"/run/with\040space"), "/run/with space");
        assert_eq!(
            unescape_mountinfo(r"/run/back\134slash"),
            r"/run/back\slash"
        );
    }

    #[test]
    fn finds_only_exact_mount_point() {
        let info = "36 25 0:32 / /run/anonify rw,nosuid - tmpfs tmpfs rw\n\
                    37 25 0:33 / /etc/resolv.conf rw - ext4 /dev/sda1 rw\n";
        assert!(mountinfo_contains(info, Path::new("/etc/resolv.conf")));
        assert!(!mountinfo_contains(info, Path::new("/etc")));
    }
}
