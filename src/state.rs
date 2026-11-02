//! Estado persistido en `/run` (tmpfs): desaparece solo al reiniciar,
//! igual que todos los cambios que hace anonify.
//!
//! El estado contiene los valores originales necesarios para restaurar el
//! sistema. Por eso se escribe de forma atómica (`tmp + fsync + rename`),
//! con permisos `0600`, y un estado corrupto produce un error en lugar de
//! reiniciarse en silencio perdiendo la información de restauración.
use crate::modules::Module;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

pub const DIR: &str = "/run/anonify";
const FILE: &str = "/run/anonify/state.json";
const LOCK: &str = "/run/anonify/state.lock";

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct State {
    pub active: BTreeSet<Module>,
    /// Módulos con cambios parciales que aún no se han podido deshacer.
    #[serde(default)]
    pub pending: BTreeSet<Module>,
    /// interfaz -> MAC original
    pub macs: BTreeMap<String, String>,
    #[serde(default)]
    pub mac_dirty: BTreeMap<String, String>,
    pub hostname: Option<String>,
    #[serde(default)]
    pub hostname_applied: Option<String>,
    #[serde(default)]
    pub nm_devices: Vec<String>,
    /// clave sysctl -> valor original
    pub sysctl: BTreeMap<String, String>,
    pub dns_bound: bool,
    pub vpn_conf: Option<String>,
    /// Endpoint(s) numéricos resueltos del VPN, para el kill switch.
    #[serde(default)]
    pub vpn_endpoint_addrs: Vec<String>,
    #[serde(default)]
    pub vpn_endpoint_port: Option<u16>,
    /// Campo legado de versiones anteriores; se conserva para no romper
    /// estados ya existentes. El código nuevo usa `vpn_endpoint_addrs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_endpoint: Option<String>,
}

/// Exclusive file lock held for the duration of a load-modify-save cycle.
/// Exists because the watchdog thread (Ctrl+C/SIGTERM/`--timeout`) and the
/// main thread can both end up calling `State::load`/`save` around the same
/// time; without serializing them, a signal landing mid-write could corrupt
/// `state.json` or make the watchdog act on stale data.
pub struct Lock(File);

impl Lock {
    pub fn acquire() -> Result<Self> {
        fs::create_dir_all(DIR).context("creando /run/anonify")?;
        let f = File::create(LOCK).context("abriendo state.lock")?;
        // SAFETY: `flock` operates on a valid, open fd for the lifetime of `f`.
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            anyhow::bail!(
                "no se pudo tomar el lock de estado: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(Lock(f))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: the fd is still open; unlocking is best-effort on drop.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl State {
    /// Loads state without locking. Fine for read-only inspection (`status`,
    /// `check`) where a torn read at worst shows stale info for one call.
    ///
    /// A missing file means "no active state" (first run). Any other read or
    /// parse error is fatal: silently starting from an empty state would lose
    /// the original MAC/hostname/sysctl values and could leave the system in a
    /// half-anonymized, half-original state.
    pub fn load() -> Result<Self> {
        Self::load_from(Path::new(FILE))
    }

    fn load_from(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).with_context(|| {
                format!(
                    "{} está corrupto; no se puede restaurar el estado original. \
                     Reinicia para descartar los cambios volátiles o revisa el archivo.",
                    path.display()
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("leyendo {}", path.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(Path::new(FILE))
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .context("la ruta de estado no tiene directorio padre")?;
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;

        let tmp = temp_path(path);
        let json = serde_json::to_vec_pretty(self).context("serializando el estado")?;
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .with_context(|| format!("abriendo {}", tmp.display()))?;
            f.write_all(&json)
                .with_context(|| format!("escribiendo {}", tmp.display()))?;
            f.sync_all()
                .with_context(|| format!("sincronizando {}", tmp.display()))?;
        }
        fs::rename(&tmp, path)
            .with_context(|| format!("renombrando {} -> {}", tmp.display(), path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let name = path.file_name().map_or_else(
        || "state.json".to_string(),
        |n| n.to_string_lossy().to_string(),
    );
    path.with_file_name(format!(".{name}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anonify-state-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).expect("crear directorio de test");
        dir
    }

    #[test]
    fn missing_state_is_empty() {
        let dir = tempdir();
        let path = dir.join("state.json");
        let st = State::load_from(&path).expect("estado ausente = vacío");
        assert!(st.active.is_empty());
        assert!(st.pending.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn roundtrip_preserves_restore_data() {
        let dir = tempdir();
        let path = dir.join("state.json");
        let mut st = State::default();
        st.active.insert(Module::Mac);
        st.pending.insert(Module::Tor);
        st.macs.insert("eth0".into(), "aa:bb:cc:dd:ee:ff".into());
        st.hostname = Some("original".into());
        st.vpn_endpoint_addrs = vec!["203.0.113.7".into()];
        st.vpn_endpoint_port = Some(51820);
        st.save_to(&path).expect("guardar");
        let loaded = State::load_from(&path).expect("cargar");
        assert_eq!(loaded.active, st.active);
        assert_eq!(loaded.pending, st.pending);
        assert_eq!(loaded.macs, st.macs);
        assert_eq!(loaded.hostname, st.hostname);
        assert_eq!(loaded.vpn_endpoint_addrs, st.vpn_endpoint_addrs);
        assert_eq!(loaded.vpn_endpoint_port, st.vpn_endpoint_port);
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_state_is_an_error() {
        let dir = tempdir();
        let path = dir.join("state.json");
        fs::write(&path, "{ not json").expect("escribir corrupto");
        let err = State::load_from(&path).expect_err("debe fallar");
        assert!(format!("{err:#}").contains("corrupto"));
        let _ = fs::remove_dir_all(dir);
    }
}
