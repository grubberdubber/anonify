//! Estado persistido en /run (tmpfs): desaparece solo al reiniciar,
//! igual que todos los cambios que hace anonify.
use crate::modules::Module;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;

pub const DIR: &str = "/run/anonify";
const FILE: &str = "/run/anonify/state.json";
const LOCK: &str = "/run/anonify/state.lock";

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct State {
    pub active: BTreeSet<Module>,
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
        // SAFETY: flock on a valid, open fd for the lifetime of `f`.
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
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl State {
    /// Loads state without locking. Fine for read-only inspection (`status`,
    /// `check`) where a torn read at worst shows stale info for one call.
    pub fn load() -> Result<Self> {
        match fs::read_to_string(FILE) {
            Ok(s) => Ok(serde_json::from_str(&s)?),
            Err(_) => Ok(Self::default()),
        }
    }

    pub fn save(&self) -> Result<()> {
        fs::create_dir_all(DIR)?;
        fs::set_permissions(DIR, fs::Permissions::from_mode(0o755))?;
        fs::write(FILE, serde_json::to_string_pretty(self)?)?;
        fs::set_permissions(FILE, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}
