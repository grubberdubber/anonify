//! Estado persistido en /run (tmpfs): desaparece solo al reiniciar,
//! igual que todos los cambios que hace anonify.
use crate::modules::Module;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;

pub const DIR: &str = "/run/anonify";
const FILE: &str = "/run/anonify/state.json";

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct State {
    pub active: BTreeSet<Module>,
    /// interfaz -> MAC original
    pub macs: BTreeMap<String, String>,
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

impl State {
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
