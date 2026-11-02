//! Suplantación de MAC en interfaces físicas.
//!
//! Se usa una MAC unicast y localmente administrada (bit 0x02), que no
//! identifica a ningún fabricante. El módulo exige cubrir **todas** las
//! interfaces físicas: si una no se puede cambiar, falla y se revierte, para
//! no dar una falsa sensación de anonimato parcial.
use crate::{state::State, sys};
use anyhow::{bail, Result};
use rand::Rng;
use std::collections::BTreeMap;
use std::fs;

pub fn physical_ifaces() -> Vec<String> {
    let mut v = vec![];
    if let Ok(rd) = fs::read_dir("/sys/class/net") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name != "lo" && e.path().join("device").exists() {
                v.push(name);
            }
        }
    }
    v.sort();
    v
}

fn random_mac() -> String {
    let mut b: [u8; 6] = rand::thread_rng().gen();
    b[0] = (b[0] & 0xfe) | 0x02; // unicast + localmente administrada
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn set_mac(iface: &str, mac: &str) -> Result<()> {
    sys::run("ip", &["link", "set", "dev", iface, "down"])?;
    let r = sys::run("ip", &["link", "set", "dev", iface, "address", mac]);
    // Pase lo que pase con la dirección, intentamos dejar la interfaz arriba.
    let up = sys::run("ip", &["link", "set", "dev", iface, "up"]);
    r?;
    up?;
    let now = sys::read_trim(&format!("/sys/class/net/{iface}/address"))?;
    if now != mac {
        bail!("el driver no aplicó {mac} (el kernel muestra {now})");
    }
    Ok(())
}

fn current_mac(iface: &str) -> Option<String> {
    sys::read_trim(&format!("/sys/class/net/{iface}/address")).ok()
}

fn forget(st: &mut State, iface: &str) {
    st.macs.remove(iface);
    st.mac_dirty.remove(iface);
}

pub fn enable(st: &mut State) -> Result<()> {
    let ifaces = physical_ifaces();
    if ifaces.is_empty() {
        bail!("no hay interfaces físicas (¿contenedor?): nada que cambiar");
    }
    let mut failed: Vec<String> = vec![];
    for i in ifaces {
        let Some(current) = current_mac(&i) else {
            failed.push(i);
            continue;
        };
        // Si ya había un original guardado, no lo pises con una MAC spoofeada.
        let orig = st
            .macs
            .get(&i)
            .or_else(|| st.mac_dirty.get(&i))
            .cloned()
            .unwrap_or_else(|| current.clone());
        let mut new = random_mac();
        for _ in 0..8 {
            if new != current && new != orig {
                break;
            }
            new = random_mac();
        }
        match set_mac(&i, &new) {
            Ok(()) => {
                println!("    {i}: {orig} -> {new}");
                st.macs.insert(i.clone(), orig);
                st.mac_dirty.remove(&i);
            }
            Err(e) => {
                println!("    {i}: NO se pudo cambiar ({e:#})");
                // Algunos drivers dan error pero dejan otra MAC registrada:
                // guardar el original para que `restore` lo intente.
                match current_mac(&i) {
                    Some(now) if now != orig => {
                        println!(
                            "    ⚠ {i}: el kernel muestra {now}; se restaurará {orig} (esa MAC no es fiable)"
                        );
                        st.mac_dirty.insert(i.clone(), orig);
                    }
                    _ => {}
                }
                failed.push(i);
            }
        }
    }
    if !failed.is_empty() {
        bail!(
            "no se pudo cambiar la MAC de: {} (el módulo exige cubrir todas las interfaces; se revierten las que sí cambiaron)",
            failed.join(", ")
        );
    }
    Ok(())
}

pub fn disable(st: &mut State) -> Result<()> {
    // Snapshot: solo borramos del estado lo que se restaure con éxito.
    let mut todo: BTreeMap<String, String> = st.macs.clone();
    todo.extend(st.mac_dirty.clone());
    let mut stuck: Vec<String> = vec![];
    for (i, orig) in todo {
        if fs::metadata(format!("/sys/class/net/{i}")).is_err() {
            // La interfaz ya no existe (USB desconectado, etc.).
            forget(st, &i);
            continue;
        }
        let Some(now) = current_mac(&i) else {
            stuck.push(i);
            continue;
        };
        if now == orig {
            forget(st, &i);
            continue;
        }
        match set_mac(&i, &orig) {
            Ok(()) => {
                println!("    {i}: restaurada {orig}");
                forget(st, &i);
            }
            Err(e) => {
                println!("    aviso: {i}: no se pudo restaurar {orig} ({e:#})");
                stuck.push(i);
            }
        }
    }
    if !stuck.is_empty() {
        bail!(
            "MAC sin restaurar en: {} (el original se conserva; reintenta `anonify restore`)",
            stuck.join(", ")
        );
    }
    Ok(())
}

/// Comprueba que TODAS las interfaces físicas actuales tienen una MAC distinta
/// de la original guardada. Si aparece una interfaz nueva sin spoofear, hay
/// drift y `status` debe avisar.
pub fn holds(st: &State) -> bool {
    let ifaces = physical_ifaces();
    !st.macs.is_empty()
        && !ifaces.is_empty()
        && ifaces.iter().all(|i| {
            let Some(orig) = st.macs.get(i) else {
                return false;
            };
            current_mac(i).is_some_and(|now| &now != orig)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_mac_is_unicast_and_local() {
        for _ in 0..256 {
            let mac = random_mac();
            let parts: Vec<&str> = mac.split(':').collect();
            assert_eq!(parts.len(), 6);
            let first = u8::from_str_radix(parts[0], 16).expect("hex");
            assert_eq!(first & 0x01, 0, "debe ser unicast");
            assert_eq!(first & 0x02, 2, "debe ser localmente administrada");
            assert_ne!(mac, "00:00:00:00:00:00");
        }
    }
}
