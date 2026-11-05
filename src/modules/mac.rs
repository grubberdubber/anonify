//! Suplantación de MAC en interfaces físicas.
//!
//! Por defecto se usa una MAC unicast y localmente administrada (bit 0x02),
//! que no identifica a ningún fabricante y evita colisiones con dispositivos
//! reales de la LAN. Algunas redes (portales cautivos, filtros corporativos,
//! políticas de "solo dispositivos conocidos") rechazan esos prefijos: para
//! ese caso `--mac-vendor` elige un OUI real de un fabricante común. Es una
//! decisión con contrapartida: un OUI real puede coincidir con un equipo de la
//! misma red, y usar una identidad de fabricante en una red ajena puede violar
//! sus políticas. La MAC local sigue siendo la opción por defecto.
//!
//! El módulo exige cubrir **todas** las interfaces físicas: si una no se
//! puede cambiar, falla y se revierte, para no dar una falsa sensación de
//! anonimato parcial.
use crate::{state::State, sys};
use anyhow::{Result, bail};
use clap::ValueEnum;
use rand::Rng;
use std::collections::BTreeMap;
use std::fs;

/// Prefijos OUI (3 octetos) de fabricantes reales, todos unicast y con el bit
/// de administración global a 0. Repartir el tráfico entre varios fabricantes
/// de una misma red es más ruidoso que quedarse con uno solo.
const INTEL: &[&str] = &["00:1b:21", "00:1e:67", "3c:97:0e"];
const APPLE: &[&str] = &["3c:22:fb", "f0:18:98", "a4:83:e7"];
const CISCO: &[&str] = &["00:1a:a1", "00:1b:d4", "f0:9e:63"];
const DELL: &[&str] = &["00:14:22", "b8:2a:72", "f8:bc:12"];
const SAMSUNG: &[&str] = &["5c:0a:5b", "8c:77:12", "e8:50:8b"];
const TPLINK: &[&str] = &["00:1d:0f", "50:c7:bf", "a4:2b:b0"];
const REALTEK: &[&str] = &["00:e0:4c"];
const RASPBERRY: &[&str] = &["b8:27:eb", "dc:a6:32", "e4:5f:01"];

/// Cómo se genera la MAC de cada interfaz.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
pub enum Vendor {
    /// MAC localmente administrada, sin fabricante (por defecto y recomendado).
    #[default]
    Local,
    /// Elige al azar entre todos los prefijos de fabricante conocidos.
    Random,
    Intel,
    Apple,
    Cisco,
    Dell,
    Samsung,
    #[value(name = "tp-link")]
    TpLink,
    Realtek,
    Raspberry,
}

impl Vendor {
    /// Nombre estable que `rotate` guarda en el estado para reproducir la
    /// misma política que se usó al activar el módulo.
    pub fn as_str(self) -> &'static str {
        match self {
            Vendor::Local => "local",
            Vendor::Random => "random",
            Vendor::Intel => "intel",
            Vendor::Apple => "apple",
            Vendor::Cisco => "cisco",
            Vendor::Dell => "dell",
            Vendor::Samsung => "samsung",
            Vendor::TpLink => "tp-link",
            Vendor::Realtek => "realtek",
            Vendor::Raspberry => "raspberry",
        }
    }

    /// Inverso de [`Vendor::as_str`]. Un valor desconocido (estado de una
    /// versión futura) cae a `local`, que es siempre seguro.
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "local" => Vendor::Local,
            "random" => Vendor::Random,
            "intel" => Vendor::Intel,
            "apple" => Vendor::Apple,
            "cisco" => Vendor::Cisco,
            "dell" => Vendor::Dell,
            "samsung" => Vendor::Samsung,
            "tp-link" => Vendor::TpLink,
            "realtek" => Vendor::Realtek,
            "raspberry" => Vendor::Raspberry,
            _ => return None,
        })
    }

    fn prefixes(self) -> &'static [&'static str] {
        match self {
            Vendor::Local | Vendor::Random => &[],
            Vendor::Intel => INTEL,
            Vendor::Apple => APPLE,
            Vendor::Cisco => CISCO,
            Vendor::Dell => DELL,
            Vendor::Samsung => SAMSUNG,
            Vendor::TpLink => TPLINK,
            Vendor::Realtek => REALTEK,
            Vendor::Raspberry => RASPBERRY,
        }
    }
}

const ALL_OUIS: &[&[&str]] = &[
    INTEL, APPLE, CISCO, DELL, SAMSUNG, TPLINK, REALTEK, RASPBERRY,
];

/// Un prefijo es utilizable si son 3 octetos hex válidos, unicast (bit 0 del
/// primer octeto a 0) y globalmente administrado (bit 1 a 0).
fn prefix_is_valid(prefix: &str) -> bool {
    let octets: Vec<&str> = prefix.split(':').collect();
    if octets.len() != 3 || octets.iter().any(|o| o.len() != 2) {
        return false;
    }
    let Some(first) = octets.first().and_then(|o| u8::from_str_radix(o, 16).ok()) else {
        return false;
    };
    (first & 0x01) == 0 && (first & 0x02) == 0
}

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

/// MAC unicast + localmente administrada: no representa a ningún fabricante.
fn random_mac() -> String {
    let mut b: [u8; 6] = rand::rng().random();
    b[0] = (b[0] & 0xfe) | 0x02;
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn with_prefix(prefix: &str) -> String {
    if !prefix_is_valid(prefix) {
        // Defensa en profundidad: un prefijo mal formado nunca debe llegar a
        // `ip link`, así que se cae al valor seguro.
        return random_mac();
    }
    let tail: [u8; 3] = rand::rng().random();
    format!("{prefix}:{:02x}:{:02x}:{:02x}", tail[0], tail[1], tail[2])
}

fn random_vendor_prefix() -> &'static str {
    let set = ALL_OUIS[rand::rng().random_range(0..ALL_OUIS.len())];
    set[rand::rng().random_range(0..set.len())]
}

/// MAC a aplicar según la política elegida.
pub fn generate(vendor: Vendor) -> String {
    match vendor {
        Vendor::Local => random_mac(),
        Vendor::Random => with_prefix(random_vendor_prefix()),
        specific => {
            let prefixes = specific.prefixes();
            if prefixes.is_empty() {
                return random_mac();
            }
            with_prefix(prefixes[rand::rng().random_range(0..prefixes.len())])
        }
    }
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

pub fn enable(st: &mut State, vendor: Vendor) -> Result<()> {
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
        let mut new = generate(vendor);
        for _ in 0..8 {
            if new != current && new != orig {
                break;
            }
            new = generate(vendor);
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
    st.mac_vendor = Some(vendor.as_str().to_string());
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
    st.mac_vendor = None;
    Ok(())
}

/// Comprueba que TODAS las interfaces físicas actuales tienen una MAC distinta
/// de la original guardada y que no quedó ninguna a medio restaurar. Si aparece
/// una interfaz nueva sin spoofear, hay drift y `status` debe avisar.
pub fn holds(st: &State) -> bool {
    if !st.mac_dirty.is_empty() {
        return false;
    }
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

    #[test]
    fn every_vendor_oui_is_globally_administered_unicast() {
        for prefix in ALL_OUIS.iter().flat_map(|set| set.iter()) {
            assert!(
                prefix_is_valid(prefix),
                "{prefix} no es un OUI unicast global"
            );
        }
        assert!(
            !prefix_is_valid("52:54:00"),
            "QEMU es localmente administrada"
        );
        assert!(!prefix_is_valid("zz:00:00"));
        assert!(!prefix_is_valid("00:11"));
    }

    #[test]
    fn vendor_mac_uses_the_requested_prefix() {
        for _ in 0..64 {
            let mac = generate(Vendor::Apple);
            assert!(
                APPLE.iter().any(|p| mac.starts_with(&format!("{p}:"))),
                "{mac} no usa un OUI de Apple"
            );
            assert_eq!(mac.split(':').count(), 6);
        }
    }

    #[test]
    fn vendor_names_roundtrip_for_rotate() {
        for vendor in [
            Vendor::Local,
            Vendor::Random,
            Vendor::Intel,
            Vendor::Apple,
            Vendor::Cisco,
            Vendor::Dell,
            Vendor::Samsung,
            Vendor::TpLink,
            Vendor::Realtek,
            Vendor::Raspberry,
        ] {
            assert_eq!(Vendor::parse(vendor.as_str()), Some(vendor));
        }
        assert_eq!(Vendor::parse("no-such-vendor"), None);
    }

    #[test]
    fn local_policy_never_leaks_a_vendor_prefix() {
        let mac = generate(Vendor::Local);
        let first = u8::from_str_radix(mac.split(':').next().expect("octeto"), 16).expect("hex");
        assert_eq!(first & 0x03, 0x02);
    }

    #[test]
    fn random_policy_stays_within_the_known_ouis() {
        for _ in 0..64 {
            let mac = generate(Vendor::Random);
            let prefix = mac.split(':').take(3).collect::<Vec<_>>().join(":");
            assert!(
                ALL_OUIS.iter().copied().flatten().any(|p| *p == prefix),
                "{prefix} no está en la tabla"
            );
        }
    }
}
