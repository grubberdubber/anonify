use crate::{state::State, sys};
use anyhow::Result;
use rand::Rng;
use std::fs;

fn physical_ifaces() -> Vec<String> {
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
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

fn set_mac(iface: &str, mac: &str) -> Result<()> {
    sys::run("ip", &["link", "set", "dev", iface, "down"])?;
    let r = sys::run("ip", &["link", "set", "dev", iface, "address", mac]);
    sys::run("ip", &["link", "set", "dev", iface, "up"])?;
    r.map(|_| ())
}


pub fn disable(st: &mut State) -> Result<()> {
    for (i, mac) in std::mem::take(&mut st.macs) {
        if fs::metadata(format!("/sys/class/net/{i}")).is_ok() {
            set_mac(&i, &mac)?;
            println!("    {i}: restaurada {mac}");
        }
    }
    Ok(())
}

pub fn enable(st: &mut State) -> Result<()> {
    let ifaces = physical_ifaces();
    if ifaces.is_empty() {
        anyhow::bail!("no hay interfaces físicas (¿contenedor?): nada que cambiar");
    }
    let mut failed: Vec<String> = vec![];
    for i in ifaces {
        let orig = sys::read_trim(&format!("/sys/class/net/{i}/address"))?;
        let new = random_mac();
        match set_mac(&i, &new) {
            Ok(()) => {
                println!("    {i}: {orig} -> {new}");
                st.macs.entry(i).or_insert(orig);
            }
            Err(e) => {
                println!("    {i}: NO se pudo cambiar ({e:#})");
                failed.push(i);
            }
        }
    }
    if st.macs.is_empty() {
        anyhow::bail!("no se pudo cambiar la MAC de ninguna interfaz");
    }
    if !failed.is_empty() {
        println!("    ⚠ siguen con su MAC REAL: {}", failed.join(", "));
    }
    Ok(())
}
