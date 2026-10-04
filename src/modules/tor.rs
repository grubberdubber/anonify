//! Proxy transparente Tor. Todo el tráfico TCP y DNS del sistema se redirige
//! a Tor; cualquier otra cosa se descarta (sin fugas UDP/IPv6/ICMP).
//! Usa una tabla nft propia (`inet anonify_tor`): no toca tus reglas.
use crate::{state::DIR, sys};
use anyhow::{bail, Result};
use std::{fs, os::unix::fs::PermissionsExt, thread, time::Duration};

const TABLE: &str = "anonify_tor";

fn dd() -> String {
    format!("{DIR}/tor")
}

pub fn enable() -> Result<()> {
    if !sys::have("tor") {
        bail!("falta tor: sudo pacman -S tor");
    }
    if !sys::have("nft") {
        bail!("falta nftables: sudo pacman -S nftables");
    }
    let uid = sys::run("id", &["-u", "tor"])?;
    let d = dd();
    fs::create_dir_all(&d)?;
    sys::run("chown", &["tor:tor", &d])?;
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700))?;

    let torrc = format!(
        "User tor\nDataDirectory {d}\nPidFile {d}/tor.pid\nRunAsDaemon 1\n\
         Log notice file {d}/notice.log\nSocksPort 127.0.0.1:9050 IsolateClientAddr\n\
         TransPort 127.0.0.1:9040\nDNSPort 127.0.0.1:5353\nAutomapHostsOnResolve 1\n\
         VirtualAddrNetworkIPv4 10.192.0.0/10\nClientUseIPv6 0\nAvoidDiskWrites 1\nSafeLogging 1\n"
    );
    let rc = format!("{DIR}/torrc");
    fs::write(&rc, torrc)?;
    sys::run("tor", &["-f", &rc])?;

    print!("    esperando bootstrap de Tor");
    let log = format!("{d}/notice.log");
    let mut ok = false;
    for _ in 0..240 {
        if fs::read_to_string(&log).map(|s| s.contains("Bootstrapped 100%")).unwrap_or(false) {
            ok = true;
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    println!();
    if !ok {
        stop();
        bail!("Tor no completó el bootstrap en 120s (revisa {log})");
    }

    let rules = format!(
        r#"table inet {TABLE} {{
  chain nat_out {{
    type nat hook output priority -100; policy accept;
    meta skuid {uid} return
    udp dport 53 redirect to :5353
    oifname "lo" return
    meta l4proto tcp redirect to :9040
  }}
  chain out {{
    type filter hook output priority 0; policy drop;
    meta skuid {uid} accept
    oifname "lo" accept
    ip daddr 127.0.0.0/8 accept
    udp dport 67 accept
  }}
  chain in {{
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
  }}
}}
"#
    );
    sys::run_stdin("nft", &["-f", "-"], &rules)
}

fn stop() {
    if let Ok(pid) = sys::read_trim(&format!("{}/tor.pid", dd())) {
        if let Ok(p) = pid.parse::<i32>() {
            unsafe { libc::kill(p, libc::SIGTERM) };
        }
    }
}

pub fn disable() -> Result<()> {
    let _ = sys::run("nft", &["delete", "table", "inet", TABLE]);
    stop();
    Ok(())
}

pub fn alive() -> bool {
    let pid = sys::read_trim(&format!("{}/tor.pid", dd())).ok().and_then(|p| p.parse::<i32>().ok());
    let running = pid.map(|p| unsafe { libc::kill(p, 0) } == 0).unwrap_or(false);
    running && sys::run("nft", &["list", "table", "inet", TABLE]).is_ok()
}
