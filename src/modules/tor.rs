//! Proxy transparente Tor con política fail-closed.
//!
//! Orden de arranque deliberado:
//!   1. Se instala la tabla `nftables` con `policy drop` **antes** de lanzar
//!      Tor. Así, mientras Tor hace bootstrap, el tráfico de usuario no puede
//!      salir en claro; solo el UID de Tor, loopback y DHCP están permitidos.
//!   2. Se lanza Tor y se espera el bootstrap leyendo el log técnico en tmpfs.
//!   3. Se verifica que el proceso es nuestro Tor (PID + cmdline) y que el
//!      SOCKS port responde.
//!
//! `disable` primero elimina la tabla (desbloquea la red) y después detiene
//! únicamente el proceso Tor que anonify inició. Nunca mata un PID ajeno.
use crate::{state::DIR, sys};
use anyhow::{bail, Context, Result};
use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::thread;
use std::time::Duration;

const TABLE: &str = "anonify_tor";
const SOCKS_PORT: u16 = 9050;
const TRANS_PORT: u16 = 9040;
const DNS_PORT: u16 = 5353;

fn dd() -> String {
    format!("{DIR}/tor")
}

fn torrc_path() -> String {
    format!("{DIR}/torrc")
}

fn log_path() -> String {
    format!("{}/notice.log", dd())
}

fn pid_path() -> String {
    format!("{}/tor.pid", dd())
}

fn read_uid() -> Result<u32> {
    let uid = sys::run("id", &["-u", "tor"])?;
    uid.parse::<u32>()
        .with_context(|| format!("UID de tor inválido: {uid}"))
}

/// Reglas nftables. `uid` ya está validado como número.
fn rules(uid: u32) -> String {
    format!(
        r#"table inet {TABLE} {{
  chain nat_out {{
    type nat hook output priority -100; policy accept;
    meta skuid {uid} return
    meta nfproto ipv6 return
    udp dport 53 redirect to :{DNS_PORT}
    oifname "lo" return
    meta l4proto tcp redirect to :{TRANS_PORT}
  }}
  chain out {{
    type filter hook output priority 0; policy drop;
    meta nfproto ipv6 drop
    meta skuid {uid} accept
    oifname "lo" accept
    ip daddr 127.0.0.0/8 accept
    udp sport 68 udp dport 67 accept
  }}
  chain in {{
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
  }}
}}
"#
    )
}

fn apply_rules(uid: u32) -> Result<()> {
    sys::run_stdin("nft", &["-f", "-"], &rules(uid))
}

fn port_free_tcp(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    match TcpListener::bind(addr) {
        Ok(l) => {
            drop(l);
            true
        }
        Err(e) => e.kind() != std::io::ErrorKind::AddrInUse,
    }
}

fn port_free_udp(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    match UdpSocket::bind(addr) {
        Ok(s) => {
            drop(s);
            true
        }
        Err(e) => e.kind() != std::io::ErrorKind::AddrInUse,
    }
}

fn preflight() -> Result<()> {
    if !sys::have("tor") {
        bail!("falta tor: sudo pacman -S tor");
    }
    if !sys::have("nft") {
        bail!("falta nftables: sudo pacman -S nftables");
    }
    if present() {
        bail!("la tabla inet {TABLE} ya existe; ejecuta `anonify restore` antes de reintentar");
    }
    if Path::new(&pid_path()).exists() {
        let pid = read_pid();
        if let Some(pid) = pid {
            if pid_alive(pid) {
                bail!(
                    "hay un proceso en {} (PID {pid}); si es un Tor de anonify, ejecuta `anonify restore`",
                    pid_path()
                );
            }
        }
        // PID file huérfano de una ejecución anterior; es nuestro y no hay
        // proceso vivo, así que se puede retirar.
        let _ = fs::remove_file(pid_path());
    }
    if !port_free_tcp(SOCKS_PORT) {
        bail!("el puerto TCP {SOCKS_PORT} ya está en uso (¿otro Tor?)");
    }
    if !port_free_tcp(TRANS_PORT) {
        bail!("el puerto TCP {TRANS_PORT} ya está en uso");
    }
    if !port_free_udp(DNS_PORT) {
        bail!("el puerto UDP {DNS_PORT} ya está en uso");
    }
    Ok(())
}

fn torrc() -> String {
    format!(
        "User tor\nDataDirectory {}\nPidFile {}\nRunAsDaemon 1\n\
         Log notice file {}\nSocksPort 127.0.0.1:{SOCKS_PORT} IsolateClientAddr\n\
         TransPort 127.0.0.1:{TRANS_PORT}\nDNSPort 127.0.0.1:{DNS_PORT}\n\
         AutomapHostsOnResolve 1\nVirtualAddrNetworkIPv4 10.192.0.0/10\n\
         ClientUseIPv6 0\nAvoidDiskWrites 1\nSafeLogging 1\n",
        dd(),
        pid_path(),
        log_path()
    )
}

fn prepare_dir() -> Result<()> {
    let d = dd();
    fs::create_dir_all(&d)?;
    sys::run("chown", &["tor:tor", &d])?;
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700))?;
    let rc = torrc_path();
    fs::write(&rc, torrc())?;
    // El archivo solo contiene opciones, no secretos; tor lo lee antes de
    // bajar privilegios. 0644 evita fallos si el umask es agresivo.
    fs::set_permissions(&rc, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

fn read_pid() -> Option<i32> {
    fs::read_to_string(pid_path())
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
}

fn pid_alive(pid: i32) -> bool {
    // SAFETY: `kill(pid, 0)` only checks existence/permission and sends no signal.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Solo consideramos nuestro al proceso si es `tor` y su cmdline apunta a
/// nuestro torrc. Esto evita matar un PID reciclado o un Tor del sistema.
fn is_our_tor(pid: i32) -> bool {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    if comm.trim() != "tor" {
        return false;
    }
    let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let wanted = torrc_path();
    cmdline
        .split(|b| *b == 0)
        .any(|arg| arg == wanted.as_bytes())
}

fn log_contains_after(path: &str, offset: u64, needle: &str) -> bool {
    let Ok(data) = fs::read(path) else {
        return false;
    };
    let start = usize::try_from(offset)
        .ok()
        .filter(|o| *o <= data.len())
        .unwrap_or(0);
    String::from_utf8_lossy(&data[start..]).contains(needle)
}

fn socks_ready() -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], SOCKS_PORT));
    for _ in 0..30 {
        if TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

pub fn enable() -> Result<()> {
    let uid = read_uid()?;
    preflight()?;
    prepare_dir()?;
    // No borramos logs: solo recordamos el tamaño previo para buscar el
    // bootstrap de ESTA ejecución. El aviso vive en tmpfs y no es un log del
    // sistema.
    let log_offset = fs::metadata(log_path()).map_or(0, |m| m.len());

    // Fail-closed: la red queda bloqueada/redirigida ANTES de que Tor arranque.
    apply_rules(uid)?;

    let rc = torrc_path();
    if let Err(e) = sys::run("tor", &["-f", &rc]) {
        let _ = disable();
        return Err(e.context("no se pudo lanzar tor"));
    }

    let bootstrapped = {
        let step = Duration::from_millis(500);
        let mut waited = Duration::ZERO;
        let deadline = Duration::from_secs(120);
        loop {
            if log_contains_after(&log_path(), log_offset, "Bootstrapped 100%") {
                break true;
            }
            if let Some(pid) = read_pid() {
                if !pid_alive(pid) {
                    break false;
                }
            } else if waited >= Duration::from_secs(10) {
                // Tor escribe el PidFile muy pronto; si no existe, el arranque
                // falló (config inválida, usuario tor ausente, etc.). No tiene
                // sentido mantener la red bloqueada 120 s.
                break false;
            }
            if waited >= deadline {
                break false;
            }
            thread::sleep(step);
            waited += step;
        }
    };

    if !bootstrapped {
        let cleanup = disable();
        let msg = format!(
            "Tor no completó el bootstrap o terminó durante el arranque (revisa {})",
            log_path()
        );
        match cleanup {
            Ok(()) => bail!("{msg}"),
            Err(e) => bail!("{msg}; además falló la limpieza: {e:#}"),
        }
    }

    let Some(pid) = read_pid() else {
        let _ = disable();
        bail!("Tor arrancó pero no escribió {}", pid_path());
    };
    if !is_our_tor(pid) {
        let _ = disable();
        bail!("el PID {pid} de {} no parece ser nuestro Tor", pid_path());
    }
    if !socks_ready() {
        let _ = disable();
        bail!("Tor no acepta conexiones en 127.0.0.1:{SOCKS_PORT}");
    }
    if !table_ok() {
        let _ = disable();
        bail!("la tabla inet {TABLE} desapareció o cambió tras el bootstrap");
    }
    println!("    Tor bootstrapped (PID {pid}), SOCKS 127.0.0.1:{SOCKS_PORT}");
    Ok(())
}

fn stop() -> Result<()> {
    let Some(pid) = read_pid() else {
        return Ok(());
    };
    if !pid_alive(pid) {
        let _ = fs::remove_file(pid_path());
        return Ok(());
    }
    if !is_our_tor(pid) {
        bail!(
            "{} apunta al PID {pid}, que no es un Tor de anonify; no se toca",
            pid_path()
        );
    }
    // SAFETY: PID verificado como nuestro proceso tor; SIGTERM es la señal
    // estándar de terminación y no destruye nada del sistema.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    for _ in 0..50 {
        if !pid_alive(pid) {
            let _ = fs::remove_file(pid_path());
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
    // Último recurso: el proceso sigue vivo tras 10 s.
    if is_our_tor(pid) {
        // SAFETY: same as above; PID still verified as our tor process.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        thread::sleep(Duration::from_millis(500));
    }
    if pid_alive(pid) {
        bail!("el Tor PID {pid} no terminó tras SIGKILL");
    }
    let _ = fs::remove_file(pid_path());
    Ok(())
}

pub fn disable() -> Result<()> {
    let table_was_present = present();
    if table_was_present {
        let _ = sys::run("nft", &["delete", "table", "inet", TABLE]);
    }
    let table_ok = !present();
    let stop_result = stop();
    if !table_ok {
        bail!("no se pudo eliminar la tabla inet {TABLE}");
    }
    stop_result
}

pub fn alive() -> bool {
    let Some(pid) = read_pid() else {
        return false;
    };
    pid_alive(pid) && is_our_tor(pid) && table_ok()
}

pub fn present() -> bool {
    sys::run("nft", &["list", "table", "inet", TABLE]).is_ok()
}

/// La tabla existe y sigue siendo fail-closed (no basta con el nombre).
fn table_ok() -> bool {
    sys::run("nft", &["list", "table", "inet", TABLE]).is_ok_and(|out| {
        out.contains("policy drop")
            && out.contains("redirect to :5353")
            && out.contains("meta nfproto ipv6 drop")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn rules_are_fail_closed_and_redirect() {
        let r = rules(998);
        assert!(r.contains("table inet anonify_tor"));
        assert!(r.contains("meta skuid 998"));
        assert!(r.contains("udp dport 53 redirect to :5353"));
        assert!(r.contains("meta l4proto tcp redirect to :9040"));
        assert!(r.contains("type filter hook output priority 0; policy drop"));
        assert!(r.contains("meta nfproto ipv6 drop"));
    }

    #[test]
    fn nft_accepts_generated_rules_when_privileged() {
        if !sys::have("nft") || sys::run("nft", &["list", "tables"]).is_err() {
            eprintln!("skip: nft/CAP_NET_ADMIN no disponible");
            return;
        }
        sys::run_stdin("nft", &["-c", "-f", "-"], &rules(998))
            .expect("nft debe aceptar la sintaxis de las reglas");
        if !sys::in_isolated_netns() {
            eprintln!("skip install: no estamos en un netns aislado");
            return;
        }
        sys::run_stdin("nft", &["-f", "-"], &rules(998)).expect("instalar tabla de prueba");
        assert!(present(), "la tabla de prueba debe existir");
        assert!(
            table_ok(),
            "la tabla debe conservar la política fail-closed"
        );
        sys::run("nft", &["delete", "table", "inet", TABLE]).expect("limpiar tabla de prueba");
    }

    #[test]
    fn log_offset_ignores_old_bootstrap() {
        let dir = std::env::temp_dir().join(format!(
            "anonify-tor-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).expect("dir");
        let p = dir.join("notice.log");
        fs::write(&p, "old Bootstrapped 100%\n").expect("write");
        let offset = fs::metadata(&p).expect("meta").len();
        fs::write(&p, "old Bootstrapped 100%\nnew line\n").expect("append");
        assert!(!log_contains_after(
            p.to_str().expect("utf8"),
            offset,
            "Bootstrapped 100%"
        ));
        let mut f = fs::OpenOptions::new().append(true).open(&p).expect("open");
        writeln!(f, "Bootstrapped 100%").expect("append");
        assert!(log_contains_after(
            p.to_str().expect("utf8"),
            offset,
            "Bootstrapped 100%"
        ));
        let _ = fs::remove_dir_all(dir);
    }
}
