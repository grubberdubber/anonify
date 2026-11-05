//! Hardened, throwaway browser profile — portable across Linux, Windows and
//! macOS.
//!
//! A proxy only hides the IP. The browser still leaks the local address over
//! WebRTC, resolves DNS outside the tunnel, talks to DoH/telemetry/Safe
//! Browsing endpoints on its own, and links sessions if the profile persists.
//! This module writes a fresh `user.js` for every run and starts the browser
//! with it, so the main deanonymization surfaces are closed even if the app
//! itself ignores `ALL_PROXY`.
//!
//! What it does **not** do:
//!
//! - It never deletes the profile. Wiping a session's history is exactly the
//!   anti-forensic behavior `AGENTS.md` forbids; volatility comes from where
//!   the profile lives (tmpfs) on Linux, not from unlinking evidence.
//! - It never touches the user's normal Firefox profile, `/etc/localtime` or
//!   the system clock.
//! - It does not guarantee anonymity: without Tor (or a VPN) behind it, the
//!   browser uses the real network and says so.
//!
//! Platform notes: on Linux the profile goes to `XDG_RUNTIME_DIR` or
//! `/dev/shm` (RAM). Windows has no tmpfs, so it goes to `%TEMP%\anonify`;
//! permanent private browsing keeps history and cache out of it, but the
//! directory itself stays until the user or the OS cleans the temp folder.

use crate::i18n::{Lang, tr};
use anyhow::{Context, Result, bail};
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

/// Local SOCKS port used by `anonify tor` and by Tor Browser / the Tor Expert
/// Bundle.
pub const SOCKS_PORT: u16 = 9050;

const BROWSERS: &[&str] = &["librewolf", "firefox", "firefox-esr"];

#[cfg(windows)]
const EXE_SUFFIXES: &[&str] = &["", ".exe"];
#[cfg(not(windows))]
const EXE_SUFFIXES: &[&str] = &[""];

/// Preferences written to the ephemeral `user.js`.
const BASE_PREFS: &[&str] = &[
    "// Perfil efímero generado por anonify. Vive en RAM (o en el temporal del",
    "// sistema fuera de Linux) y no se borra: no modifica tu perfil normal.",
    "",
    "// --- Huella del navegador y de la máquina ---",
    "user_pref(\"privacy.resistFingerprinting\", true);",
    "user_pref(\"privacy.resistFingerprinting.letterboxing\", true);",
    "user_pref(\"privacy.firstparty.isolate\", true);",
    "user_pref(\"privacy.trackingprotection.enabled\", true);",
    "user_pref(\"privacy.trackingprotection.socialtracking.enabled\", true);",
    "user_pref(\"webgl.disabled\", true);",
    "user_pref(\"dom.battery.enabled\", false);",
    "user_pref(\"device.sensors.enabled\", false);",
    "user_pref(\"media.navigator.enabled\", false);",
    "user_pref(\"geo.enabled\", false);",
    "user_pref(\"permissions.default.geo\", 2);",
    "user_pref(\"permissions.default.desktop-notification\", 2);",
    "",
    "// --- Fugas de red que no pasan por el proxy ---",
    "user_pref(\"media.peerconnection.enabled\", false);",
    "user_pref(\"network.dns.disableIPv6\", true);",
    "user_pref(\"network.trr.mode\", 5);",
    "user_pref(\"network.captive-portal-service.enabled\", false);",
    "user_pref(\"network.connectivity-service.enabled\", false);",
    "user_pref(\"network.dns.disablePrefetch\", true);",
    "user_pref(\"network.prefetch-next\", false);",
    "user_pref(\"network.predictor.enabled\", false);",
    "user_pref(\"network.http.speculative-parallel-limit\", 0);",
    "user_pref(\"browser.places.speculativeConnect.enabled\", false);",
    "user_pref(\"beacon.enabled\", false);",
    "user_pref(\"browser.send_pings\", false);",
    "user_pref(\"network.http.referer.XOriginTrimmingPolicy\", 2);",
    "user_pref(\"security.OCSP.enabled\", 0);",
    "",
    "// --- Servicios y telemetría que hablan con terceros ---",
    "user_pref(\"toolkit.telemetry.enabled\", false);",
    "user_pref(\"toolkit.telemetry.unified\", false);",
    "user_pref(\"toolkit.telemetry.archive.enabled\", false);",
    "user_pref(\"datareporting.healthreport.uploadEnabled\", false);",
    "user_pref(\"datareporting.policy.dataSubmissionEnabled\", false);",
    "user_pref(\"app.shield.optoutstudies.enabled\", false);",
    "user_pref(\"app.normandy.enabled\", false);",
    "user_pref(\"browser.ping-centre.telemetry\", false);",
    "user_pref(\"browser.newtabpage.activity-stream.feeds.telemetry\", false);",
    "user_pref(\"browser.newtabpage.activity-stream.telemetry\", false);",
    "user_pref(\"browser.safebrowsing.malware.enabled\", false);",
    "user_pref(\"browser.safebrowsing.phishing.enabled\", false);",
    "user_pref(\"browser.safebrowsing.downloads.remote.enabled\", false);",
    "user_pref(\"browser.urlbar.suggest.searches\", false);",
    "user_pref(\"browser.search.suggest.enabled\", false);",
    "user_pref(\"browser.region.network.url\", \"\");",
    "user_pref(\"browser.region.update.enabled\", false);",
    "user_pref(\"extensions.pocket.enabled\", false);",
    "user_pref(\"identity.fxaccounts.enabled\", false);",
    "user_pref(\"breakpad.reportURL\", \"\");",
    "user_pref(\"browser.tabs.crashReporting.sendReport\", false);",
    "",
    "// --- Nada que sobreviva a la sesión ---",
    "user_pref(\"browser.privatebrowsing.autostart\", true);",
    "user_pref(\"browser.cache.disk.enable\", false);",
    "user_pref(\"browser.cache.offline.enable\", false);",
    "user_pref(\"browser.formfill.enable\", false);",
    "user_pref(\"browser.sessionstore.privacy_level\", 2);",
    "user_pref(\"extensions.getAddons.cache.enabled\", false);",
    "",
    "// --- Primer arranque silencioso (perfil nuevo en cada ejecución) ---",
    "user_pref(\"browser.shell.checkDefaultBrowser\", false);",
    "user_pref(\"browser.aboutwelcome.enabled\", false);",
    "user_pref(\"browser.startup.homepage_override.mstone\", \"ignore\");",
];

/// Full `user.js`. With `socks_port` all traffic (including DNS) goes to the
/// local Tor SOCKS; without it the system network is left untouched, which is
/// the right choice behind a VPN but not Tor.
#[must_use]
pub fn prefs(socks_port: Option<u16>) -> String {
    let mut out = String::new();
    for line in BASE_PREFS {
        out.push_str(line);
        out.push('\n');
    }
    if let Some(port) = socks_port {
        out.push_str("\n// --- Todo por el SOCKS local de Tor (DNS remoto, sin fugas) ---\n");
        out.push_str("user_pref(\"network.proxy.type\", 1);\n");
        out.push_str("user_pref(\"network.proxy.socks\", \"127.0.0.1\");\n");
        out.push_str("user_pref(\"network.proxy.socks_port\", ");
        out.push_str(&port.to_string());
        out.push_str(");\n");
        out.push_str("user_pref(\"network.proxy.socks_version\", 5);\n");
        out.push_str("user_pref(\"network.proxy.socks_remote_dns\", true);\n");
    } else {
        out.push_str("\n// Sin SOCKS de Tor: el navegador usa la red del sistema.\n");
        out.push_str("user_pref(\"network.proxy.type\", 0);\n");
    }
    out
}

/// Only `http(s)://` without spaces or control characters: the argument never
/// goes through a shell, but a value starting with `-` would be another
/// Firefox option, and a newline would corrupt the generated `user.js`.
#[must_use]
pub fn is_valid_url(url: &str) -> bool {
    !url.starts_with('-')
        && url.len() <= 2048
        && (url.starts_with("http://") || url.starts_with("https://"))
        && !url.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Is something listening on Tor's SOCKS port? A loopback connect needs no
/// privileges, sends no data and resolves nothing. A false positive only
/// means the browser points at a SOCKS that is not Tor: no leak, it just
/// will not navigate.
#[must_use]
pub fn tor_socks_port() -> Option<u16> {
    let addr = SocketAddr::from(([127, 0, 0, 1], SOCKS_PORT));
    TcpStream::connect_timeout(&addr, Duration::from_millis(300))
        .ok()
        .map(|_| SOCKS_PORT)
}

/// Where the ephemeral profile lives.
#[must_use]
pub fn profile_root() -> PathBuf {
    #[cfg(not(windows))]
    {
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_dir())
            .unwrap_or_else(|| PathBuf::from("/dev/shm"))
    }
    #[cfg(windows)]
    {
        std::env::temp_dir().join("anonify")
    }
}

/// Create a new profile under `root`, write `user.js` and return the path.
///
/// The directory is `0700` and `user.js` is `0600` on Unix. `owner` re-chowns
/// both (used when the Linux engine runs under `sudo` and the browser will
/// drop to the real user). The profile is deliberately **not** deleted later.
///
/// # Errors
///
/// Fails if the profile directory or `user.js` cannot be created or written,
/// or if the ownership cannot be handed to the target user.
pub fn create_profile(root: &Path, prefs: &str, owner: Option<(u32, u32)>) -> Result<PathBuf> {
    std::fs::create_dir_all(root)
        .with_context(|| format!("no se pudo crear {}", root.display()))?;
    let dir = root.join(format!("anonify-browser-{:016x}", rand::random::<u64>()));
    #[cfg(unix)]
    {
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&dir)
            .with_context(|| format!("no se pudo crear el perfil {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir(&dir)
        .with_context(|| format!("no se pudo crear el perfil {}", dir.display()))?;

    let user_js = dir.join("user.js");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts
        .open(&user_js)
        .with_context(|| format!("no se pudo escribir {}", user_js.display()))?;
    file.write_all(prefs.as_bytes())
        .with_context(|| format!("no se pudo escribir {}", user_js.display()))?;
    drop(file);

    #[cfg(unix)]
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::chown(&dir, Some(uid), Some(gid))
            .with_context(|| format!("no se pudo ceder {} al usuario", dir.display()))?;
        std::os::unix::fs::chown(&user_js, Some(uid), Some(gid))
            .with_context(|| format!("no se pudo ceder {} al usuario", user_js.display()))?;
    }
    #[cfg(not(unix))]
    let _ = owner;

    Ok(dir)
}

/// First supported browser found in `PATH`.
#[must_use]
pub fn find_browser() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for name in BROWSERS {
            for suffix in EXE_SUFFIXES {
                let candidate = dir.join(format!("{name}{suffix}"));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

/// Run the portable browser flow: validate the URL, create the profile, pin it
/// to Tor's SOCKS when available, start the browser and wait for it.
///
/// Returns the browser's exit code.
///
/// # Errors
///
/// Fails on an invalid URL, when no supported browser is installed, or when
/// the profile or the child process cannot be started.
pub fn run(url: Option<&str>, lang: Lang) -> Result<i32> {
    if let Some(u) = url {
        if !is_valid_url(u) {
            bail!(
                "{}",
                tr(
                    lang,
                    "invalid URL: only http:// or https://, without spaces or line breaks",
                    "URL inválida: solo http:// o https://, sin espacios ni saltos de línea"
                )
            );
        }
    }
    let prog = find_browser().context(tr(
        lang,
        "no supported browser found: install librewolf, firefox or firefox-esr",
        "no encontré un navegador compatible: instala librewolf, firefox o firefox-esr",
    ))?;

    let socks = tor_socks_port();
    let profile = create_profile(&profile_root(), &prefs(socks), None)?;
    eprintln!(
        "[+] {}: {}",
        tr(lang, "ephemeral profile", "perfil efímero"),
        profile.display()
    );
    match socks {
        Some(port) => eprintln!(
            "[+] {} {port} {}",
            tr(lang, "Tor SOCKS 127.0.0.1:", "proxy: Tor SOCKS 127.0.0.1:"),
            tr(
                lang,
                "(remote DNS; WebRTC off)",
                "(DNS remoto; WebRTC desactivado)"
            )
        ),
        None => eprintln!(
            "[!] {}",
            tr(
                lang,
                "nothing listening on 127.0.0.1:9050: the browser will use the system network as-is. Without tor/vpn you expose your real IP",
                "no hay SOCKS de Tor en 127.0.0.1:9050: el navegador usará la red del sistema tal cual. Sin tor/vpn verás tu IP real"
            )
        ),
    }
    eprintln!(
        "[*] {}",
        tr(
            lang,
            "the profile is not deleted on exit: it is not evidence cleaning, it is a fresh identity per run",
            "el perfil no se borra al salir: no es limpieza de rastros, es una identidad nueva por ejecución"
        )
    );

    let mut cmd = Command::new(&prog);
    cmd.arg("--no-remote")
        .arg("--new-instance")
        .arg("--profile")
        .arg(&profile);
    if let Some(u) = url {
        cmd.arg(u);
    }
    let status = cmd
        .status()
        .with_context(|| format!("no se pudo lanzar {}", prog.display()))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_tor_sends_dns_and_http_through_socks() {
        let p = prefs(Some(9050));
        for expected in [
            "user_pref(\"network.proxy.type\", 1);",
            "user_pref(\"network.proxy.socks_port\", 9050);",
            "user_pref(\"network.proxy.socks_remote_dns\", true);",
            "user_pref(\"media.peerconnection.enabled\", false);",
            "user_pref(\"privacy.resistFingerprinting\", true);",
            "user_pref(\"toolkit.telemetry.enabled\", false);",
            "user_pref(\"browser.privatebrowsing.autostart\", true);",
            "user_pref(\"network.trr.mode\", 5);",
        ] {
            assert!(p.contains(expected), "falta {expected}");
        }
        assert!(!p.contains("network.proxy.type\", 0"));
    }

    #[test]
    fn without_tor_uses_the_system_network() {
        let p = prefs(None);
        assert!(p.contains("user_pref(\"network.proxy.type\", 0);"));
        assert!(!p.contains("network.proxy.socks_port"));
    }

    #[test]
    fn every_line_is_a_comment_or_user_pref() {
        for p in [prefs(None), prefs(Some(9050))] {
            for line in p.lines().filter(|l| !l.is_empty()) {
                assert!(
                    line.starts_with("//")
                        || (line.starts_with("user_pref(\"") && line.ends_with(");")),
                    "línea inválida en user.js: {line}"
                );
            }
        }
    }

    #[test]
    fn urls_are_plain_http() {
        assert!(is_valid_url("https://example.org"));
        assert!(is_valid_url("http://127.0.0.1:8080/x?y=1"));
        assert!(!is_valid_url("-headless"));
        assert!(!is_valid_url("file:///etc/passwd"));
        assert!(!is_valid_url("about:config"));
        assert!(!is_valid_url(
            "https://example.org/\nuser_pref(\"x\", true);"
        ));
        assert!(!is_valid_url("https://example.org/a b"));
        assert!(!is_valid_url(&format!("https://{}.org", "a".repeat(2048))));
    }

    #[test]
    fn profile_gets_a_user_js_and_survives() {
        let root =
            std::env::temp_dir().join(format!("anonify-test-{:016x}", rand::random::<u64>()));
        let dir = create_profile(&root, &prefs(None), None).expect("perfil");
        let written = std::fs::read_to_string(dir.join("user.js")).expect("user.js");
        assert!(written.contains("privacy.resistFingerprinting"));
        assert!(dir.is_dir());
        // Test artifact of our own, not user data: safe to remove.
        std::fs::remove_dir_all(&root).expect("limpieza del temporal de prueba");
    }
}
