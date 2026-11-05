//! Utilidades de bajo nivel: ejecutar comandos, privilegios y PATH.
//!
//! Todos los subprocesos se ejecutan con `LC_ALL=C`/`LANG=C` para que la
//! salida de herramientas como `nmcli`, `ip` o `tor` sea estable y se pueda
//! parsear sin depender del idioma del sistema.
use anyhow::{Context, Result, bail};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

pub fn run(prog: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(prog)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("LANGUAGE", "C")
        .output()
        .with_context(|| format!("no se pudo ejecutar `{prog}`"))?;
    if !out.status.success() {
        bail!(
            "`{prog} {}` falló: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn run_stdin(prog: &str, args: &[&str], input: &str) -> Result<()> {
    let mut child = Command::new(prog)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("LANGUAGE", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("no se pudo ejecutar `{prog}`"))?;
    let mut stdin = child.stdin.take().context("el subproceso no abrió stdin")?;
    stdin.write_all(input.as_bytes())?;
    drop(stdin);
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "`{prog}` falló: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Comprueba que `prog` existe en `PATH` y es ejecutable por el usuario actual.
pub fn have(prog: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| {
            let path = d.join(prog);
            path.metadata()
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
}

pub fn euid() -> u32 {
    // SAFETY: `geteuid` no toma punteros y no puede fallar.
    unsafe { libc::geteuid() }
}

pub fn is_root() -> bool {
    euid() == 0
}

pub fn read_trim(path: &str) -> Result<String> {
    Ok(std::fs::read_to_string(path)
        .with_context(|| format!("leyendo {path}"))?
        .trim()
        .to_string())
}

/// True only when the test process runs in a network namespace different from
/// PID 1's. Destructive nftables tests use this as a hard guard so a bare
/// `cargo test` on a real host can never install a `policy drop` table.
#[cfg(test)]
pub fn in_isolated_netns() -> bool {
    use std::os::unix::fs::MetadataExt;
    let current = std::fs::metadata("/proc/self/ns/net").ok().map(|m| m.ino());
    let init = std::fs::metadata("/proc/1/ns/net").ok().map(|m| m.ino());
    matches!((current, init), (Some(a), Some(b)) if a != b)
}
