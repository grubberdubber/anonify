//! Utilidades de bajo nivel: ejecutar comandos, privilegios, PATH.
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};

pub fn run(prog: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(prog)
        .args(args)
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
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("no se pudo ejecutar `{prog}`"))?;
    child.stdin.take().unwrap().write_all(input.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("`{prog}` falló: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

pub fn have(prog: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(prog).is_file()))
        .unwrap_or(false)
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn read_trim(path: &str) -> Result<String> {
    Ok(std::fs::read_to_string(path)
        .with_context(|| format!("leyendo {path}"))?
        .trim()
        .to_string())
}
