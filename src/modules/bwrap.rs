//! Construcción del sandbox `bubblewrap` para `anonify launch --isolate`.
//!
//! Qué aísla y cómo se revierte: nada de esto toca el sistema. Son espacios
//! de nombres efímeros que mueren con el proceso (`--die-with-parent`); al
//! salir de la app no queda estado, montaje ni regla alguna.
//!
//! - `/usr` y `/etc` en solo lectura; `/bin`, `/sbin`, `/lib`, `/lib64` como
//!   symlinks a `/usr` (compatible con sistemas `usrmerge`).
//! - `/tmp` y `/dev/shm` en tmpfs propios: cachés, sockets y archivos
//!   temporales desaparecen al cerrar.
//! - `HOME` en tmpfs vacío por defecto (o el directorio que pida `--home`),
//!   y `XDG_CACHE_HOME` apuntando a [`CACHE_DIR`] dentro de ese tmpfs: las
//!   cachés de fuentes, shaders o perfiles no tocan el disco.
//! - `--unshare-all`: red, PID, IPC, UTS y cgroup propios. Sin `--allow-net`
//!   la app **no tiene red en absoluto** (solo loopback): no hay fugas de DNS,
//!   IP ni IPv6 posibles por esa vía.
//! - Hostname propio en el namespace UTS, sin modificar el del sistema.
//!
//! Quién es dueño de los directorios: `bwrap` crea los nodos del sandbox con
//! el uid con el que corre. Por eso `launch` baja privilegios con `setpriv`
//! **antes** de invocar `bwrap` cuando hay un usuario destino: si `bwrap`
//! corriera como root, el `HOME`/`/tmp` del sandbox quedarían root-owned y la
//! aplicación, ya sin privilegios, no podría escribir su perfil.
use crate::sys;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// Directorio de cachés de la aplicación dentro del sandbox (tmpfs).
pub const CACHE_DIR: &str = "/tmp/.cache";

pub struct Options {
    /// Mantener la red del host dentro del sandbox (`--allow-net`).
    pub net: bool,
    /// Hostname visible dentro del namespace UTS.
    pub hostname: String,
    /// Ruta que será `HOME` dentro del sandbox.
    pub home: String,
    /// `true` = `--home` explícito: se monta en RW; `false` = tmpfs vacío.
    pub bind_home: bool,
    /// UID del usuario destino, para exponer `/run/user/<uid>`.
    pub uid: u32,
}

/// Hostnames de un solo label; se rechaza cualquier cosa que no sea
/// alfanumérica, `-` o `.` para no inyectar argumentos ni rutas.
fn valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
}

/// Devuelve la ruta absoluta real del ejecutable. El sandbox solo contiene
/// `/usr` (y los symlinks de `/bin`), así que un binario de `$HOME` o `/opt`
/// no existiría dentro: mejor fallar aquí que con un `exec` opaco.
fn resolve_prog(prog: &str) -> Result<PathBuf> {
    let candidate = if prog.contains('/') {
        PathBuf::from(prog)
    } else {
        let path = std::env::var_os("PATH").context("PATH no está definido")?;
        std::env::split_paths(&path)
            .map(|dir| dir.join(prog))
            .find(|p| {
                p.metadata().is_ok_and(|m| {
                    m.is_file()
                        && std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o111 != 0
                })
            })
            .with_context(|| format!("`{prog}` no está en PATH"))?
    };
    let resolved = std::fs::canonicalize(&candidate)
        .with_context(|| format!("no se pudo resolver `{}`", candidate.display()))?;
    if !resolved.is_file() {
        bail!("`{}` no es un archivo ejecutable", resolved.display());
    }
    let inside = ["/usr", "/bin", "/sbin", "/lib", "/lib64"]
        .iter()
        .any(|root| resolved.starts_with(root));
    if !inside {
        bail!(
            "`{}` vive fuera de /usr y no existiría dentro del sandbox; \
             usa `--no-sandbox`, instálalo en /usr, o lanza el comando con --home",
            resolved.display()
        );
    }
    Ok(resolved)
}

fn random_hostname() -> String {
    format!("host-{:08x}", rand::random::<u32>())
}

/// Argumentos completos de `bwrap`, terminando en `-- <prog> [args...]`.
pub fn args(
    opts: &Options,
    prog: &str,
    prog_args: &[String],
    xauthority: Option<&str>,
) -> Result<Vec<String>> {
    if !valid_hostname(&opts.hostname) {
        bail!(
            "hostname inválido `{}`: solo letras, dígitos, `-` y `.` (máx. 63)",
            opts.hostname
        );
    }
    let runtime = format!("/run/user/{}", opts.uid);
    let mut argv: Vec<String> = vec![
        "bwrap".into(),
        "--unshare-all".into(),
        "--die-with-parent".into(),
        "--new-session".into(),
        "--ro-bind".into(),
        "/usr".into(),
        "/usr".into(),
        "--symlink".into(),
        "usr/bin".into(),
        "/bin".into(),
        "--symlink".into(),
        "usr/sbin".into(),
        "/sbin".into(),
        "--symlink".into(),
        "usr/lib".into(),
        "/lib".into(),
        "--symlink".into(),
        "usr/lib64".into(),
        "/lib64".into(),
        "--ro-bind".into(),
        "/etc".into(),
        "/etc".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        // tmpfs se monta con permisos de root si bwrap corre como root; 1777
        // deja que la app (ya sin privilegios) escriba temporales.
        "--chmod".into(),
        "1777".into(),
        "/tmp".into(),
        "--dir".into(),
        CACHE_DIR.into(),
        "--chmod".into(),
        "0700".into(),
        CACHE_DIR.into(),
        "--tmpfs".into(),
        "/dev/shm".into(),
        "--chmod".into(),
        "1777".into(),
        "/dev/shm".into(),
    ];
    // GPU y sesión gráfica: sin esto las apps GUI no arrancan o van a software.
    argv.extend(["--ro-bind-try".into(), "/dev/dri".into(), "/dev/dri".into()]);
    argv.extend(["--bind-try".into(), runtime.clone(), runtime]);
    argv.extend([
        "--ro-bind-try".into(),
        "/tmp/.X11-unix".into(),
        "/tmp/.X11-unix".into(),
    ]);
    if let Some(xauth) = xauthority {
        argv.extend(["--ro-bind-try".into(), xauth.to_string(), xauth.to_string()]);
    }

    if opts.bind_home {
        argv.extend(["--bind".into(), opts.home.clone(), opts.home.clone()]);
    } else {
        argv.extend(["--tmpfs".into(), opts.home.clone()]);
    }

    argv.extend([
        "--chdir".into(),
        "/tmp".into(),
        "--hostname".into(),
        opts.hostname.clone(),
    ]);
    if opts.net {
        // Cancela el `--unshare-net` implícito de `--unshare-all`.
        argv.push("--share-net".into());
    }
    argv.push("--".into());
    argv.push(prog.to_string());
    argv.extend(prog_args.iter().cloned());
    Ok(argv)
}

/// Comando listo para `exec`. `bwrap` es fail-closed: si falta, no se lanza
/// nada en claro. `cmd[0]` es el ejecutable y el resto sus argumentos.
pub fn command(
    net: bool,
    hostname: Option<&str>,
    home: Option<&Path>,
    default_home: &str,
    uid: u32,
    cmd: &[String],
) -> Result<Vec<String>> {
    if !sys::have("bwrap") {
        bail!("falta bubblewrap: sudo pacman -S bubblewrap");
    }
    let Some(prog) = cmd.first() else {
        bail!("no hay ningún comando que lanzar en el sandbox");
    };
    let resolved = resolve_prog(prog)?;
    let (home, bind_home) = if let Some(dir) = home {
        let dir = std::fs::canonicalize(dir)
            .with_context(|| format!("no se pudo abrir {}", dir.display()))?;
        if !dir.is_dir() {
            bail!("--home {} no es un directorio", dir.display());
        }
        (dir, true)
    } else {
        (PathBuf::from(default_home), false)
    };
    let opts = Options {
        net,
        hostname: hostname.map_or_else(random_hostname, ToString::to_string),
        home: home.to_string_lossy().to_string(),
        bind_home,
        uid,
    };
    args(
        &opts,
        &resolved.to_string_lossy(),
        &cmd[1..],
        std::env::var("XAUTHORITY").ok().as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> Options {
        Options {
            net: false,
            hostname: "host-test".into(),
            home: "/home/arch".into(),
            bind_home: false,
            uid: 1000,
        }
    }

    #[test]
    fn rejects_hostnames_that_could_inject_arguments() {
        assert!(valid_hostname("host-1234abcd"));
        assert!(valid_hostname("anonify.local"));
        assert!(!valid_hostname("host --share-net"));
        assert!(!valid_hostname("host/../../etc"));
        assert!(!valid_hostname("-leading"));
        assert!(!valid_hostname("trailing-"));
        assert!(!valid_hostname(&"a".repeat(64)));
        assert!(!valid_hostname(""));
    }

    #[test]
    fn network_is_off_by_default() {
        let argv = args(&opts(), "/usr/bin/sh", &[], None).expect("args");
        assert!(argv.contains(&"--unshare-all".to_string()));
        assert!(!argv.contains(&"--share-net".to_string()));
        let sep = argv.iter().position(|a| a == "--").expect("separador");
        assert_eq!(argv.get(sep + 1).map(String::as_str), Some("/usr/bin/sh"));
    }

    #[test]
    fn child_arguments_follow_the_program() {
        let argv = args(
            &opts(),
            "/usr/bin/firefox",
            &["--new-instance".to_string()],
            None,
        )
        .expect("args");
        let sep = argv.iter().position(|a| a == "--").expect("separador");
        assert_eq!(
            argv.get(sep + 1..sep + 3),
            Some(["/usr/bin/firefox".to_string(), "--new-instance".to_string()].as_slice())
        );
    }

    #[test]
    fn allow_net_shares_the_host_network() {
        let o = Options {
            net: true,
            ..opts()
        };
        let argv = args(&o, "/usr/bin/sh", &[], None).expect("args");
        assert!(argv.contains(&"--share-net".to_string()));
    }

    #[test]
    fn home_is_tmpfs_unless_explicitly_bound() {
        let argv = args(&opts(), "/usr/bin/sh", &[], None).expect("args");
        let pos = argv.iter().position(|a| a == "/home/arch").expect("home");
        assert_eq!(argv.get(pos - 1).map(String::as_str), Some("--tmpfs"));

        let o = Options {
            bind_home: true,
            ..opts()
        };
        let argv = args(&o, "/usr/bin/sh", &[], None).expect("args");
        let pos = argv.iter().position(|a| a == "/home/arch").expect("home");
        assert_eq!(argv.get(pos - 1).map(String::as_str), Some("--bind"));
    }

    #[test]
    fn system_dirs_are_read_only() {
        let argv = args(&opts(), "/usr/bin/sh", &[], None).expect("args");
        let usr = argv
            .windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1] == "/usr" && w[2] == "/usr");
        assert!(usr, "/usr debe montarse en solo lectura");
        assert!(!argv.windows(3).any(|w| w[0] == "--bind" && w[1] == "/usr"));
    }

    #[test]
    fn tmp_and_cache_are_writable_inside_the_sandbox() {
        let argv = args(&opts(), "/usr/bin/sh", &[], None).expect("args");
        let tmp_chmod = argv
            .windows(3)
            .any(|w| w[0] == "--chmod" && w[1] == "1777" && w[2] == "/tmp");
        assert!(tmp_chmod, "/tmp debe quedar escribible por la app");
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--dir" && w[1] == CACHE_DIR)
        );
    }

    #[test]
    fn resolves_programs_from_path() {
        let path = resolve_prog("sh").expect("sh debe resolver");
        assert!(path.starts_with("/usr"), "{}", path.display());
        assert!(path.is_file());
    }

    #[test]
    fn refuses_programs_outside_usr() {
        let dir = std::env::temp_dir().join(format!(
            "anonify-bwrap-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let exe = dir.join("tool");
        std::fs::write(&exe, "#!/bin/sh\n").expect("write");
        std::fs::set_permissions(&exe, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("chmod");
        let err = resolve_prog(exe.to_str().expect("utf8")).expect_err("debe rechazar");
        assert!(format!("{err:#}").contains("fuera de /usr"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
