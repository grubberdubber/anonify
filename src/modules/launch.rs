//! Lanzadores con enmascaramiento de entorno y descarte de privilegios.
//!
//! Lo que cambia respecto a ejecutar la app a mano:
//!
//! - **Entorno saneado.** La app recibe un entorno mínimo: no se propagan
//!   `HOSTNAME`, `SSH_AUTH_SOCK`/`SSH_CONNECTION`, `MAIL` ni las variables de
//!   locale del usuario. `TZ`, `LANG` y `LC_ALL` se fijan solo en el hijo
//!   (`--tz`/`--lang`), nunca en `/etc/localtime` ni en el reloj del sistema:
//!   los timestamps de logs y archivos no se tocan (ver `AGENTS.md`).
//! - **Descarte de privilegios.** Si anonify corre con `sudo`, la app se abre
//!   como el usuario original, no como root, y se descarta el *bounding set*
//!   de capacidades. `no_new_privs` impide que binarios setuid la escalen.
//!   Con `--isolate` los privilegios se bajan **antes** de `bwrap`, para que
//!   el `HOME`/`/tmp` del sandbox pertenezcan a ese usuario y la app pueda
//!   escribir su perfil; dentro del namespace de usuario no quedan caps.
//!
//! Límites: esto enmascara variables de entorno, no la identidad real (uid,
//! `HOME`, `~/.Xauthority` siguen siendo los del usuario) y, sin `--isolate`,
//! tampoco aísla la red ni el sistema de archivos (ver `bwrap.rs` para eso).
//! El hostname del
//! kernel lo sigue viendo cualquier proceso (y `bash` incluso lo copia a
//! `HOSTNAME` al arrancar): para ocultarlo hace falta el módulo `hostname`.
//! Tampoco se toca `/etc/localtime` ni el reloj del sistema.
use super::bwrap;
use crate::sys;
use anonify::browser as browser_lib;
use anyhow::{Context, Result, bail};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Opciones de endurecimiento del proceso hijo.
pub struct Sandbox {
    pub tz: String,
    pub lang: String,
    /// `false` = sin enmascarar entorno ni endurecer capacidades. Aun así,
    /// bajo `sudo` la app se abre como el usuario original, nunca como root.
    pub enabled: bool,
}

/// Aislamiento por espacios de nombres (`bubblewrap`). Todo es efímero: no
/// escribe configuración del sistema ni deja montajes al terminar.
pub struct Isolate {
    /// Mantener la red del host dentro del sandbox. Por defecto no hay red.
    pub net: bool,
    /// Hostname propio del namespace UTS (por defecto aleatorio).
    pub hostname: Option<String>,
    /// Directorio que será `HOME` en RW (por defecto, tmpfs vacío).
    pub home: Option<PathBuf>,
}

/// Variables que la app necesita para funcionar (gráficos, sesión, `PATH`).
/// Todo lo demás se descarta: es más fácil auditar una lista blanca que una
/// lista negra de variables.
const PRESERVE: &[&str] = &[
    "PATH",
    "TERM",
    "COLORTERM",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_DESKTOP",
    "XDG_DATA_DIRS",
    "DBUS_SESSION_BUS_ADDRESS",
    "TMPDIR",
];

/// Identidad del usuario al que se baja cuando anonify corre con `sudo`.
struct TargetUser {
    name: String,
    uid: u32,
    gid: u32,
    home: String,
}

/// Zona horaria: `UTC` o una ruta relativa real dentro de `zoneinfo`.
/// Se rechaza cualquier cosa con `..`, `/` inicial o caracteres raros para no
/// poder convertirse en una ruta arbitraria.
fn valid_tz(tz: &str) -> bool {
    if tz.is_empty() || tz.len() > 64 || tz.starts_with('/') {
        return false;
    }
    let well_formed = tz.split('/').all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+'))
    });
    well_formed && (tz == "UTC" || Path::new("/usr/share/zoneinfo").join(tz).is_file())
}

/// Locale POSIX: `C`, `C.UTF-8`, `es_CL.UTF-8`, `sr_RS.UTF-8@latin`.
fn valid_locale(locale: &str) -> bool {
    !locale.is_empty()
        && locale.len() <= 64
        && locale
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'@'))
}

fn parse_passwd(line: &str) -> Option<TargetUser> {
    let fields: Vec<&str> = line.trim().split(':').collect();
    if fields.len() < 7 {
        return None;
    }
    Some(TargetUser {
        name: fields[0].to_string(),
        uid: fields[2].parse().ok()?,
        gid: fields[3].parse().ok()?,
        home: fields[5].to_string(),
    })
}

/// Usuario real que invocó `sudo anonify ...`. `None` si ya somos ese usuario.
fn target_user() -> Result<Option<TargetUser>> {
    if !sys::is_root() {
        return Ok(None);
    }
    let Ok(name) = std::env::var("SUDO_USER") else {
        return Ok(None);
    };
    if name == "root" {
        return Ok(None);
    }
    let entry = sys::run("getent", &["passwd", &name])
        .with_context(|| format!("no se pudo resolver SUDO_USER={name}"))?;
    let user =
        parse_passwd(&entry).with_context(|| format!("entrada de passwd inválida para {name}"))?;
    Ok(Some(user))
}

/// Entorno del hijo. Función pura sobre un accesor para poder probarla sin
/// tocar el entorno real del test.
fn sanitized_env<F>(
    get: F,
    sandbox: &Sandbox,
    target: Option<&TargetUser>,
    ephemeral_caches: bool,
) -> Vec<(String, String)>
where
    F: Fn(&str) -> Option<String>,
{
    let mut env: Vec<(String, String)> = PRESERVE
        .iter()
        .filter(|key| !(target.is_some() && ***key == *"XDG_RUNTIME_DIR"))
        .filter_map(|key| get(key).map(|value| ((*key).to_string(), value)))
        .collect();

    // HOME y XDG_RUNTIME_DIR pertenecen al usuario destino, no a root.
    if let Some(user) = target {
        env.push(("HOME".into(), user.home.clone()));
        let runtime = format!("/run/user/{}", user.uid);
        if Path::new(&runtime).is_dir() {
            env.push(("XDG_RUNTIME_DIR".into(), runtime));
        }
    } else if let Some(home) = get("HOME") {
        env.push(("HOME".into(), home));
    }

    // Identidad de sesión enmascarada; el uid real sigue siendo visible.
    env.push(("USER".into(), "user".into()));
    env.push(("LOGNAME".into(), "user".into()));
    env.push(("TZ".into(), sandbox.tz.clone()));
    env.push(("LANG".into(), sandbox.lang.clone()));
    env.push(("LC_ALL".into(), sandbox.lang.clone()));

    // Dentro del sandbox `/tmp` es tmpfs, así que redirigir ahí las cachés
    // (fuentes, shaders, perfiles) evita que la app escriba rastros en el
    // disco del usuario. Nada de esto toca el sistema: muere con el proceso.
    if ephemeral_caches {
        env.push(("TMPDIR".into(), "/tmp".into()));
        env.push(("XDG_CACHE_HOME".into(), bwrap::CACHE_DIR.into()));
    }
    env
}

fn build(
    prog: &str,
    args: &[String],
    sandbox: &Sandbox,
    isolate: Option<&Isolate>,
) -> Result<Command> {
    if isolate.is_some() && !sandbox.enabled {
        bail!("`--isolate` necesita el entorno saneado: no lo combines con `--no-sandbox`");
    }
    if sandbox.enabled {
        if !valid_tz(&sandbox.tz) {
            bail!(
                "zona horaria inválida `{}`: usa `UTC` o un nombre de /usr/share/zoneinfo (p. ej. Europe/Madrid)",
                sandbox.tz
            );
        }
        if !valid_locale(&sandbox.lang) {
            bail!("locale inválido `{}` (p. ej. C.UTF-8)", sandbox.lang);
        }
    }

    let target = target_user()?;
    let uid = target.as_ref().map_or_else(sys::euid, |u| u.uid);
    // HOME que usará el sandbox cuando no hay `--home`: debe ser el del
    // usuario destino, no el de root, o la app escribiría en un tmpfs distinto
    // del que cree servir como HOME.
    let default_home = target.as_ref().map_or_else(
        || std::env::var("HOME").unwrap_or_else(|_| "/home/user".into()),
        |u| u.home.clone(),
    );

    if (target.is_some() || sandbox.enabled) && !sys::have("setpriv") {
        bail!(
            "falta `setpriv` (util-linux), necesario para bajar privilegios; \
             instálalo o usa `--no-sandbox` para lanzar la app tal cual"
        );
    }

    // argv del hijo **dentro** del sandbox. Sin usuario destino, `setpriv` va
    // aquí dentro: `no_new_privs` siempre, y el bounding set vacío solo cuando
    // somos root (requiere CAP_SETPCAP). Con `--isolate` bwrap además crea un
    // namespace de usuario sin capacidades.
    let mut child_cmd: Vec<String> = Vec::new();
    if sandbox.enabled && target.is_none() {
        child_cmd.extend(["setpriv", "--no-new-privs"].map(ToString::to_string));
        if sys::is_root() {
            child_cmd.extend(
                [
                    "--bounding-set=-all",
                    "--inh-caps=-all",
                    "--ambient-caps=-all",
                ]
                .map(ToString::to_string),
            );
        }
        child_cmd.push("--".to_string());
    }
    child_cmd.push(prog.to_string());
    child_cmd.extend(args.iter().cloned());

    let mut child_argv: Vec<String> = match isolate {
        Some(iso) => bwrap::command(
            iso.net,
            iso.hostname.as_deref(),
            iso.home.as_deref(),
            &default_home,
            uid,
            &child_cmd,
        )?,
        None => child_cmd,
    };

    // Si anonify corre con sudo, la app nunca debe abrirse como root: para eso
    // hace falta `setpriv` aunque el endurecimiento esté desactivado. Se aplica
    // **fuera** de bwrap para que el sandbox (HOME, /tmp) pertenezca al usuario.
    if let Some(user) = &target {
        let mut full = vec![
            "setpriv".to_string(),
            "--reuid".to_string(),
            user.uid.to_string(),
            "--regid".to_string(),
            user.gid.to_string(),
            "--init-groups".to_string(),
        ];
        if sandbox.enabled {
            // no_new_privs neutraliza binarios setuid incluso sin root.
            full.push("--no-new-privs".to_string());
        }
        full.push("--".to_string());
        full.extend(child_argv);
        child_argv = full;
    }

    let mut cmd = Command::new(&child_argv[0]);
    cmd.args(&child_argv[1..]);

    if sandbox.enabled {
        cmd.env_clear();
        for (key, value) in sanitized_env(
            |k| std::env::var(k).ok(),
            sandbox,
            target.as_ref(),
            isolate.is_some(),
        ) {
            cmd.env(key, value);
        }
    } else if let Some(user) = &target {
        // Sin sandbox el entorno se hereda, pero un proceso con el uid del
        // usuario y `HOME=/root` (o `USER=root`) rompe apps y filtra que se
        // lanzó desde sudo. Se corrige solo la identidad de sesión.
        cmd.env("HOME", &user.home);
        cmd.env("USER", &user.name);
        cmd.env("LOGNAME", &user.name);
        let runtime = format!("/run/user/{}", user.uid);
        if Path::new(&runtime).is_dir() {
            cmd.env("XDG_RUNTIME_DIR", runtime);
        }
    }

    // Con `--home`, HOME debe ser la misma ruta que bwrap monta en RW; si se
    // dejara el HOME del host, la app escribiría en un tmpfs que no ve.
    if let Some(home) = isolate.and_then(|iso| iso.home.as_deref()) {
        cmd.env("HOME", home);
    }
    Ok(cmd)
}

fn inherit(cmd: &mut Command) {
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
}

fn spawn_detached(
    prog: &str,
    args: &[String],
    sandbox: &Sandbox,
    isolate: Option<&Isolate>,
) -> Result<()> {
    let mut cmd = build(prog, args, sandbox, isolate)?;
    inherit(&mut cmd);
    cmd.spawn()
        .map_err(|e| anyhow::anyhow!("no se pudo lanzar {prog}: {e}"))?;
    println!("[+] lanzado: {prog}");
    Ok(())
}

fn exec_replace(
    prog: &str,
    args: &[String],
    sandbox: &Sandbox,
    isolate: Option<&Isolate>,
) -> Result<()> {
    let mut cmd = build(prog, args, sandbox, isolate)?;
    inherit(&mut cmd);
    // `exec` reemplaza este proceso: el hijo conserva el terminal y el código
    // de salida correcto. Solo retorna si falla.
    let e = cmd.exec();
    bail!("no se pudo lanzar {prog}: {e}")
}

pub fn spawn(
    prog: &str,
    args: &[String],
    sandbox: &Sandbox,
    isolate: Option<&Isolate>,
) -> Result<()> {
    exec_replace(prog, args, sandbox, isolate)
}

pub fn vbox(vm: Option<&str>, sandbox: &Sandbox, isolate: Option<&Isolate>) -> Result<()> {
    match vm {
        Some(v) => spawn_detached(
            "VBoxManage",
            &["startvm".into(), v.into(), "--type".into(), "gui".into()],
            sandbox,
            isolate,
        ),
        None => spawn_detached("VirtualBox", &[], sandbox, isolate),
    }
}

pub fn proton(sandbox: &Sandbox, isolate: Option<&Isolate>) -> Result<()> {
    for c in ["protonvpn-app", "proton-vpn-gtk-app", "protonvpn-gui"] {
        if sys::have(c) {
            return spawn_detached(c, &[], sandbox, isolate);
        }
    }
    bail!(
        "no encontré app de Proton VPN (AUR: proton-vpn-gtk-app). Alternativa: --vpn-conf con un .conf WireGuard"
    )
}

/// Navegador con perfil efímero y prefs de anonimato. No requiere root.
///
/// Reemplaza el proceso (como `launch exec`): así el sandbox `--isolate`
/// sigue vivo mientras el navegador lo esté (`bwrap --die-with-parent`) y el
/// perfil no queda huérfano. La lógica portable (prefs, creación del perfil,
/// detección del SOCKS) vive en `anonify::browser`, compartida con el binario
/// `anonify-browser` que corre en Windows y macOS.
pub fn browser(url: Option<&str>, sandbox: &Sandbox, isolate: Option<&Isolate>) -> Result<()> {
    if let Some(u) = url {
        if !browser_lib::is_valid_url(u) {
            bail!("URL inválida `{u}`: solo http:// o https://, sin espacios ni saltos de línea");
        }
    }
    if isolate.is_some_and(|iso| !iso.net) {
        bail!(
            "el navegador necesita red: usa `--isolate --allow-net` con tor o vpn activos, \
             o lánzalo sin `--isolate`"
        );
    }
    let prog = ["librewolf", "firefox", "firefox-esr"]
        .into_iter()
        .find(|p| sys::have(p))
        .context("no encontré un navegador compatible: instala librewolf, firefox o firefox-esr")?;

    let socks = browser_lib::tor_socks_port();
    let owner = target_user()?.map(|u| (u.uid, u.gid));
    let profile =
        browser_lib::create_profile(&browser_profile_root(), &browser_lib::prefs(socks), owner)?;
    let mut args = vec![
        "--no-remote".to_string(),
        "--new-instance".to_string(),
        "--profile".to_string(),
        profile.to_string_lossy().into_owned(),
    ];
    if let Some(u) = url {
        args.push(u.to_string());
    }

    eprintln!("[+] perfil efímero: {}", profile.display());
    match socks {
        Some(port) => {
            eprintln!("[+] proxy: Tor SOCKS 127.0.0.1:{port} (DNS remoto; WebRTC desactivado)");
        }
        None => eprintln!(
            "[!] no hay SOCKS de Tor en 127.0.0.1:9050: el navegador usará la red del \
             sistema tal cual. Sin tor/vpn verás tu IP real; activa `tor` o `vpn` primero"
        ),
    }
    eprintln!("[*] el perfil no se borra al salir: vive en tmpfs y desaparece al reiniciar");
    exec_replace(prog, &args, sandbox, isolate)
}

/// Perfil en el tmpfs del usuario destino (`/run/user/<uid>`), que `bwrap`
/// monta dentro del sandbox, o `/dev/shm`. Bajo `sudo` se usa el runtime del
/// usuario real, no el de root.
fn browser_profile_root() -> PathBuf {
    let uid = target_user()
        .ok()
        .flatten()
        .map_or_else(sys::euid, |u| u.uid);
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    if runtime.is_dir() {
        return runtime;
    }
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| PathBuf::from("/dev/shm"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn sandbox() -> Sandbox {
        Sandbox {
            tz: "UTC".into(),
            lang: "C.UTF-8".into(),
            enabled: true,
        }
    }

    fn env_of(pairs: &[(&str, &str)]) -> BTreeMap<String, Option<String>> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), Some((*v).to_string())))
            .collect()
    }

    #[test]
    fn isolate_requires_environment_sanitization() {
        let off = Sandbox {
            tz: "UTC".into(),
            lang: "C.UTF-8".into(),
            enabled: false,
        };
        let iso = Isolate {
            net: false,
            hostname: None,
            home: None,
        };
        let err = build("/usr/bin/true", &[], &off, Some(&iso)).expect_err("debe fallar");
        assert!(format!("{err:#}").contains("--no-sandbox"));
    }

    #[test]
    fn tz_must_be_a_real_zone() {
        assert!(valid_tz("UTC"));
        assert!(valid_tz("Europe/Madrid"));
        assert!(valid_tz("America/Argentina/Buenos_Aires"));
        assert!(!valid_tz("../etc/passwd"));
        assert!(!valid_tz("/etc/passwd"));
        assert!(!valid_tz("Europe/../.."));
        assert!(!valid_tz("Europe Madrid"));
        assert!(!valid_tz("Nowhere/Fake"));
        assert!(!valid_tz(""));
    }

    #[test]
    fn locale_must_be_posix_shaped() {
        assert!(valid_locale("C"));
        assert!(valid_locale("C.UTF-8"));
        assert!(valid_locale("es_CL.UTF-8"));
        assert!(valid_locale("sr_RS.UTF-8@latin"));
        assert!(!valid_locale("en US"));
        assert!(!valid_locale("en;touch /tmp/x"));
        assert!(!valid_locale(""));
    }

    #[test]
    fn parses_passwd_entry() {
        let u = parse_passwd("arch:x:1000:1000::/home/arch:/bin/bash").expect("entrada válida");
        assert_eq!(u.name, "arch");
        assert_eq!(u.uid, 1000);
        assert_eq!(u.gid, 1000);
        assert_eq!(u.home, "/home/arch");
        assert!(parse_passwd("arch:x:1000").is_none());
        assert!(parse_passwd("arch:x:no-uid:1000::/home/arch:/bin/bash").is_none());
    }

    #[test]
    fn env_is_whitelisted_and_masked() {
        let source = env_of(&[
            ("PATH", "/usr/bin"),
            ("DISPLAY", ":0"),
            ("HOME", "/home/arch"),
            ("HOSTNAME", "archlinux"),
            ("SSH_AUTH_SOCK", "/tmp/agent.sock"),
            ("SSH_CONNECTION", "10.0.0.1 22"),
            ("USER", "arch"),
            ("LOGNAME", "arch"),
            ("TZ", "Europe/Madrid"),
            ("LANG", "es_CL.UTF-8"),
            ("MAIL", "/var/mail/arch"),
        ]);
        let target = TargetUser {
            name: "arch".into(),
            uid: 1000,
            gid: 1000,
            home: "/home/arch".into(),
        };
        let env: BTreeMap<String, String> = sanitized_env(
            |k| source.get(k).cloned().flatten(),
            &sandbox(),
            Some(&target),
            false,
        )
        .into_iter()
        .collect();

        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(env.get("DISPLAY").map(String::as_str), Some(":0"));
        assert_eq!(env.get("HOME").map(String::as_str), Some("/home/arch"));
        assert_eq!(env.get("TZ").map(String::as_str), Some("UTC"));
        assert_eq!(env.get("LANG").map(String::as_str), Some("C.UTF-8"));
        assert_eq!(env.get("LC_ALL").map(String::as_str), Some("C.UTF-8"));
        assert_eq!(env.get("USER").map(String::as_str), Some("user"));
        assert_eq!(env.get("LOGNAME").map(String::as_str), Some("user"));

        for leaked in ["HOSTNAME", "SSH_AUTH_SOCK", "SSH_CONNECTION", "MAIL"] {
            assert!(!env.contains_key(leaked), "{leaked} no debe propagarse");
        }
    }

    #[test]
    fn home_comes_from_the_target_user_not_root() {
        let source = env_of(&[("HOME", "/root"), ("PATH", "/usr/bin")]);
        let target = TargetUser {
            name: "arch".into(),
            uid: 1000,
            gid: 1000,
            home: "/home/arch".into(),
        };
        let env: BTreeMap<String, String> = sanitized_env(
            |k| source.get(k).cloned().flatten(),
            &sandbox(),
            Some(&target),
            false,
        )
        .into_iter()
        .collect();
        assert_eq!(env.get("HOME").map(String::as_str), Some("/home/arch"));
    }

    #[test]
    fn isolated_launches_keep_caches_in_the_sandbox_tmpfs() {
        let isolated: BTreeMap<String, String> = sanitized_env(|_| None, &sandbox(), None, true)
            .into_iter()
            .collect();
        assert_eq!(isolated.get("TMPDIR").map(String::as_str), Some("/tmp"));
        assert_eq!(
            isolated.get("XDG_CACHE_HOME").map(String::as_str),
            Some(bwrap::CACHE_DIR)
        );

        let plain: BTreeMap<String, String> = sanitized_env(|_| None, &sandbox(), None, false)
            .into_iter()
            .collect();
        assert!(!plain.contains_key("XDG_CACHE_HOME"));
    }

    #[test]
    fn custom_tz_and_lang_reach_the_child() {
        let sb = Sandbox {
            tz: "Europe/Madrid".into(),
            lang: "en_US.UTF-8".into(),
            enabled: true,
        };
        let env: BTreeMap<String, String> = sanitized_env(|_| None, &sb, None, false)
            .into_iter()
            .collect();
        assert_eq!(env.get("TZ").map(String::as_str), Some("Europe/Madrid"));
        assert_eq!(env.get("LANG").map(String::as_str), Some("en_US.UTF-8"));
        assert_eq!(env.get("LC_ALL").map(String::as_str), Some("en_US.UTF-8"));
    }
}
