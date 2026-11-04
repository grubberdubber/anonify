//! Endurecimiento de memoria del propio proceso. Nada de esto modifica el
//! sistema ni escribe estado en disco: son propiedades de la ejecución actual.
//!
//! - `lock_process`: `mlockall(MCL_CURRENT)` best-effort para que las páginas
//!   ya mapeadas no acaben en swap. Deliberadamente **no** usa `MCL_FUTURE`:
//!   con un `RLIMIT_MEMLOCK` pequeño, cualquier asignación posterior (o la
//!   creación del hilo del watchdog) fallaría y rompería la red de seguridad.
//! - [`SecretBuf`]: buffer que se borra con ceros al liberarse. Se usa para
//!   material sensible que solo debe vivir en RAM, como la clave privada del
//!   archivo `.conf` de `WireGuard`.
//! - `swap_warnings`: auditoría de solo lectura de `/proc/swaps`. Si hay swap
//!   en claro, las páginas de tmpfs (incluido `/run/anonify` con los valores
//!   originales de MAC/hostname) pueden acabar escritas en disco.
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

/// Bloquea las páginas actuales del proceso en RAM. Best-effort: si el
/// sistema no lo permite (por ejemplo `RLIMIT_MEMLOCK` agotado), el llamante
/// debe avisar y continuar; no es un cambio del sistema ni algo irreversible.
pub fn lock_process() -> Result<()> {
    // SAFETY: `mlockall` solo recibe una máscara de flags `MCL_*`; no toma
    // punteros ni referencias a memoria de Rust.
    if unsafe { libc::mlockall(libc::MCL_CURRENT) } != 0 {
        return Err(std::io::Error::last_os_error()).context("mlockall(MCL_CURRENT)");
    }
    Ok(())
}

/// Texto sensible que se zeroiza al liberarse. No implementa `Debug` ni
/// `Display` a propósito, para que no pueda acabar impreso por accidente.
pub struct SecretBuf(Vec<u8>);

impl SecretBuf {
    /// Lee un archivo que contiene material sensible (claves privadas) e
    /// intenta además fijarlo en RAM. El `mlock` es best-effort: el borrado
    /// con ceros al liberar es lo que realmente protege el contenido.
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("leyendo archivo sensible {}", path.display()))?;
        let this = Self(bytes);
        this.lock();
        Ok(this)
    }

    /// Intenta fijar el buffer en RAM; si falla no es un error, porque el
    /// contenido se zeroiza igualmente al liberarse.
    fn lock(&self) {
        if self.0.is_empty() {
            return;
        }
        // SAFETY: el puntero y la longitud describen el buffer `self.0`, que
        // no se reasigna ni se mueve mientras vive `self` (nunca se muta).
        unsafe {
            libc::mlock(
                self.0.as_ptr().cast::<libc::c_void>(),
                self.0.len() as libc::size_t,
            );
        }
    }

    /// Vista como `str`. Falla si el archivo no es UTF-8 válido.
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.0).context("el archivo sensible no es UTF-8 válido")
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Qué garantía ofrece un dispositivo de swap sobre el contenido que recibe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapKind {
    /// zram: swap comprimido en RAM, nunca toca el disco.
    Memory,
    /// Dispositivo de bloques dm-crypt: lo que se escribe queda cifrado.
    Encrypted,
    /// Todo lo demás, o un cifrado que no se pudo verificar.
    Plain,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Swap {
    pub path: String,
    pub kind: SwapKind,
}

/// Clasifica una entrada de `/proc/swaps`.
///
/// `dm_uuid` es el contenido de `/sys/block/<dev>/dm/uuid` cuando el swap
/// vive en un dispositivo device-mapper; dm-crypt lo publica con prefijo
/// `CRYPT-`. Sin esa prueba no se asume cifrado.
fn kind_of(path: &str, dm_uuid: Option<&str>) -> SwapKind {
    let name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if name.starts_with("zram") {
        return SwapKind::Memory;
    }
    if dm_uuid.is_some_and(|u| u.starts_with("CRYPT-")) {
        return SwapKind::Encrypted;
    }
    SwapKind::Plain
}

/// Rutas de swap listadas en `/proc/swaps`. La cabecera se descarta y el
/// kernel escapa los espacios de las rutas, así que separar por espacios es
/// seguro aquí.
fn parse_swaps(text: &str) -> Vec<String> {
    text.lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .map(ToString::to_string)
        .collect()
}

fn dm_uuid(path: &str) -> Option<String> {
    let resolved = fs::canonicalize(path).ok()?;
    let name = resolved.file_name()?.to_string_lossy().to_string();
    if !name.starts_with("dm-") {
        return None;
    }
    fs::read_to_string(format!("/sys/block/{name}/dm/uuid"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Swap activo ahora mismo. `/proc/swaps` solo lista dispositivos activos.
pub fn swaps() -> Vec<Swap> {
    let Ok(text) = fs::read_to_string("/proc/swaps") else {
        return vec![];
    };
    parse_swaps(&text)
        .into_iter()
        .map(|path| {
            let kind = kind_of(&path, dm_uuid(&path).as_deref());
            Swap { path, kind }
        })
        .collect()
}

/// Avisos de privacidad sobre el swap activo, para `anonify check`.
pub fn swap_warnings() -> Vec<String> {
    warnings_for(swaps())
}

fn warnings_for(swaps: Vec<Swap>) -> Vec<String> {
    swaps
        .into_iter()
        .filter(|s| s.kind == SwapKind::Plain)
        .map(|s| {
            format!(
                "swap is active on {} without verified encryption; tmpfs pages (including /run/anonify) and this process can reach disk in cleartext",
                s.path
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_swaps_without_header() {
        let text = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n\
                    /dev/zram0                              partition\t8388604\t\t0\t\t100\n\
                    /dev/nvme0n1p3                          partition\t8388604\t\t0\t\t-2\n";
        assert_eq!(parse_swaps(text), vec!["/dev/zram0", "/dev/nvme0n1p3"]);
    }

    #[test]
    fn parses_empty_swaps() {
        assert!(parse_swaps("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n").is_empty());
    }

    #[test]
    fn zram_never_touches_disk() {
        assert_eq!(kind_of("/dev/zram0", None), SwapKind::Memory);
        // Un dm-crypt montado sobre zram tampoco cambia la clasificación.
        assert_eq!(kind_of("/dev/zram0", Some("CRYPT-x")), SwapKind::Memory);
    }

    #[test]
    fn only_verified_dm_crypt_counts_as_encrypted() {
        assert_eq!(
            kind_of("/dev/dm-1", Some("CRYPT-1234")),
            SwapKind::Encrypted
        );
        // Un dm lineal (LVM/LUKS sin CRYPT-) no se asume cifrado.
        assert_eq!(kind_of("/dev/dm-1", Some("LVM-abc")), SwapKind::Plain);
        assert_eq!(kind_of("/dev/dm-1", None), SwapKind::Plain);
        assert_eq!(kind_of("/swapfile", None), SwapKind::Plain);
        // El nombre "cryptswap" no es prueba de cifrado: exige el UUID real.
        assert_eq!(kind_of("/dev/mapper/cryptswap", None), SwapKind::Plain);
    }

    fn entry(path: &str, kind: SwapKind) -> Swap {
        Swap {
            path: path.to_string(),
            kind,
        }
    }

    #[test]
    fn only_plain_swap_produces_a_warning() {
        let warnings = warnings_for(vec![
            entry("/dev/zram0", SwapKind::Memory),
            entry("/dev/dm-1", SwapKind::Encrypted),
        ]);
        assert!(warnings.is_empty());

        let warnings = warnings_for(vec![
            entry("/dev/nvme0n1p3", SwapKind::Plain),
            entry("/dev/zram0", SwapKind::Memory),
        ]);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("/dev/nvme0n1p3"));
        assert!(warnings[0].contains("/run/anonify"));
    }

    #[test]
    fn secret_buffer_zeroizes_on_drop() {
        let dir = std::env::temp_dir().join(format!(
            "anonify-mem-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("wg.conf");
        fs::write(&path, "[Interface]\nPrivateKey = secret\n").expect("write");
        {
            let buf = SecretBuf::read(&path).expect("leer");
            assert!(buf.as_str().expect("utf8").contains("PrivateKey"));
        }
        let _ = fs::remove_dir_all(dir);
    }
}
