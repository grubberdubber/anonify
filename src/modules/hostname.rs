//! Hostname transitorio. El original se guarda en `State` y solo se descarta
//! cuando la restauración se ha verificado; si `sethostname` falla, el estado
//! se conserva para reintentar.
use crate::{state::State, sys};
use anyhow::{bail, Result};
use rand::Rng;

fn set(name: &str) -> Result<()> {
    let c = std::ffi::CString::new(name)?;
    // SAFETY: `c` is a valid NUL-terminated string and `name.len()` is its
    // byte length without the terminator, which is what sethostname expects.
    if unsafe { libc::sethostname(c.as_ptr(), name.len()) } != 0 {
        bail!("sethostname falló: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn current() -> Result<String> {
    sys::read_trim("/proc/sys/kernel/hostname")
}

pub fn enable(st: &mut State) -> Result<()> {
    let orig = current()?;
    st.hostname.get_or_insert(orig);
    let new = format!("host-{:08x}", rand::thread_rng().gen::<u32>());
    set(&new)?;
    // Verificar que se mantiene: otro proceso podría revertirlo.
    std::thread::sleep(std::time::Duration::from_secs(3));
    let now = current()?;
    if now != new {
        bail!("el hostname fue revertido por otro proceso (ahora es: {now})");
    }
    st.hostname_applied = Some(new.clone());
    println!("    hostname -> {new}");
    Ok(())
}

pub fn disable(st: &mut State) -> Result<()> {
    let Some(orig) = st.hostname.clone() else {
        return Ok(());
    };
    set(&orig)?;
    let now = current()?;
    if now != orig {
        bail!("el hostname no quedó restaurado (ahora es: {now})");
    }
    // Solo descartar el original después de verificarlo.
    st.hostname = None;
    st.hostname_applied = None;
    println!("    hostname restaurado: {orig}");
    Ok(())
}

pub fn holds(st: &State) -> bool {
    st.hostname_applied
        .as_deref()
        .is_some_and(|h| current().is_ok_and(|c| c == h))
}
