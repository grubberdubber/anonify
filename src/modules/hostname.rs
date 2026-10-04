use crate::{state::State, sys};
use anyhow::{bail, Result};
use rand::Rng;

fn set(name: &str) -> Result<()> {
    let c = std::ffi::CString::new(name)?;
    if unsafe { libc::sethostname(c.as_ptr(), name.len()) } != 0 {
        bail!("sethostname falló: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn enable(st: &mut State) -> Result<()> {
    let orig = sys::read_trim("/proc/sys/kernel/hostname")?;
    st.hostname.get_or_insert(orig);
    let new = format!("host-{:08x}", rand::thread_rng().gen::<u32>());
    set(&new)?;
    // Verificar que se mantiene: otro proceso podría revertirlo.
    std::thread::sleep(std::time::Duration::from_secs(3));
    let now = sys::read_trim("/proc/sys/kernel/hostname")?;
    if now != new {
        bail!("el hostname fue revertido por otro proceso (ahora es: {now})");
    }
    st.hostname_applied = Some(new.clone());
    println!("    hostname -> {new}");
    Ok(())
}

pub fn disable(st: &mut State) -> Result<()> {
    if let Some(h) = st.hostname.take() {
        st.hostname_applied = None;
        set(&h)?;
        println!("    hostname restaurado: {h}");
    }
    Ok(())
}
