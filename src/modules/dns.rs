use crate::{state::{State, DIR}, sys};
use anyhow::Result;
use std::fs;

const TARGET: &str = "/etc/resolv.conf";

pub fn enable(st: &mut State) -> Result<()> {
    if st.dns_bound {
        return Ok(());
    }
    fs::create_dir_all(DIR)?;
    let tmp = format!("{DIR}/resolv.conf");
    // Con Tor activo, el firewall redirige todo UDP/53 al DNSPort de Tor.
    fs::write(&tmp, "# anonify (temporal)\nnameserver 127.0.0.1\noptions edns0 trust-ad\n")?;
    sys::run("mount", &["--bind", &tmp, TARGET])?;
    st.dns_bound = true;
    Ok(())
}

pub fn disable(st: &mut State) -> Result<()> {
    if st.dns_bound {
        sys::run("umount", &[TARGET])?;
        st.dns_bound = false;
    }
    Ok(())
}
