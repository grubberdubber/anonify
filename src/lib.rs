//! Portable, OS-independent parts of anonify.
//!
//! The Linux engine (nftables, sysctl, `NetworkManager`, Tor supervision) lives
//! in the `anonify` binary. Everything that can run on any OS lives here so
//! the cross-platform binaries do not depend on Linux-only code.

pub mod browser;
pub mod i18n;
