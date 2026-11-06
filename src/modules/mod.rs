//! Registro de módulos de anonimato.
//!
//! Por política de proyecto no existen módulos de borrado/alteración de logs,
//! auditoría, timestamps o evidencia. La lista de módulos es deliberadamente
//! de privacidad de red y hardening reversible; ver `AGENTS.md`.
use crate::i18n::{Lang, tr};
use crate::state::State;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

pub mod bwrap;
pub mod check;
pub mod dns;
pub mod doctor;
pub mod hostname;
pub mod ipv6;
pub mod killswitch;
pub mod lan;
pub mod launch;
pub mod mac;
pub mod sysctl;
pub mod tor;
pub mod vpn;

/// Declaration order = activation order (reversed on deactivation).
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[clap(rename_all = "kebab-case")]
pub enum Module {
    Mac,
    Sysctl,
    Ipv6,
    Hostname,
    Vpn,
    Tor,
    Dns,
    Killswitch,
    Lan,
}

impl Module {
    /// Todos los módulos, en orden de activación.
    pub const ALL: &'static [Module] = &[
        Module::Mac,
        Module::Sysctl,
        Module::Ipv6,
        Module::Hostname,
        Module::Vpn,
        Module::Tor,
        Module::Dns,
        Module::Killswitch,
        Module::Lan,
    ];

    /// Modules enabled by `--all` (vpn and killswitch are explicit opt-in).
    /// Tor goes before DNS so the DNS module can require an active Tor stack.
    pub const DEFAULT_SET: &'static [Module] = &[
        Module::Mac,
        Module::Hostname,
        Module::Sysctl,
        Module::Ipv6,
        Module::Tor,
        Module::Dns,
    ];

    /// Checks against the REAL system state (not just the saved state) that
    /// the module is still applied. Shared by `status`, `check`, `watch` and
    /// the post-enable settle check.
    pub fn holds(self, st: &State) -> bool {
        match self {
            Module::Mac => mac::holds(st),
            Module::Hostname => hostname::holds(st),
            Module::Sysctl => sysctl::holds(sysctl::HARDEN),
            Module::Ipv6 => ipv6::holds(),
            Module::Vpn => vpn::holds(st),
            Module::Dns => dns::holds(st),
            Module::Tor => tor::alive(),
            Module::Killswitch => killswitch::holds(st),
            Module::Lan => lan::holds(),
        }
    }

    pub fn desc(self, lang: Lang) -> &'static str {
        match self {
            Module::Mac => tr(
                lang,
                "random MAC on physical interfaces",
                "MAC aleatoria en interfaces físicas",
            ),
            Module::Hostname => tr(
                lang,
                "random ephemeral hostname",
                "hostname transitorio aleatorio",
            ),
            Module::Sysctl => tr(
                lang,
                "kernel/network hardening (sysctl)",
                "hardening de kernel/red (sysctl)",
            ),
            Module::Ipv6 => tr(
                lang,
                "disables IPv6 (prevents leaks)",
                "desactiva IPv6 (evita fugas)",
            ),
            Module::Vpn => tr(
                lang,
                "WireGuard / Proton via wg-quick",
                "WireGuard / Proton vía wg-quick",
            ),
            Module::Tor => tr(
                lang,
                "transparent Tor proxy + anti-leak firewall",
                "proxy transparente Tor + firewall anti-fuga",
            ),
            Module::Dns => tr(
                lang,
                "temporary resolv.conf (requires Tor)",
                "resolv.conf temporal (requiere Tor)",
            ),
            Module::Killswitch => tr(
                lang,
                "kill switch: VPN/Tor tunnel only",
                "kill switch: solo túnel VPN / Tor",
            ),
            Module::Lan => tr(
                lang,
                "silences mDNS/LLMNR/SSDP/NetBIOS discovery on the LAN",
                "silencia mDNS/LLMNR/SSDP/NetBIOS en la LAN",
            ),
        }
    }
}
