use crate::i18n::{tr, Lang};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

pub mod dns;
pub mod hostname;
pub mod ipv6;
pub mod killswitch;
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
    Dns,
    Tor,
    Killswitch,
}

impl Module {
    /// Modules enabled by `--all` (vpn and killswitch are explicit opt-in).
    pub const DEFAULT_SET: &'static [Module] = &[
        Module::Mac,
        Module::Hostname,
        Module::Sysctl,
        Module::Ipv6,
        Module::Dns,
        Module::Tor,
    ];

    pub fn desc(&self, lang: Lang) -> &'static str {
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
            Module::Dns => tr(
                lang,
                "temporary resolv.conf (bind mount)",
                "resolv.conf temporal (bind mount)",
            ),
            Module::Tor => tr(
                lang,
                "transparent Tor proxy + anti-leak firewall",
                "proxy transparente Tor + firewall anti-fuga",
            ),
            Module::Killswitch => tr(
                lang,
                "kill switch: VPN/Tor tunnel only",
                "kill switch: solo túnel VPN / Tor",
            ),
        }
    }
}
