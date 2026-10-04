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

/// El orden de declaración = orden de activación (al desactivar se invierte).
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
    /// Módulos que activa `--all` (vpn y killswitch son opt-in explícitos).
    pub const DEFAULT_SET: &'static [Module] = &[
        Module::Mac,
        Module::Hostname,
        Module::Sysctl,
        Module::Ipv6,
        Module::Dns,
        Module::Tor,
    ];

    pub fn desc(&self) -> &'static str {
        match self {
            Module::Mac => "MAC aleatoria en interfaces físicas",
            Module::Hostname => "hostname transitorio aleatorio",
            Module::Sysctl => "hardening de kernel/red (sysctl)",
            Module::Ipv6 => "desactiva IPv6 (evita fugas)",
            Module::Vpn => "WireGuard / Proton vía wg-quick",
            Module::Dns => "resolv.conf temporal (bind mount)",
            Module::Tor => "proxy transparente Tor + firewall anti-fuga",
            Module::Killswitch => "kill switch: solo túnel VPN / Tor",
        }
    }
}
