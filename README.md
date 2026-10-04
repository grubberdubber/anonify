# anonify

<!-- Replace with your actual banner image, e.g. docs/banner.png -->
<p align="center">
  <img src=".github/assets/anonify_banner.jpg" alt="anonify banner" width="700">
</p>

<p align="center">
  <strong>Reversible, memory-only network anonymity hardening for Linux.</strong>
</p>

<p align="center">
  <a href="https://www.rust-lang.org/"><img alt="Language: Rust" src="https://img.shields.io/badge/Language-Rust-orange.svg?style=flat-square&logo=rust"></a>
  <a href="https://archlinux.org/"><img alt="Platform: Arch Linux" src="https://img.shields.io/badge/Platform-Arch_Linux-blue.svg?style=flat-square&logo=arch-linux"></a>
  <a href="LICENSE"><img alt="License: GPL-3.0" src="https://img.shields.io/badge/License-GPL--3.0-green.svg?style=flat-square&logo=gnu"></a>
  <img alt="State: RAM only" src="https://img.shields.io/badge/State-RAM_only-critical.svg?style=flat-square">
  <a href="../../issues"><img alt="PRs Welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square"></a>
</p>

<!-- Replace with an actual terminal recording or screenshot, e.g. docs/demo.gif or docs/screenshot.png -->
<p align="center">
  <img src="docs/screenshot.png" alt="anonify terminal demo" width="700">
</p>

---

## Overview

`anonify` is a Rust command-line tool that applies temporary, reversible network-anonymity hardening on Linux. All state changes live in volatile memory (`/run/anonify`, kernel `sysctl` values, `nftables` tables, bind mounts) — nothing is written to persistent storage, and a reboot or `anonify restore` returns the machine to its exact original state.

It exists because most "anonymity scripts" in circulation are ad-hoc shell scripts that silently fail halfway through, leak traffic over IPv6 or background DNS, or leave the firewall and network stack in a broken, half-applied state. `anonify` is built with real error handling, automatic rollback, and continuous drift detection (so it can tell you if something else on the system — NetworkManager, a daemon, etc. — reverted one of its changes behind its back).

## Who this is for

`anonify` is aimed at:

- Privacy-conscious individuals who want their machine's network fingerprint (MAC address, hostname, DNS, IPv6) to not trivially identify them to a local network, ISP, or passive observer.
- Security researchers and red-team operators running **authorized**, scoped engagements who need a controlled, auditable way to vary network-layer identifiers between test sessions.
- Journalists, researchers, and others operating under real threat models who need defense-in-depth against network-level tracking.

It is **not** a tool for evading law enforcement investigation, destroying evidence, or hiding wrongdoing. See the Legal & Disclaimer section below.

## Features

| Module       | What it does                                                                                                                                        | How it's reverted                                                       |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `mac`        | Randomizes the MAC address on physical network interfaces.                                                                                          | Restores the original MAC via `ip link`.                                |
| `hostname`   | Sets an ephemeral, randomized hostname (`host-xxxxxxxx`).                                                                                           | Restores the original hostname.                                         |
| `sysctl`     | Kernel-level network hardening: ignores ICMP echo, disables TCP timestamps, blocks ICMP redirects, restricts `kptr`/`bpf` exposure.                 | Restores each key's exact previous value.                               |
| `ipv6`       | Disables IPv6 on all interfaces to eliminate IPv6 leak vectors.                                                                                     | Re-enables IPv6 with its previous value.                                |
| `dns`        | Temporary RAM-backed bind mount over `/etc/resolv.conf`, pointed at a local resolver (e.g. `127.0.0.1:5353`).                                       | Unmounts `/etc/resolv.conf` immediately.                                |
| `tor`        | Runs an isolated Tor instance plus a dedicated `nftables` table (`inet anonify_tor`) redirecting TCP and DNS traffic through it.                    | Tears down the `nftables` table and sends `SIGTERM` to the Tor process. |
| `vpn`        | Brings up a WireGuard/ProtonVPN tunnel via `wg-quick`.                                                                                              | Runs `wg-quick down`.                                                   |
| `killswitch` | Strict firewall rule allowing only loopback, VPN interfaces (`wg*`, `tun*`, `proton*`), and Tor daemon traffic. If the tunnel drops, nothing leaks. | Deletes the `inet anonify_ks` table.                                    |

## Requirements & Installation

```bash
# 1. System dependencies
sudo pacman -S --needed rust tor nftables wireguard-tools iproute2 curl

# 2. Clone and build in release mode
git clone https://github.com/grubberdubber/anonify.git
cd anonify
cargo build --release

# 3. Install the binary
sudo install -m755 target/release/anonify /usr/local/bin/
```

## Usage

### Enable the full stack

```bash
sudo anonify enable --all
```

### Enable specific modules

```bash
# MAC spoofing + Tor only
sudo anonify enable mac tor

# VPN with a strict kill switch
sudo anonify enable vpn killswitch --vpn-conf ~/my-vpn/mullvad-es.conf
```

### Check status and detect configuration drift

```bash
sudo anonify status
```

If NetworkManager or another daemon reverted your MAC or hostname in the background, `anonify` flags it with an `[ON!]` drift warning.

### Run a leak check

```bash
sudo anonify check
```

### Launch isolated applications (non-root)

```bash
anonify launch vbox Whonix-Workstation
anonify launch exec -- firefox
```

### Restore everything

```bash
sudo anonify restore
```

Or simply reboot — nothing persists to disk.

### Language

`anonify` auto-detects your system locale (`LANG`/`LC_ALL`) and defaults to English if no translation is available. Override explicitly:

```bash
anonify --lang es status
# or persist the choice:
export ANONIFY_LANG=es
```

## Roadmap

- [ ] **Network-namespace sandboxing (netns / bubblewrap)**: isolate individual applications in their own ephemeral virtual interface instead of routing the whole system through Tor.
- [ ] **OUI-aware MAC spoofing**: generate MACs using real vendor prefixes (Apple, Intel, Samsung) so captive portals and enterprise routers don't flag purely random addresses.
- [ ] **Timezone & locale masking**: volatile bind-mount over `/etc/localtime` and sanitized locale environment variables.
- [ ] **File metadata scrubber**: `anonify scrub <file>` to strip EXIF, timestamps, and geolocation data before sharing files.
- [ ] **Multi-network support**: optional routing through I2P/Lokinet in addition to Tor.
- [ ] **Ephemeral browser profiles**: launch LibreWolf/Mullvad Browser with a profile mounted on `/dev/shm` that is destroyed on exit.

## Contributing

Found a bug, a network configuration this doesn't handle, or have an idea for a new module? Please [open an issue](../../issues). Well-structured, focused pull requests that fit the project's scope are welcome.

## Legal & Disclaimer

**anonify is provided for lawful use only** — personal privacy, authorized security research, and authorized red-team engagements. You are solely responsible for complying with the laws of your jurisdiction and the terms of any network, platform, or engagement you use this tool on. The author does not condone, and is not responsible for, any unlawful use of this software by any party.

This software is distributed **"AS IS", WITHOUT WARRANTY OF ANY KIND**, express or implied, as permitted under Section 15 of the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for the full text. In particular:

- **No absolute anonymity.** No tool can guarantee total anonymity. Logging into an identified account, browser fingerprinting, and traffic-correlation attacks by well-resourced adversaries are outside this tool's threat model. For high-stakes anonymity needs, use hardened, purpose-built environments such as Tor Browser, Tails, or Whonix.
- **Scope of protection.** This tool mitigates hardware-level (MAC), OS-level (hostname, sysctl), and packet-level (IPv6/DNS leaks, kill switch) identifiers. It does not protect against malware, endpoint compromise, or advanced traffic-correlation analysis.
- **Data-integrity risk.** Operations that touch kernel memory state or live network configuration carry inherent risk (e.g., an abrupt power loss during a sensitive operation can leave the system or filesystem in an inconsistent state). Use on systems where that risk is acceptable, and keep backups.
- **No liability.** To the maximum extent permitted by applicable law, the author(s) and contributors accept no liability for damages, data loss, legal consequences, or any other harm arising from the use, misuse, or inability to use this software.

If you are conducting an authorized security assessment, ensure your engagement's rules of engagement and legal authorization are documented independently of this tool.

## Support This Project

`anonify` is free, open-source, and developed independently. If your organization funds digital-privacy or anonymity tooling and would like to support continued development, please reach out via [Issues](../../issues) or see [FUNDING.yml](.github/FUNDING.yml) for sponsorship options (GitHub Sponsors / Open Collective / etc.).

## License

Licensed under the **GNU General Public License v3.0 (GPLv3)**. You are free to use, audit, modify, and redistribute this software, provided derivative works remain under the same license and source code remains available. See [LICENSE](LICENSE) for details.
