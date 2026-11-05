# Platform support

`anonify` is a Linux network-anonymity tool. That is not a packaging detail:
almost every control it relies on is a Linux kernel or Linux-daemon interface.
This document records what actually works where, why the engine is not ported
1:1, and what a real Windows backend would require.

## What runs where

| Capability | Linux | Windows | macOS |
| --- | --- | --- | --- |
| `anonify` engine (`mac`, `hostname`, `sysctl`, `ipv6`, `dns`, `tor`, `vpn`, `killswitch`, `lan`, `check`, `watch`, `launch`) | ✅ | ❌ | ❌ |
| `anonify-browser` (hardened throwaway browser profile) | ✅ | ✅ (CI build + library tests) | ✅ (build) |
| Root/administrator required | For the engine only | No | No |
| Writes system configuration | No (runtime only) | No | No |

The Windows CI job builds `anonify-browser` and runs the portable library
tests. It does **not** run the Linux engine, and no privileged Windows code is
shipped.

## Why the engine is not portable

| Linux mechanism | Windows equivalent | Why it is not a drop-in |
| --- | --- | --- |
| `nftables` (`inet` tables, redirects) | WFP filters / `netsh advfirewall` | Different rule model, different rollback semantics, requires elevation and a saved copy of the previous policy. |
| `sysctl net.ipv4.*`, `net.ipv6.*` | Registry `Tcpip\Parameters` + `netsh int tcp set global` | Persistent by nature; “restore” means writing values back and often needs a reboot. |
| `ip link set address` | Per-network random MAC in Windows 10+ only | No supported runtime API to set an arbitrary MAC per interface without a reboot. |
| Transient hostname via `PR_SET_NAME`/`sethostname` | `SetComputerNameEx` | Persistent, reboot-bound. Out of scope under the reversibility rule. |
| `/run` tmpfs state | `%LOCALAPPDATA%` | No tmpfs; state would survive reboots unless the tool removes it, which changes the “volatile by construction” guarantee. |
| `nmcli device modify` | `netsh interface` / PowerShell cmdlets | Persistent interface configuration, not a per-boot runtime override. |
| `tor` + `wg-quick` + `setpriv` | Tor Expert Bundle + WireGuard for Windows | Tor can run, but the transparent redirect and user dropping do not exist; each app must be forced through SOCKS. |

The Windows threat model is also different: Windows telemetry, Defender and the
WFP policy engine are part of the observable system, and a tool that “hardens”
them can easily become a tool that hides activity from the machine's owner.
That is a red line in `AGENTS.md`.

## If a Windows engine is built

It would be a separate backend behind the same CLI, with these rules:

1. **Elevation is explicit.** A UAC manifest requests administrator only for
   the commands that need it (`tor`, `killswitch`, `dns`, `ipv6`), never for
   `check` or `anonify-browser`.
2. **Every change is saved and verified.** Firewall rules are exported before
   modification and re-imported/removed on restore; DNS and IPv6 settings are
   read back and compared, not assumed.
3. **No persistent identity changes.** No computer-name changes, no registry
   hostname edits, no MAC “spoofing” that needs a reboot.
4. **No audit, log, Defender or telemetry tampering.** WFP filters are traffic
   policy, not evidence handling.
5. **Fail-closed is opt-in and loud.** A Windows kill switch can lock the user
   out of their own network; the design must include a documented recovery path
   (safe mode / `anonify restore`) before it ships.
6. **State is volatile-by-contract.** State lives in a directory the tool
   creates per boot/session and documents; `restore` removes the filters and
   restores the saved policy. Deleting the state file must never be presented
   as “cleaning traces”.

Milestones, in order:

1. ✅ `anonify-browser` (portable, no privileges).
2. `anonify check` read-only backend: firewall profile, DNS servers, IPv6
   binding, adapter vendor/OUI, proxy settings.
3. `anonify tor` + `killswitch` over WFP, with exported/restored policy.
4. Docs, threat model and legal review before any of it is enabled by default.

Until then, Windows users get the browser profile and are told plainly that the
network engine is Linux-only.
