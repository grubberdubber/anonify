# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `check` command: fail-closed DNS, IPv6, MAC, hostname, sysctl, Tor, VPN and
  kill-switch audit. Public-IP checks only run through Tor's SOCKS port.
- Unit tests for state handling, sysctl rollback, MAC generation, DNS mount
  parsing, endpoint resolution, and both nftables rule sets.
- `tests/namespace-smoke.sh`: exercises hostname, nftables, bind mounts, and
  network sysctls inside private user/mount/network/UTS namespaces.
- GitHub Actions CI for formatting, pedantic clippy, tests, release build, and
  the namespace smoke test when the runner supports user namespaces.
- `CONTRIBUTING.md`, `SECURITY.md`, and this changelog.

### Changed

- Activation order is now `mac`, `sysctl`, `ipv6`, `hostname`, `vpn`, `tor`,
  `dns`, `killswitch`; deactivation runs in reverse.
- `sysctl` records each original value before writing, verifies the read-back,
  and rolls back already-applied keys on failure.
- `mac` and `hostname` only discard restore data after verifying the original
  value is back.
- `dns` detects its bind mount through `/proc/self/mountinfo`, refuses to
  overwrite foreign mounts, and is automatically disabled before `tor`.
- `vpn` refuses to touch an existing interface, validates config permissions,
  warns on hostname endpoints, and stores numeric endpoint addresses.
- `killswitch` allows only loopback, DHCP, tunnel interfaces, the resolved VPN
  endpoint (`IP` + UDP port), and the Tor UID.
- `check` reports drift when the Tor or kill-switch table no longer keeps its
  `policy drop` policy.

### Fixed

- **Fail-closed Tor startup:** the redirecting/blocking nftables table is
  installed before Tor starts, so bootstrap cannot leak cleartext traffic.
- Tor cleanup only terminates a PID verified as anonify's own Tor instance.
- Partial module activation now triggers an automatic rollback; unrecoverable
  cleanup is recorded in `State.pending` and retried by `restore`.
- Corrupt `state.json` is a hard error for `enable` instead of silently
  discarding the original MAC/hostname/sysctl values.
- `State` writes are atomic (`temp + fsync + rename`, mode `0600`) and use a
  `flock` around read-modify-write sequences.
- The startup banner and watchdog no longer trigger pedantic or pointer-cast
  warnings; all `unsafe` blocks document their invariant.
- Removed `kernel.dmesg_restrict` from sysctl hardening: restricting `dmesg`
  access is outside the network-privacy scope and can obstruct diagnostics.

### Security

- Documentation now states the hard legal boundary: no log deletion, audit
  suppression, timestamp manipulation, history wiping, or evidence tampering.
- `check`, `README.md`, `AGENTS.md`, and contribution policy explicitly reject
  anti-forensic features.
