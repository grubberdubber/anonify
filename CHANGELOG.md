# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-06

First stable release. The CLI, the `--json` reports of `status`, `check` and
`doctor`, the exit codes and the `state.json` format are covered by the 1.x
stability contract in [`docs/stability.md`](docs/stability.md). No absolute
anonymity is promised; the threat model is unchanged.

### Added

- `doctor`: a read-only preflight that runs without root and reports blockers
  (`fail`: no `nftables`, corrupt or pending state, orphaned `anonify_*`
  tables), warnings (not root, unwritable `sysctl`, `systemd-resolved` stub
  resolver, a foreign listener on `127.0.0.1:9050`, plaintext swap) and notes
  (optional tools missing). `--json` emits the same report; exit code 1 only
  when something blocks a safe run.
- Packaging: AUR `PKGBUILD` (tagged source, `--locked` build, optional
  dependencies as `optdepends`), a Fedora/COPR spec with a vendoring helper for
  offline mock builds, and a Debian `debian/` directory for `.deb` builds.
- `.github/workflows/release.yml`: pushing a `v*` tag builds glibc and static
  musl Linux archives plus the portable `anonify-browser` for Windows/macOS,
  publishes checksums and creates the GitHub release.
- `docs/install.md` (AUR, cargo, source, releases, Windows/macOS, uninstall)
  and `docs/stability.md` (what 1.x will not break).
- `lan`: silences local service discovery so the LAN stops learning the
  machine's hostname and services. A dedicated `inet anonify_lan` table drops
  outbound `mDNS` (5353), `LLMNR` (5355), `SSDP` (1900), `NetBIOS`
  (137/138/139) and `WS-Discovery` (3702) with `policy accept`, so it can
  never cut internet access; nothing is written to any daemon configuration
  and `restore` just deletes the table. DHCP still announces the hostname when
  the client asks for it, which is documented instead of hidden.
- `anonify-browser`: a portable binary (Linux, Windows, macOS) that opens
  Firefox/LibreWolf with the same throwaway hardened profile without root,
  UAC or any system change. The profile logic moved to a library shared with
  `launch browser`. On Windows it lives under `%TEMP%\anonify` because there
  is no tmpfs; permanent private browsing keeps history and cache out of it.
- `launch browser`: opens LibreWolf/Firefox/`firefox-esr` with a throwaway
  profile in `/run/user/<uid>` (tmpfs, `0700`, `user.js` `0600`) instead of the
  user's real profile. The generated `user.js` closes the leaks a proxy alone
  does not cover — WebRTC local IP, plaintext DNS, DoH/TRR to a third party,
  speculative connections, telemetry/studies, Safe Browsing, Pocket/FxA, crash
  reports — and starts in permanent private browsing so nothing persists. When
  a SOCKS listener is up on `127.0.0.1:9050`, all traffic and DNS are pinned to
  it; otherwise it warns and uses the system network (VPN-only setups). The
  profile is memory-backed and is never deleted by `anonify`, so the tool does
  not touch session history; it disappears on reboot. Integrates with
  `--isolate --allow-net` when the sandbox needs the host network.
- `enable --tor-bridges <FILE>`: feeds Tor a bridges file for censored or DPI-heavy
  networks. Only `Bridge ...` and `ClientTransportPlugin ...` lines are accepted
  (pluggable transports must declare their plugin, and other directives such as
  `SocksPort` are rejected) so the file cannot smuggle an arbitrary `torrc` into
  the sandboxed instance; the parse happens before any firewall change.
- Process-wide hardening at startup: `PR_SET_DUMPABLE=0` blocks same-user
  `ptrace`/`/proc/<pid>/mem` access, `RLIMIT_CORE=0` prevents core dumps from
  spilling keys to disk, and `PR_SET_NO_NEW_PRIVS` stops privilege gain via
  setuid helpers. `launch`ed children inherit all three.
- `check` now audits routes and secondary links (still read-only): with `vpn`
  active, an IPv4/IPv6 default route that still leaves through a physical
  interface is reported as a leak (covering split tunnels), an IPv6 default
  route while `ipv6` is supposed to be off is a leak, and more than one
  physical interface being up is warned as an extra egress path. Parsers for
  `/proc/net/route` and `/proc/net/ipv6_route` are unit-tested.
- `anonify watch`: foreground drift monitor that re-verifies active modules
  against the real system state on an interval. Warns once per drift episode
  (stderr only, nothing logged), `--restore` runs a full restore and exits on
  the first drift, and `--once` gives a script-friendly one-shot check that
  exits 1 when something drifted.
- `status --json` and `check --json`: stable, documented JSON shapes
  (`status`: `drift`/`active`/`pending`/`modules`; `check`:
  `active`/`pending`/`leaks`/`warnings`/`notes`/`ok`). Exit statuses are
  unchanged, so both remain usable in CI and shell pipelines.
- `enable mac --mac-vendor <family>`: OUI-aware MAC spoofing (`local` by
  default, plus `random`, `intel`, `apple`, `cisco`, `dell`, `samsung`,
  `tp-link`, `realtek`, `raspberry`) for networks that reject locally
  administered addresses. Prefixes are validated as unicast/globally
  administered before use, and a malformed prefix falls back to `local`.
- `anonify rotate`: new MACs/hostname for the active `mac`/`hostname` modules
  without touching the saved originals; the MAC policy is persisted in the
  volatile state so rotation reproduces it.
- `launch --isolate` now sets `TMPDIR` and `XDG_CACHE_HOME` to the sandbox
  tmpfs, so font/shader/browser caches from that app never reach the real home
  directory.
- `launch --isolate --allow-net` warns when no `tor`/`vpn`/`killswitch` layer
  is active, since the sandbox then uses the host network as-is.
- `launch --isolate`: per-application `bubblewrap` sandbox with read-only
  `/usr` and `/etc`, private tmpfs `/tmp`, `/dev/shm` and `HOME`, a UTS
  namespace with its own (random by default) hostname, and no network at all
  unless `--allow-net`. `--home <dir>` keeps a specific profile writable (e.g.
  a browser profile in `/dev/shm`). Everything dies with the process; no
  mounts or config files persist. `--hostname` fixes the sandbox hostname.
- `sys::euid()` helper; `Containerfile` now installs `bubblewrap`.
- `launch` hardening: apps now start from a whitelisted environment (no
  `HOSTNAME`, `SSH_AUTH_SOCK`/`SSH_CONNECTION`, `MAIL`, no inherited
  `TZ`/`LANG`/`LC_*`), get a neutral `USER`/`LOGNAME`, and run through
  `setpriv` with `no_new_privs` plus (when root) an empty capability bounding
  set. `--tz`/`--lang` apply to the child only; `--no-sandbox` opts out.
- Memory hardening: `mlockall(MCL_CURRENT)` best-effort for the process (the
  failure path warns instead of aborting), a `SecretBuf` that is `mlock`ed and
  zeroized on drop for the `WireGuard` private key, and a zeroized buffer for
  the serialized state.
- `check` now audits swap: it warns when swap is active on a device that is
  neither `zram` nor verified `dm-crypt`, since `tmpfs` pages (including
  `/run/anonify`) can otherwise be written to disk in cleartext. Read-only, and
  it never disables swap.
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

- `launch --isolate` now drops privileges with `setpriv` **before** executing
  `bwrap` (when a target user is known). `bwrap` then creates the sandbox
  `HOME`/`/tmp` as that user, which fixes apps being unable to write their
  profile under `sudo`; capability dropping is delegated to the unprivileged
  user namespace `bwrap` sets up. Running as root without a target user keeps
  the previous order (bwrap, then `setpriv --bounding-set=-all`).
- `State::save` no longer resets `/run/anonify` to `0755` on every write: an
  operator who tightened the directory permissions is no longer overridden.
  `state.json` still stays `0600`.
- `launch` drops privileges with `setpriv` instead of `sudo -u ... -H`, so the
  target user's `HOME`, `USER`, `LOGNAME` and `XDG_RUNTIME_DIR` are set
  explicitly, and the app no longer inherits root's environment.
- New runtime dependency: `zeroize` (default features) for wiping process
  buffers on drop.
- Activation order is now `mac`, `sysctl`, `ipv6`, `hostname`, `vpn`, `tor`,
  `dns`, `killswitch`; deactivation runs in reverse.
- `sysctl` records each original value before writing, verifies the read-back,
  and rolls back already-applied keys on failure.
- `mac` and `hostname` only discard restore data after verifying the original
  value is back.
- `dns` detects its bind mount through `/proc/self/mountinfo`, refuses to
  overwrite foreign mounts, and is automatically disabled before `tor`.
- `vpn` refuses to touch an existing interface, validates config permissions,
  warns on hostname endpoints and `wg-quick` hook directives, and stores numeric
  endpoint addresses.
- `killswitch` allows only loopback, DHCP, tunnel interfaces, the resolved VPN
  endpoint (`IP` + UDP port), and the Tor UID.
- `check` reports drift when the Tor or kill-switch table no longer keeps its
  `policy drop` policy.

### Fixed

- **DHCP renewal under Tor:** the `anonify_tor` input chain dropped DHCP
  OFFER/ACK (source port 67 to 68), which are not tracked as `established`.
  Lease renewal could therefore fail and the network die when the lease
  expired. The reply rule is now explicit.
- `mac::holds` reports drift when a previous change left `mac_dirty` entries,
  instead of claiming the module is applied.
- `launch --isolate` used root's `HOME` as the sandbox `HOME` under `sudo`,
  so the app was told to use a path that was neither mounted nor writable.
- `launch`'s flag-validation error is now translated instead of hard-coded
  Spanish.
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

### Changed

- Rust 2024 edition, declared MSRV (`rust-version = "1.85"`) verified in CI,
  and `[lints.rust]`/`[lints.clippy]` in `Cargo.toml` (all + pedantic) so
  `cargo clippy` enforces the same rules editors and CI see. `clap` upgraded
  to 4.5/4.6 and `rand` to 0.9 (`gen` → `random`, `gen_range` →
  `random_range`).
- CI runs a Linux matrix (stable + 1.85) and a Windows job that builds
  `anonify-browser` and runs the portable library tests.
