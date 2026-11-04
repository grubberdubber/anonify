# Contributing to anonify

Thanks for helping improve privacy tooling. Please read this before opening a pull request.

## Scope and ethics

`anonify` reduces network identifiers and leak vectors for **lawful privacy and authorized security work**. It is not an anti-forensics tool.

We reject, without exception, contributions that:

- delete, truncate, rotate, redirect, or modify system logs, `journald`, `auditd`, `dmesg`, authentication logs, or application logs;
- change file timestamps or metadata to hide activity;
- wipe shell histories, browser histories, caches, or evidence;
- disable auditing, SELinux/AppArmor, system firewalls, or forensic tooling;
- hide processes, files, connections, interfaces, or users;
- destroy or alter evidence, or obstruct a lawful investigation.

If your idea requires any of the above, it is out of scope. Privacy-by-minimization is welcome; evidence tampering is not.

New modules and cross-cutting changes must pass the admission gate in
[AGENTS.md](AGENTS.md#3-procedimiento-de-admisión-gate-obligatorio) (threat
model, data touched, reversibility, fail-closed, persistence, legal impact,
tests). Decisions already settled there are not re-litigated in review.

## Development setup

```bash
sudo pacman -S --needed rust tor nftables wireguard-tools openresolv iproute2 curl
cargo build
cargo test
```

Low-level tests can run inside a user/network/mount namespace without touching the host network:

```bash
./tests/namespace-smoke.sh
```

## Required checks

Before submitting a change, run:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings -W clippy::pedantic
cargo test
```

If your change touches network state, describe what it changes, how it is reverted, and how you tested it in an isolated namespace.

## Commit style

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new user-visible capability
- `fix:` bug fix
- `docs:` documentation only
- `refactor:` internal change without behavior change
- `test:` tests only
- `chore:` tooling, CI, dependencies
- `security:` hardening or vulnerability fix

Keep commits atomic. In the body, explain the **why**, the failure mode, and the rollback behavior. Do not include secrets, VPN private keys, personal configurations, or test credentials.

Example:

```
fix(tor): install the blocking firewall before bootstrap

Starting Tor first left a window where TCP/DNS traffic could leave
in clear text. Load the nftables table first so the output policy is
drop while Tor bootstraps, then verify the process and bootstrap log.
```

## Code guidelines

- Rust 2021, `clippy::pedantic`, explicit errors (`anyhow`/`thiserror`).
- No `unwrap()`/`expect()` in production paths.
- Every `unsafe` block needs a `SAFETY` comment.
- Never interpolate untrusted data into a shell command or `nftables` rule. Validate UIDs, IPs, ports, and interface names.
- Preserve restore state when a deactivation fails; never silently discard the original value.
- Keep the tool's own logs in tmpfs or `stderr`; never write activity logs to persistent storage.

## Security reports

Please do not open a public issue for vulnerabilities. See [SECURITY.md](SECURITY.md).
