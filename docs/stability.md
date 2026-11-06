# Stability contract (1.x)

This document is a promise, in the spirit of [Semantic Versioning](https://semver.org/):
what `anonify` 1.x will not break without a major version bump. If any of it
changes in a way that breaks you, that is a bug — [open an
issue](https://github.com/grubberdubber/anonify/issues).

The tool's *behavior* (which MAC you get, which tables exist) is not covered:
the point of the tool is to change the network, and the list of modules will
grow. What is covered is everything a script, package or operator can depend
on.

## 1. Command line

These subcommands, flags and positional-argument shapes stay compatible for the
whole 1.x line:

```
anonify [--lang L] [--quiet] [--timeout S] <command>
  enable [MODULE...] [--all] [--vpn-conf FILE] [--tor-bridges FILE] [--mac-vendor V]
  disable [MODULE...]
  restore
  status [--json]
  check [--json]
  doctor [--json]
  rotate
  watch [--interval S] [--restore] [--once]
  launch [--isolate] [--allow-net] [--hostname H] [--home DIR]
         [--tz ZONE] [--lang L] [--no-sandbox] <program> [ARGS...]
anonify-browser [--browser BIN] [URL]
```

- New **optional** flags and new subcommands may be added in a minor release.
- Existing flags are never removed or given a different meaning inside 1.x.
- Module names (`mac`, `hostname`, `sysctl`, `ipv6`, `dns`, `tor`, `vpn`,
  `killswitch`, `lan`) are stable identifiers: scripts may `enable mac tor` and
  expect those names to keep working.
- Human-readable messages (and their translations) are **not** a stable API.
  Anything a program needs to read is in `--json`.

## 2. JSON output

The JSON objects are stable in the additive sense: fields below keep their
names, types and meaning. New fields may appear; consumers must ignore unknown
ones.

**`anonify status --json`**

| Field | Type | Meaning |
| --- | --- | --- |
| `drift` | bool | at least one active module is no longer applied |
| `active` | string[] | modules recorded as active |
| `pending` | string[] | modules enabled but not yet confirmed applied |
| `modules` | object[] | per-module state (`module`, `active`, `pending`, …) |

**`anonify check --json`**

| Field | Type | Meaning |
| --- | --- | --- |
| `ok` | bool | no leaks and no drift |
| `active` | string[] | modules currently applied |
| `pending` | string[] | modules awaiting confirmation |
| `leaks` | string[] | confirmed leaks (non-empty ⇒ exit 1) |
| `warnings` | string[] | suspicious but unconfirmed |
| `notes` | string[] | informational findings |

**`anonify doctor --json`**

| Field | Type | Meaning |
| --- | --- | --- |
| `ok` | bool | no blockers |
| `kernel`, `distro` | string | detected platform |
| `root` | bool | running with effective uid 0 |
| `active` | string[] | modules currently applied |
| `blockers` | number | count of `fail` findings |
| `warnings` | number | count of `warn` findings |
| `findings` | object[] | `{level, code, detail}`, `level` ∈ `ok`/`note`/`warn`/`fail` |

`code` values are stable; `detail` is prose in English and may be reworded.

## 3. Exit codes

| Code | Meaning |
| --- | --- |
| `0` | success; for `check`/`doctor`/`watch --once`/`status`, "nothing wrong found" |
| `1` | a leak (`check`), drift (`status`, `watch --once`) or a blocker (`doctor`) |
| `2` | CLI usage error (produced by clap: unknown flag, bad value, missing argument) |
| `130` | interrupted while a state-changing command was running; a best-effort `restore` was attempted |
| other non-zero | an operation failed; the message on stderr says which layer and whether rollback succeeded |

## 4. State format

- State lives at `/run/anonify/state.json` (tmpfs), mode `0600`, written
  atomically (`temp` + `fsync` + `rename`) under an exclusive `flock`.
- The file carries a format version. A 1.x release reads any state file written
  by an earlier 1.x release.
- A **corrupt** state file is a hard error, not a silent reset: losing the saved
  originals would mean the machine could not be restored. The error names the
  file and tells you how to proceed; it never discards the data.
- The on-disk key set may gain fields in a minor release. Tools that parse it
  must ignore unknown keys. Nothing outside `/run/anonify` is part of the state.

## 5. System side effects

- Reverting is the contract, not a best effort per module: `restore` reports
  each failure and **keeps** the original value so it can be retried. It exits
  non-zero if anything could not be reverted.
- Only these system surfaces are touched, and only while a module is enabled:
  link `MAC`, the running hostname, a documented set of `sysctl` keys, IPv6
  `disable_ipv6`, a bind mount over `/etc/resolv.conf`, `nftables` tables named
  `anonify_*`, a Tor process owned by anonify under `/run/anonify`, and
  `wg-quick` interfaces it brought up.
- `anonify` never writes to the system's persistent configuration, never edits
  `/etc/hostname` or `/etc/machine-id`, and never touches logs, audit state,
  histories, caches or file timestamps. This will not change in 1.x; see
  [AGENTS.md](../AGENTS.md).

## 6. Platform support

| Platform | `anonify` | `anonify-browser` |
| --- | --- | --- |
| Linux (glibc, x86_64/aarch64) | supported, tested in CI | supported |
| Linux (musl, static) | supported | supported |
| Windows (x86_64) | not yet (see [`platforms.md`](platforms.md)) | supported |
| macOS (x86_64/arm64) | not yet | supported |

Minimum supported Rust version: **1.85** (edition 2024). Raising it requires a
minor release and a note in the changelog.

## 7. What 1.x will not promise

No version promises anonymity. `anonify` reduces a set of network identifiers
and prevents a documented list of leaks; it does not defend against a global
adversary, endpoint compromise, or an authenticated account. The threat model
is spelled out in [AGENTS.md](../AGENTS.md) and is not negotiable for funding,
features or convenience.
