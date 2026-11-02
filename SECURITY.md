# Security Policy

## Supported versions

Security fixes are applied to the latest release on the `main` branch. If you are running an older commit, reproduce the issue on the latest `main` before reporting it.

## Reporting a vulnerability

Please **do not** open a public issue for a security vulnerability. Instead, contact the maintainer privately through the repository's security advisory feature (GitHub → Security → Report a vulnerability) or the contact listed in `Cargo.toml`/the repository profile.

Include:

- a description of the issue and its impact;
- affected version/commit;
- minimal reproduction steps, ideally in an isolated namespace or virtual machine;
- whether the issue can leak traffic, bypass the kill switch, expose credentials, or leave restore state behind.

Please allow reasonable time for a fix before public disclosure. Do not test against networks or systems you do not own or have explicit authorization to test.

## Scope

In scope:

- traffic leaks (DNS, IPv6, ICMP, cleartext outside Tor/VPN);
- kill-switch bypasses or fail-open behavior;
- injection into `nftables`/shell commands;
- state corruption that loses original MAC/hostname/sysctl values;
- privilege escalation or unsafe handling of user-supplied files;
- persistent writes of sensitive data that the documentation says are volatile.

Out of scope:

- requests to add log deletion, audit suppression, timestamp manipulation, or evidence tampering (these are rejected by policy);
- anonymity guarantees against global traffic correlation, compromised endpoints, or malware;
- issues that require an already-compromised root account.
