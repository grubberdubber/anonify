# Installing anonify

`anonify` ships two binaries:

| Binary | Platforms | Root | What it does |
| --- | --- | --- | --- |
| `anonify` | Linux | yes, for everything except `doctor`, `launch` and `--help` | The network engine: MAC, hostname, sysctl, IPv6, DNS, Tor, VPN, kill switch, LAN discovery, `check`, `watch`, `doctor`, `launch`. |
| `anonify-browser` | Linux, Windows, macOS | no | Opens Firefox/LibreWolf with a throwaway, leak-hardened profile. No system changes, no elevation. |

Both come from the same crate; `anonify-browser` is the only binary that is
built and tested on Windows/macOS (see [`platforms.md`](platforms.md)).

## Before you install: `doctor`

`anonify doctor` is a read-only preflight. Run it first; it tells you which
dependencies are missing, whether the state is restorable, and which
environment hazards (plain swap, `systemd-resolved` stub, a foreign listener
on `127.0.0.1:9050`) apply to *your* machine. It needs no root and changes
nothing:

```bash
anonify doctor
anonify doctor --json | jq '.findings[] | select(.level=="fail")'
```

Exit code is `1` only when it finds a blocker (missing `nftables`, corrupt or
pending state, or an `anonify_*` nftables table no active module owns).

## Debian / Ubuntu (apt repository)

The package is published to a signed apt repository served from GitHub Pages.
Works on Debian 13 (trixie) and later, and on Ubuntu 24.04 and later:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://grubberdubber.github.io/anonify/anonify-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/anonify-archive-keyring.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/anonify-archive-keyring.gpg] \
https://grubberdubber.github.io/anonify/ stable main" \
  | sudo tee /etc/apt/sources.list.d/anonify.list
sudo apt update
sudo apt install anonify
sudo anonify doctor
```

Check the key fingerprint before trusting it:

```
DA96 EF55 DA81 E253 A239  54AA 88FA 799E 2AC1 65BB
```

The package ships `anonify`, `anonify-browser` and both man pages. Runtime
dependencies: `nftables`, `iproute2`, `procps`. Recommended: `tor`,
`wireguard-tools`, `network-manager`, `bubblewrap`, `curl`, `obfs4proxy`.

## Arch Linux / AUR

The `PKGBUILD` lives in [`packaging/aur`](../packaging/aur). The AUR is
currently not accepting new packages, so build it locally in the meantime:

```bash
git clone https://github.com/grubberdubber/anonify.git
cd anonify/packaging/aur && makepkg -si
sudo anonify doctor
```

Once it is published there, `yay -S anonify` (or `paru -S anonify`) will work.

Runtime dependencies installed by the package: `nftables`, `iproute2`,
`util-linux`. Optional: `tor`, `wireguard-tools`, `networkmanager`,
`bubblewrap`, `curl`, `obfs4proxy`.

## Cargo (any Linux distribution)

```bash
# Rust 1.85 or newer (edition 2024)
cargo install anonify --locked        # from crates.io, once the crate is published
cargo install --git https://github.com/grubberdubber/anonify --bins   # or from git
# or, from a checkout, without touching the PATH-managed registry:
cargo install --path . --bins
```

That installs `anonify` and `anonify-browser` into `~/.cargo/bin`.

## From source (recommended for auditability)

```bash
git clone https://github.com/grubberdubber/anonify.git
cd anonify
cargo build --release --locked
sudo install -m755 target/release/anonify /usr/local/bin/
install -m755 target/release/anonify-browser ~/.local/bin/
```

System packages on Arch:

```bash
sudo pacman -S --needed nftables iproute2 util-linux tor wireguard-tools \
                        networkmanager bubblewrap curl obfs4proxy
```

Debian/Ubuntu equivalents:

```bash
sudo apt install nftables iproute2 procps tor wireguard-tools \
                 network-manager bubblewrap curl obfs4proxy
```

## GitHub Releases

Pushing a `v*` tag runs `.github/workflows/release.yml`, which builds and
attaches:

- `anonify-<version>-x86_64-linux-gnu.tar.gz` — `anonify` + `anonify-browser`
- `anonify-<version>-x86_64-linux-musl.tar.gz` — static engine, no libc match needed
- `anonify-browser-<version>-x86_64-windows.zip`
- `anonify-browser-<version>-x86_64-macos.tar.gz`
- `SHA256SUMS-linux` and per-file `.sha256`

Verify before running as root:

```bash
sha256sum -c SHA256SUMS-linux
tar -tzf anonify-1.0.0-x86_64-linux-gnu.tar.gz
```

## Windows and macOS

```bash
cargo install --git https://github.com/grubberdubber/anonify --bin anonify-browser
anonify-browser https://example.org
```

No administrator/UAC prompt, no firewall or DNS change. The hardened
`user.js` is the whole feature: WebRTC off, DNS through the local Tor SOCKS
when it is listening, no telemetry, permanent private browsing. On Windows the
profile lives under `%TEMP%\anonify` rather than tmpfs.

The engine is Linux-only on purpose. A Windows firewall backend (WFP) is a
separate milestone with its own threat model; see
[`platforms.md`](platforms.md).

## Upgrading

State is versioned implicitly and stays compatible across 1.x releases; check
[`stability.md`](stability.md). Upgrading never requires a reboot, but if a
release changes a module's rules, run:

```bash
sudo anonify restore
sudo anonify enable --all
```

## Uninstalling

```bash
sudo anonify restore          # undo every runtime change first
sudo pacman -Rns anonify      # or: cargo uninstall anonify
```

Everything anonify stores lives in `/run/anonify` (tmpfs) and is gone after a
reboot. It never writes persistent state, so uninstalling leaves nothing
behind beyond the binaries themselves.
