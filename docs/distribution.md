# Distribution channels

Where anonify is published, what is already automated, and what needs a human
account on the other side. Debian itself is in [debian-upload.md](debian-upload.md).

| Channel | State | Needs from you |
|---|---|---|
| Signed apt repository (Debian/Ubuntu) | automated, live | nothing |
| GitHub releases (Linux glibc/musl, macOS, Windows) | automated, live | nothing |
| crates.io | ready, verified with `cargo publish --dry-run` | `cargo login` token |
| Snap Store | manifest ready in `snap/snapcraft.yaml` | `snapcraft login`, classic review |
| BlackArch | `packaging/blackarch/PKGBUILD` ready | GitHub PR |
| Debian archive / Kali | source package + guide ready | mentors account, GPG key, sponsor |
| Ubuntu PPA | same source package | Launchpad account + same GPG key |
| Flatpak | **not viable**, see below | — |

## crates.io

The crate metadata is in `Cargo.toml`: description, license, repository, readme,
keywords, categories, and an `exclude` list that keeps `packaging/`, `snap/`,
`vendor/`, `.github/` and `tests/` out of the tarball. The dry run packages 45
files and compiles them from the tarball.

```bash
cargo login                     # paste the token from https://crates.io/settings/tokens
cargo publish --dry-run         # already passes
cargo publish
```

Then `cargo install anonify` builds it for the user. Two caveats worth stating
in the README: `cargo install` builds from source (no man pages, no `anonify`
entry in `/usr/share/man`), and the crate is a **binary** crate, so the crates.io
page is a landing page, not a library API.

Bumping the version later: `cargo set-version`/manual edit in `Cargo.toml`,
`cargo build` to refresh `Cargo.lock`, `cargo publish`, then the git tag.

## Snap Store

`snap/snapcraft.yaml` builds both binaries with the `rust` plugin on core24 and
uses **classic confinement**, because the tool needs root to touch nftables,
sysctl and network interfaces; a strictly confined snap cannot do that.

```bash
sudo snap install snapcraft --classic
snapcraft login
snapcraft pack                       # produces anonify_1.0.0_amd64.snap
sudo snap install --dangerous ./anonify_1.0.0_amd64.snap   # local test
snapcraft upload --release=edge anonify_1.0.0_amd64.snap
snapcraft promote anonify --from-channel=edge --to-channel=stable
```

A classic snap is not published automatically: file a request in the
"store-requests" category of <https://forum.snapcraft.io> with the justification
above (network administration tool, needs CAP_NET_ADMIN and /etc access, no
alternative confinement). Until it is granted, the snap stays in `edge` for
testers. The snap is not built in this repository's CI: snapcraft needs LXD or
multipass, and the release job has neither.

## BlackArch

BlackArch takes packages by pull request against <https://github.com/BlackArch/blackarch>.
The PKGBUILD is in `packaging/blackarch/` and builds from the tagged tarball
(checksum pinned to `v1.0.0`).

```bash
git clone https://github.com/BlackArch/blackarch
cd blackarch
mkdir -p packages/anonify
cp /path/to/anonify/packaging/blackarch/PKGBUILD packages/anonify/
cd packages/anonify
makepkg --printsrcinfo > .SRCINFO
makepkg -f                           # must build clean
namcap PKGBUILD anonify-1.0.0-1-x86_64.pkg.tar.zst
git checkout -b anonify
git add packages/anonify
git commit -m "anonify: add package"
git push origin anonify              # then open the PR on GitHub
```

Their CI lints the PKGBUILD and builds it in a clean chroot. Keep `depends`
accurate (`procps-ng`, not `procps`, on Arch) and regenerate `.SRCINFO` on every
version bump, or the PR is rejected.

Arch's own AUR is closed to new packages right now (bot/spam restrictions on
account creation), which is why `packaging/aur/PKGBUILD` is kept in-tree but
unpublished.

## Flatpak: why it is not offered

Flatpak is the wrong container for this tool, and shipping a manifest that cannot
work would be worse than not shipping one:

- A Flatpak app runs as the user inside a sandbox with no `CAP_NET_ADMIN`. It
  cannot create nftables tables, change `sysctl`, rename interfaces or change a
  MAC address — which is most of what anonify does.
- `/etc` is read-only (or a private tmpfs) inside the sandbox, and `/run` is not
  shared as writable state, so the state directory and restore path do not exist.
- Polkit and root escalation are unavailable to sandboxed apps, so `anonify tor`
  and `anonify vpn` cannot install their fail-closed rules.

The parts that *would* work in a Flatpak (`anonify check`, `anonify launch`) are
secondary, and `anonify launch` already uses `bubblewrap` directly, which is the
same sandboxing technology without the runtime indirection.

For Flatpak users the honest recommendation is the static musl tarball from the
GitHub release, run from outside the sandbox, or the apt repository.

## Fedora / RHEL

Not packaged. `packaging/fedora/` is empty on purpose: an RPM would need to be
submitted to Fedora's review process (a bug against `fedora-review`), and the
tool targets systemd-networkd/NetworkManager behaviour that differs enough on
Fedora to deserve its own testing pass. Treat it as a future channel, not as
"just another file".
