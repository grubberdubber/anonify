# Debian / Ubuntu

This directory is a `debian/` directory. Debian tooling expects it at the
source root, so copy it there when building.

## Status

The package builds, installs and is lintian-clean on Debian 13 (trixie), which
is also the CI target:

```
anonify_1.0.0-1_amd64.deb
  /usr/bin/anonify
  /usr/bin/anonify-browser
  /usr/share/man/man1/anonify.1.gz
  /usr/share/man/man1/anonify-browser.1.gz
```

It ships binary packages only. Getting into the Debian archive proper is a
different process (see below) and is not something a build can decide.

## Building

```bash
# from a checkout, with network access for the vendoring step
./packaging/vendor.sh
cp -r packaging/debian .
chmod +x debian/rules
dpkg-buildpackage -us -uc -b
lintian ../anonify_1.0.0-1_amd64.changes
```

Or, fully reproduced in a container (what CI does):

```bash
docker run --rm -v "$PWD":/src:ro -v "$PWD/dist":/out debian:trixie bash -c '
  apt-get update && apt-get install -y --no-install-recommends \
    build-essential cargo debhelper dpkg-dev fakeroot git rustc lintian
  cp -a /src /work && cd /work && ./packaging/vendor.sh
  cp -r packaging/debian debian && chmod +x debian/rules
  dpkg-buildpackage -us -uc -b && cp /anonify_*.{deb,changes,buildinfo} /out/'
```

## Source package for mentors.debian.net

A binary build is not what gets uploaded; a source package is. This produces
`.dsc`, `.orig.tar.gz`, `.debian.tar.xz`, `_source.buildinfo` and the
`_source.changes` that `dput` sends:

```bash
./packaging/debian/make-source.sh dist/source
lintian --pedantic --fail-on error dist/source/*_source.changes
debsign -k <keyid> dist/source/*_source.changes
dput mentors dist/source/*_source.changes
```

`make-source.sh` takes the package name and version from
`debian/changelog`, so nothing here hardcodes a version. It picks podman or
docker automatically, builds inside `debian:trixie` (so `dpkg-source` and the
Rust toolchain match the target distribution) and prunes artefacts of earlier
versions from the output directory.

The interactive wrapper does lintian, signing and the upload in one step, from
a throwaway copy of the keyring in `/dev/shm` so the container never shares
`~/.gnupg` with the host `gpg-agent`:

```bash
./packaging/debian/upload.sh -k <keyid>        # lintian, sign, dput
./packaging/debian/upload.sh -k <keyid> -n     # lintian only
./packaging/debian/upload.sh -k <keyid> -s     # sign only
./packaging/debian/upload.sh -k <keyid> -f     # re-upload after a rejection
```

`-f` matters: a rejected upload leaves a `*.upload` log behind and `dput`
refuses to retry until it is forced.

## A new version

Once the package is in Debian, a release is a changelog entry plus a rebuild:

```bash
./packaging/debian/new-version.sh 1.0.1-1     # new upstream release
./packaging/debian/new-version.sh 1.0.0-2     # Debian-only changes
```

`new-version.sh` writes the changelog stanza (package name, maintainer line and
date copied from the current entry, UTC date) and prints the next commands;add `-b` to build the source package right away, or `-D noble` to target an Ubuntu
distribution. The ITP, the RFS bug and the NEW queue are one-time: a version
bump only needs the sponsor to upload, and once you hold upload rights yourself
(`dput ftp-master`) it needs nobody.

The full per-release checklist, from the version number to the tag and the
sponsor mail, is [`docs/debian-release.md`](../../docs/debian-release.md).

## What still needs a human

1. A GPG key whose fingerprint is registered in your `mentors.debian.net`
   account, plus the SSH key you uploaded there. Uploads are authenticated by
   the GPG signature on the `.changes` file and pushed over SSH; no token or
   password can stand in for it. The private key must stay on your machine,
   which is why CI builds but never uploads.
2. An ITP (Intent To Package) bug in the Debian BTS, so the package has a
   number to close and a place to discuss licensing.
3. A sponsor: Debian requires an existing Developer to review and upload the
   first version. `mentors.debian.net` is the queue where sponsors look.

## CI

`.github/workflows/packaging.yml` builds the source package and the binary
packages on every `v*` tag and on pull requests touching `packaging/`, and runs
lintian on both. On a tag it also checks that the tag matches the upstream
version in `debian/changelog`, so a release cannot ship a `.dsc` with a
different version than the one it is tagged with.

Both jobs start from `debian:trixie` with `docker run`, exactly like the local
commands above. They need no secrets.

## Moving to another machine

Everything except the private key is in the repository or in the image:

1. `podman` (or `docker`) and `gpg`.
2. Your GPG key, restored with its passphrase.
3. Nothing else: `make-source.sh` installs its own build tooling inside the
   container, and `upload.sh` builds its own image (`-r` rebuilds it) for
   lintian, debsign and dput.

## Latest release

The published apt repository is

```bash
apt install anonify   # after adding the repo, see docs/install.md
```

and is generated by `packaging/apt-repo.sh` from the `.deb` files, signed with
the archive key. The release workflow refreshes it on every `v*` tag.

## Why the vendored tree

Debian and Ubuntu build in a chroot with no network. `debian/rules` therefore
builds and tests with `--offline --locked` against `./vendor`, which
`packaging/vendor.sh` produces and `.cargo/config.toml` points at.

The archive does not accept vendored Rust dependencies for a source upload:
every crate has to be packaged as its own `librust-*-dev` package and the build
must use `dh-cargo` with `debian/cargo-checksum.json`. `anonify` needs `clap`,
`anyhow`, `serde`, `serde_json`, `rand`, `libc` and `zeroize` plus their
transitive crates; several are already in Debian, `rand 0.9` and its tree are
the main gap. Until that set is complete, the signed apt repository (binary
packages, not an archive upload) is the supported path on Debian and Ubuntu.
