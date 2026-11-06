# Debian / Ubuntu

These files are a `debian/` directory; Debian tooling expects it at the source
root, so copy it there when building:

```bash
# from the repo root, on a clean tag
./packaging/vendor.sh
tar -czf ../anonify_1.0.0.orig.tar.gz --exclude=target --exclude=.git .
cp -r packaging/debian .
dpkg-buildpackage -us -uc -b          # binary package
# or, to test the whole thing in a clean chroot:
sbuild -d unstable ../anonify_1.0.0-1.dsc
lintian ../anonify_1.0.0-1_amd64.changes
```

Resulting package: `anonify_1.0.0-1_amd64.deb` with both binaries.

## Why the vendored tree

Debian and Ubuntu build in a chroot with no network. The `rules` file therefore
builds and tests with `--offline --locked` against `./vendor`, which
`packaging/vendor.sh` produces and `.cargo/config.toml` points at.

## Getting into Debian proper

The archive does not accept vendored Rust dependencies: every crate must be
packaged as its own `librust-*-dev` package and the build must use `dh-cargo`
with `debian/cargo-checksum.json`. `anonify` depends on `clap`, `anyhow`,
`serde`, `serde_json`, `rand`, `libc` and `zeroize` (plus their transitive
crates); `clap` and `serde` are already in Debian, the rest would need
packaging or version work.

The realistic path, in order:

1. **A PPA / a `.deb` on the GitHub release** (this directory) — immediate.
2. **Debian mentors** (`mentors.debian.net`) once the crate set is packaged;
   a sponsor is required for the first upload.
3. **Ubuntu**: a PPA can carry the same binaries for a single distro series
   without waiting for the archive.

Step 1 is fully automated already: the `.deb` can be built in CI from the
vendored tarball and attached to the release. Steps 2 and 3 need an account
and a sponsor, which is where your approval is required.
