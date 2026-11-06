# Fedora / COPR

The spec is [`anonify.spec`](anonify.spec). COPR's mock builds have no network,
so the source tarball carries the vendored crates:

```bash
# from the repo root, on a clean tag
./packaging/vendor.sh
tar -czf anonify-1.0.0-vendored.tar.gz \
    --exclude=target --exclude=.git .
sha256sum anonify-1.0.0-vendored.tar.gz
```

Attach that tarball to the GitHub release for the tag (the spec's `Source0`
points at `releases/download/v1.0.0/anonify-1.0.0-vendored.tar.gz`), then:

```bash
# one-time: COPR account at https://copr.fedorainfracloud.org, API token in
# ~/.config/copr, and `sudo dnf install copr-cli`
copr-cli create anonify \
    --chroot fedora-43-x86_64 --chroot fedora-43-aarch64 \
    --chroot fedora-rawhide-x86_64 \
    --description "Temporary, reversible network privacy hardening"
copr-cli build anonify \
    https://github.com/grubberdubber/anonify/releases/download/v1.0.0/anonify-1.0.0-vendored.tar.gz
```

Users then install with:

```bash
sudo dnf copr enable grubberdubber/anonify
sudo dnf install anonify
```

## Getting into Fedora proper

A package in the official repositories must build from Fedora's own packaged
crates, not a vendored tree, and must pass review. That means packaging the
crate dependencies as `rust-*` RPMs (`rust2rpm`, `fedpkg`, review in
Bugzilla). `anonify` depends on `clap`, `anyhow`, `serde`, `serde_json`,
`rand`, `libc` and `zeroize`; most are already in Fedora, so the review is
plausible but not instant. COPR is the right first step and is what the
command above does.

Build locally without COPR:

```bash
mkdir -p ~/rpmbuild/{SOURCES,SPECS}
cp anonify-1.0.0-vendored.tar.gz ~/rpmbuild/SOURCES/
cp packaging/fedora/anonify.spec ~/rpmbuild/SPECS/
rpmbuild -ba ~/rpmbuild/SPECS/anonify.spec
rpmlint ~/rpmbuild/SPECS/anonify.spec
```
