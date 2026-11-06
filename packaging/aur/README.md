# AUR packaging

`PKGBUILD` builds anonify 1.0.0 from the `v1.0.0` git tag: the Linux engine
(`/usr/bin/anonify`) plus the portable browser binary
(`/usr/bin/anonify-browser`).

## Before publishing (needs your AUR account)

The package is ready, but pushing it is a manual step because it needs
credentials only the maintainer has:

1. Create an account at <https://aur.archlinux.org> and add your SSH public
   key to it.
2. Set `MAINTAINER` in the `PKGBUILD` header to your name and e-mail. AUR
   rejects placeholder maintainers.
3. Sanity-check the package locally (no build needed to validate metadata):

   ```bash
   cd packaging/aur
   makepkg --printsrcinfo > .SRCINFO   # regenerate after editing
   namcap PKGBUILD
   makepkg -si                          # full build + install test
   ```

4. Publish:

   ```bash
   git clone ssh://aur@aur.archlinux.org/anonify.git aur-anonify
   cp PKGBUILD .SRCINFO aur-anonify/
   cd aur-anonify && git add PKGBUILD .SRCINFO
   git commit -m "Initial import: anonify 1.0.0"
   git push
   ```

`sha256sums=('SKIP')` is correct here because the source is a VCS checkout
(`git+...#tag=v1.0.0`); AUR expects the tag to exist before the first push.

## Other channels

- `cargo install --path . --bins` (both binaries) or
  `cargo install --path . --bin anonify-browser`.
- GitHub Releases: the `Release` workflow builds and attaches the Linux
  glibc/musl archives and the Windows/macOS `anonify-browser` archives when a
  `v*` tag is pushed.
- Fedora/COPR: [`packaging/fedora`](../fedora/README.md).
- Debian/Ubuntu: [`packaging/debian`](../debian/README.md).
- Source build instructions: [`docs/install.md`](../../docs/install.md).
