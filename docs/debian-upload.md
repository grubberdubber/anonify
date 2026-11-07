# Getting anonify into Debian

This is the whole path, in order, with the exact commands. It is written for
the case where the uploader is not a Debian Developer yet, which is the normal
case for a new package. The other channels (snap, Flatpak, BlackArch,
crates.io) are in [distribution.md](distribution.md); Ubuntu and Kali are in
section 9 because they build on this Debian package.

Two things cannot be automated and are not optional:

1. The upload has to be **signed with your own OpenPGP key**, registered in
   your `mentors.debian.net` account. The signature is the authentication.
2. A **sponsor** (an existing Debian Developer) has to review the package and
   upload it to the Debian archive on your behalf. Nobody can do that for you;
   the best you can do is make the review easy.

There is also a technical blocker at the end of this document: Debian does not
accept vendored Rust dependencies in the archive. Read section 8 before you
promise yourself an upload date.

## 1. Install the tooling

On a Debian/Ubuntu machine (or inside a `debian:trixie` container):

```bash
sudo apt install devscripts dput dh-cargo lintian sbuild \
                 python3-debian reportbug gnupg
```

Configure your identity once, in `~/.devscripts`:

```bash
cat > ~/.devscripts <<'EOF'
DEBFULLNAME="Rodrigo Martinez"
DEBEMAIL="elgalacticoyt@gmail.com"
EOF
```

Every Debian tool picks the name and address from there. The `Maintainer:`
field of `packaging/debian/control` must match it exactly.

## 2. Create your OpenPGP key

Use a key tied to the address above, and keep it alive long enough (two years
is fine; you can extend it later):

```bash
gpg --quick-generate-key "Rodrigo Martinez <elgalacticoyt@gmail.com>" rsa4096 sign 2y
gpg --list-secret-keys --keyid-format long elgalacticoyt@gmail.com
gpg --armor --export elgalacticoyt@gmail.com > anonify-signing-key.asc
```

Note the fingerprint: it goes into the mentors account and into `debsign -k`.

Do not put this key in CI, do not share it, and do not reuse the archive key
that signs the apt repository in this project — that one only signs repository
metadata and is stored as a GitHub secret.

## 3. Create the mentors account

1. Go to <https://mentors.debian.net/> and sign up with `elgalacticoyt@gmail.com`.
2. In the control panel, add:
   - your **OpenPGP fingerprint** (the one from step 2),
   - your **SSH public key** (`~/.ssh/id_ed25519.pub`), used for ssh access to
     your package pages.
3. Wait for the confirmation email before uploading; uploads signed by an
   unknown key are rejected.

## 4. File the ITP bug

Debian wants to know the package is coming, and the archive upload has to close
this bug number. Either run:

```bash
reportbug --email elgalacticoyt@gmail.com wnpp
# choose "ITP" and fill the fields
```

or send this mail to `submit@bugs.debian.org`:

```
To: submit@bugs.debian.org
Subject: ITP: anonify -- temporary, reversible network privacy hardening

Package: wnpp
Severity: wishlist
Owner: Rodrigo Martinez <elgalacticoyt@gmail.com>

* Package name    : anonify
  Version         : 1.0.0
  Upstream Author : Rodrigo Martinez <elgalacticoyt@gmail.com>
* URL             : https://github.com/grubberdubber/anonify
* License         : GPL-3.0-only
  Programming Lang: Rust
  Description     : temporary, reversible network privacy hardening

 anonify layers network-anonymity hardening on a Linux machine and takes it
 back off again: randomized MAC and hostname, kernel hardening, IPv6 and DNS
 leak prevention, Tor or WireGuard behind a fail-closed nftables kill switch,
 and a per-application sandbox.
 .
 All state lives in /run (tmpfs) and in kernel runtime state, so a reboot or
 "anonify restore" returns the machine to its original configuration. It does
 not delete, alter or suppress logs, audit records, histories or evidence.
```

Save the bug number: it will be `#NNNNNN`, and the changelog entry must end
with `Closes: #NNNNNN`.

Be aware of what mentors says on its own front page: Debian is not a platform
to advertise software. A sponsor is much more likely to pick this up if the ITP
can point at real users asking for it (issue reports, distro forum threads,
the apt repository download count).

## 5. Build the source package

From a checkout of this repository:

```bash
./packaging/debian/make-source.sh dist/source
ls dist/source
# anonify_1.0.0-1.dsc
# anonify_1.0.0.orig.tar.gz
# anonify_1.0.0-1.debian.tar.xz
```

Then check it the way a sponsor will:

```bash
lintian --pedantic --fail-on error dist/source/anonify_1.0.0-1_source.changes
sbuild --dist=trixie dist/source/anonify_1.0.0-1.dsc     # clean chroot build
```

`sbuild` needs a chroot; create it once with `sudo sbuild-createchroot trixie
/srv/chroot/trixie-amd64 http://deb.debian.org/debian`.

## 6. Sign and upload

`dput` config (HTTPS, as documented by mentors):

```bash
cat > ~/.dput.cf <<'EOF'
[mentors]
fqdn = mentors.debian.net
incoming = /upload
method = https
allow_unsigned_uploads = 0
progress_indicator = 2
allowed_distributions = .*
EOF
```

The source package is uploaded as a `_source.changes`, which references the
`.dsc`, the `.orig.tar.gz` and the `.debian.tar.xz`. `debsign` signs both the
`.changes` and the `.dsc` it points at:

```bash
debsign -k elgalacticoyt@gmail.com dist/source/anonify_1.0.0-1_source.changes
```

Then upload:

```bash
dput mentors dist/source/anonify_1.0.0-1_source.changes
```

If the package is rejected, the confirmation email says why; fix it, bump the
version in `debian/changelog` (`dch -i`), rebuild, sign again and re-upload.
Use `dput -f` only after reading the error, never to force past a signature or
checksum failure.

Verify it is really there:

```bash
dget -x https://mentors.debian.net/debian/pool/main/a/anonify/anonify_1.0.0-1.dsc
```

## 7. Ask for a sponsor

Your upload page has an "RFS" template. Send it as a bug against the
`sponsorship-requests` pseudo-package:

```
To: submit@bugs.debian.org
Subject: RFS: anonify/1.0.0-1 -- temporary, reversible network privacy hardening

Package: sponsorship-requests
Severity: wishlist

Dear mentors,

I am looking for a sponsor for my package "anonify":

 * Package name     : anonify
   Version          : 1.0.0-1
   Upstream contact : Rodrigo Martinez <elgalacticoyt@gmail.com>
 * URL              : https://github.com/grubberdubber/anonify
 * License          : GPL-3.0-only
 * Vcs              : https://github.com/grubberdubber/anonify
   Section          : net

It builds those binary packages:

  anonify - temporary, reversible network privacy hardening

To access further information about this package, please visit:
  https://mentors.debian.net/package/anonify/

Changes since the last upload:

  * Initial release.
```

Then look at <https://mentors.debian.net/sponsors/> and pick two or three whose
stated interests match (privacy, networking, Rust). Do not mail the whole list.

## 8. The blocker a sponsor will hit: Rust dependencies

Debian's archive does not accept vendored crates. Every crate has to exist as
`librust-*-dev` in the archive, and the build must use `dh-cargo` with
`debian/cargo-checksum.json` instead of `cargo vendor`.

Current state of `anonify 1.0.0`:

| Crate | In Debian (unstable) | Usable |
|---|---|---|
| clap 4.6 | yes | yes |
| anyhow 1 | yes | yes |
| serde / serde_json | yes | yes |
| libc 0.2 | yes | yes |
| zeroize 1 | yes | yes |
| rand 0.9 | only 0.10.3 packaged | **no** |
| zerocopy 0.8 (via ppv-lite86) | to verify | unknown |

So a first upload to mentors will be reviewed as a *vendored* package and the
sponsor will very likely not forward it to the archive until the tree is
packaged or the dependency versions are adjusted.

The practical order that avoids wasted work:

1. Upload to mentors now anyway, to get review comments on policy, man pages,
   changelog, copyright and the rest. Those comments are worth having.
2. In parallel, port the code to `rand 0.10` (the API used here — `rand::rng()`,
   `random_range`, `rand::random` — is close to unchanged) so the version in
   Debian can satisfy the dependency.
3. Check the remaining transitive crates against
   <https://tracker.debian.org/pkg/rust-zerocopy> and friends; if one is
   missing, coordinate with the Debian Rust team (`debian-rust@lists.debian.org`)
   instead of packaging it alone.
4. Switch `debian/rules` to `dh-cargo` and drop `vendor/` from the source
   package. Only then ask a sponsor for the archive upload.

Until step 4 is done, the supported Debian/Ubuntu channel remains the signed
apt repository in `docs/install.md`.

## 9. Ubuntu and Kali

Both are downstream and need no separate package, but they need different
things from you.

**Ubuntu PPA** (builds in Launchpad, no sponsor, works today):

1. Create a Launchpad account at <https://launchpad.net> and import the same
   OpenPGP key (`gpg --armor --export <keyid>`), then confirm the encrypted
   email Launchpad sends.
2. Sign the Ubuntu Code of Conduct (required before any upload).
3. Build a PPA-specific source package: the changelog distribution must be an
   Ubuntu series, not `unstable`.

   ```bash
   cd anonify-1.0.0
   dch --distribution noble --force-distribution -v 1.0.0-1~noble1 "Rebuild for Ubuntu noble."
   dpkg-buildpackage -S -us -uc
   debsign -k elgalacticoyt@gmail.com ../anonify_1.0.0-1~noble1_source.changes
   dput ppa:grubberdubber/anonify ../anonify_1.0.0-1~noble1_source.changes
   ```

   `dput` needs `python3-launchpadlib` for the `ppa:` shortcut. Launchpad
   rebuilds the package in a clean chroot and emails you if it fails.
4. Users then install with `sudo add-apt-repository ppa:grubberdubber/anonify`.

**Kali**: Kali imports Debian packages, so the Debian upload is the prerequisite.
Two things speed it up:

- Once the package is in Debian testing, open a request at <https://bugs.kali.org>
  (product *Kali Packages*, type *New Package Request*) naming `anonify`, the
  upstream URL, the license and why it fits Kali (privacy/anonymity tooling).
- If you want it in a Kali metapackage, say which one in the same request
  (`kali-tools-anonymity` is the natural home); that decision belongs to the
  Kali team.

Do not maintain a Kali fork of the `.deb`: a patched copy of the Debian package
is the fastest way to have it dropped again.
