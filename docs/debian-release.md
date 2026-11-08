# Publishing a new version

The expensive part is already done and does not repeat: the ITP
([#1153365](https://bugs.debian.org/1153365)), the request for sponsorship
([#1153443](https://bugs.debian.org/1153443)), the GPG key, the mentors account
and the NEW queue that the first accepted upload goes through. From here on,
every release is this runbook.

Two situations, same steps:

- **Now**: you upload to mentors, a sponsor uploads to Debian.
- **Later**: once you are a Debian Maintainer, `dput ftp-master` replaces the
  sponsor. Nothing else changes.

Getting the package *into* Debian for the first time is a different story; see
[`debian-upload.md`](debian-upload.md).

## 0. What the automation assumes

On the machine that builds:

```bash
podman --version        # or docker; the scripts pick whichever exists
gpg -K                  # your key, e.g. 498B2CF502101D9568CD38075F69CC5655D12B33
```

Nothing else. `make-source.sh` installs cargo, dpkg-dev, debhelper and lintian
inside a `debian:trixie` container, and `upload.sh` builds its own image for
lintian, debsign and dput. On a fresh machine the only things to restore are
the repository, podman/docker and the private key.

## 1. Decide the version

`<upstream>-<revision>`, e.g. `1.0.1-1`:

- new upstream code → bump the upstream part (`1.0.1-1`);
- packaging-only fix → bump the revision (`1.0.0-2`);
- Ubuntu PPA → add the series suffix (`1.0.1-1~noble1`) and a `-D noble` entry.

Never reuse a version that is already on mentors or in Debian: the archive
compares checksums and refuses a second, different upload of the same version.

## 2. Open the changelog entry

```bash
./packaging/debian/new-version.sh 1.0.1-1
# or, for an Ubuntu series:
./packaging/debian/new-version.sh -D noble 1.0.1-1~noble1
```

It writes the stanza with the package name, the maintainer line and the UTC
date, and picks a first bullet (`New upstream release 1.0.1.` when the upstream
part changed, `Debian packaging update.` otherwise). Edit the bullets to say
what actually changed, close ITP bugs only with `(Closes: #nnnnnn)`, and leave
the RFS bug alone: the sponsor closes it.

`-b` builds the source package in the same step, `-m "text"` sets the first
bullet from the command line.

## 3. Build the source package

```bash
./packaging/debian/make-source.sh          # -> dist/source
```

The package name and version come from `debian/changelog`, so there is nothing
to keep in sync. The result is unsigned:

```
dist/source/anonify_1.0.1-1.dsc            # the signed entry point of the upload
dist/source/anonify_1.0.1.orig.tar.gz      # upstream sources + vendored crates
dist/source/anonify_1.0.1-1.debian.tar.xz  # the debian/ directory
dist/source/anonify_1.0.1-1_source.buildinfo
dist/source/anonify_1.0.1-1_source.changes # what dput sends
```

Artefacts of earlier versions are pruned from `dist/source` automatically;
`upload.sh` refuses to run when it finds more than one `*_source.changes`.

## 4. Check before touching the network

```bash
./packaging/debian/upload.sh -k <keyid> -n     # lintian, no signing, no upload
```

Expect the known informational tags and no `E:`/`W:` lines:

```
P: anonify source: maintainer-manual-page [debian/man/anonify.1]
P: anonify source: source-contains-prebuilt-wasm-binary [vendor/wit-bindgen/...]
```

CI runs the same checks on every `v*` tag and on pull requests touching
`packaging/`, so this step mostly confirms the local state matches.

## 5. Sign and upload

```bash
./packaging/debian/upload.sh -k <keyid>
```

The script copies the keyring to `/dev/shm`, signs the `.changes` and the
`.dsc`, and calls `dput mentors`. You will be asked for the passphrase once.

Success looks like the `ACCEPTED on mentors (unstable)` mail and:

```bash
curl -sI https://mentors.debian.net/debian/pool/main/a/anonify/anonify_1.0.1-1.dsc
# HTTP/1.1 200 OK
```

If the upload was rejected (for example the signing key was not on a keyserver
yet), fix the cause and retry with `-f`. A `403 Forbidden` while *re-uploading a
version that is already published* is not a signing problem: the version is
there, check it and move on.

## 6. Tell the sponsor

The package is visible to sponsors in the mentors queue as soon as the mail
arrives. Give your sponsor something to work with:

- **before the first archive upload**, comment on the RFS bug
  [#1153443](https://bugs.debian.org/1153443) with the `dget` line and the
  changelog entry;
- **after the package is in Debian**, no RFS bug is needed: mail your sponsor
  directly, or upload yourself once you hold upload rights.

```
dget -x https://mentors.debian.net/debian/pool/main/a/anonify/anonify_1.0.1-1.dsc
```

## 7. Tag the release

The tag must match the upstream version in `debian/changelog`: the packaging
workflow checks it and fails on a mismatch, so a release cannot publish a `.dsc`
whose version disagrees with the tag.

```bash
git tag -a v1.0.1 -m "anonify 1.0.1"
git push origin v1.0.1
```

The `v*` tag also refreshes the signed apt repository described in
[`install.md`](install.md).

## 8. Follow it through

| Where | When | What |
|---|---|---|
| mentors page | immediately | `https://mentors.debian.net/package/anonify/` shows the new upload |
| `tracker.debian.org/pkg/anonify` | after the sponsor's upload | `404` becomes the package page; the first time it also waits in NEW |
| sponsor mail / `dak` | after ftpmaster approval | `Accepted` then `Installed`, with the version |
| RFS bug | closed by the sponsor | do not close it yourself |

## 9. When a sponsor asks for changes

1. Fix the packaging (or upstream) issue.
2. Bump the revision: `./packaging/debian/new-version.sh 1.0.1-2`.
3. Describe the fixes in the changelog bullets, not in a commit message.
4. Rebuild and re-upload: `./packaging/debian/make-source.sh` then
   `./packaging/debian/upload.sh -k <keyid>`.
5. Reply on the bug with the new `dget` line and the new changelog entry.

Do not amend or re-sign an already uploaded version; a new revision is the only
thing the archive accepts.

## Cheat sheet

```bash
./packaging/debian/new-version.sh 1.0.1-1       # changelog
./packaging/debian/make-source.sh               # dist/source
./packaging/debian/upload.sh -k <keyid> -n      # lintian only
./packaging/debian/upload.sh -k <keyid>         # sign + dput mentors
git tag -a v1.0.1 -m "anonify 1.0.1" && git push origin v1.0.1
```

Options worth remembering: `make-source.sh -h`, `new-version.sh -h`,
`upload.sh -h` (`-n` check, `-s` sign only, `-f` force re-upload, `-r` rebuild
the image).
