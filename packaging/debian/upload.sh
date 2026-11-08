#!/usr/bin/env bash
# Sign and upload the Debian source package from a non-Debian host.
#
#   ./packaging/debian/upload.sh -k elgalacticoyt@gmail.com          # sign + upload
#   ./packaging/debian/upload.sh -k <keyid> -s                       # sign only
#   ./packaging/debian/upload.sh -k <keyid> -f                       # re-upload after a rejection
#
# Everything runs in the anonify-deb-upload container (podman); the host only
# needs podman and gpg. The keyring is copied into tmpfs for the run: the
# container must not share ~/.gnupg with the host agent, which holds the
# keybox lock and makes gpg give up with "keydb_search failed: Connection
# timed out". The copy disappears when the run ends.
#
# Options:
#   -k <keyid>   OpenPGP key id or fingerprint (required unless -n is used)
#   -d <dir>     directory holding the *_source.changes (default: dist/source)
#   -s           sign only, do not upload
#   -n           check only: lintian, no signing, no upload
#   -f           force: upload again even if dput has a local *.upload log
#   -r           rebuild the container image before running
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
src_dir=$repo_root/dist/source
keyid=
mode=upload
rebuild=0
force=

while getopts ":k:d:snfrh" opt; do
  case $opt in
    k) keyid=$OPTARG ;;
    d) src_dir=$(cd -- "$OPTARG" && pwd) ;;
    s) mode=sign ;;
    n) mode=check ;;
    f) force=force ;;
    r) rebuild=1 ;;
    h) awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown option -$OPTARG (see -h)" >&2; exit 2 ;;
  esac
done

if [ "$mode" != check ] && [ -z "$keyid" ]; then
  echo "error: -k <keyid> is required to sign (see -h)" >&2
  exit 2
fi

mapfile -t changes_files < <(find "$src_dir" -maxdepth 1 -name '*_source.changes' -print)
if [ "${#changes_files[@]}" -ne 1 ]; then
  echo "error: expected one *_source.changes in $src_dir, found ${#changes_files[@]}" >&2
  echo "       run ./packaging/debian/make-source.sh $src_dir first" >&2
  exit 1
fi
changes=${changes_files[0]}

image=anonify-deb-upload:trixie
engine=${CONTAINER_ENGINE:-podman}
command -v "$engine" >/dev/null || { echo "error: $engine not found" >&2; exit 1; }

if [ "$rebuild" = 1 ] || ! "$engine" image exists "$image" >/dev/null 2>&1; then
  echo "==> building $image"
  "$engine" build -t "$image" -f "$repo_root/packaging/debian/Containerfile.upload" \
    "$repo_root/packaging/debian"
fi

gnupg=${GNUPGHOME_HOST:-$HOME/.gnupg}
if [ ! -d "$gnupg" ]; then
  echo "error: $gnupg does not exist; create your key first (gpg --quick-generate-key ...)" >&2
  exit 1
fi

# Sign from a throwaway copy of the keyring instead of bind-mounting the real
# one. Two gpg instances sharing a keybox fight over its lock, and the host
# gpg-agent keeps it while the container waits for the same file, so signing
# times out. tmpfs keeps the copy off disk.
shm=$(mktemp -d "${SHM_DIR:-/dev/shm}/anonify-gnupg-XXXXXX" 2>/dev/null || mktemp -d)
chmod 700 "$shm"
trap 'rm -rf "$shm"' EXIT
tar -C "$gnupg" -cf - --exclude='S.*' --exclude='*.lock' --exclude='.#lk*' . \
  | tar -C "$shm" -xf -

# Signing needs a terminal for the passphrase (pinentry-tty); signing without
# one would hang, so only attach a tty when the caller has one.
tty_flags=()
if [ -t 0 ]; then
  tty_flags=(-it)
fi

echo "==> $changes"
echo "==> mode: $mode"
"$engine" run --rm "${tty_flags[@]}" \
  --userns=keep-id \
  -e HOME=/tmp \
  -e GNUPGHOME=/gnupg \
  -v "$src_dir":/src:Z \
  -v "$shm":/gnupg:Z \
  "$image" "$(basename "$changes")" "${keyid:--}" "$mode" "$force"
