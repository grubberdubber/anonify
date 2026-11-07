#!/usr/bin/env bash
# Sign and upload the Debian source package from a non-Debian host.
#
#   ./packaging/debian/upload.sh -k elgalacticoyt@gmail.com          # sign + upload
#   ./packaging/debian/upload.sh -k <keyid> -s                       # sign only
#   ./packaging/debian/upload.sh -k -      -n                        # lintian only
#
# Everything runs in the anonify-deb-upload container (podman); the host only
# needs podman and gpg. Your ~/.gnupg is bind-mounted, never copied.
#
# Options:
#   -k <keyid>   OpenPGP key id or fingerprint (required unless -n is used)
#   -d <dir>     directory holding the *_source.changes (default: dist/source)
#   -s           sign only, do not upload
#   -n           check only: lintian, no signing, no upload
#   -r           rebuild the container image before running
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
src_dir=$repo_root/dist/source
keyid=
mode=upload
rebuild=0

while getopts ":k:d:snrh" opt; do
  case $opt in
    k) keyid=$OPTARG ;;
    d) src_dir=$(cd -- "$OPTARG" && pwd) ;;
    s) mode=sign ;;
    n) mode=check ;;
    r) rebuild=1 ;;
    h) sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
  -v "$gnupg":/gnupg:Z \
  "$image" "$(basename "$changes")" "${keyid:--}" "$mode"
