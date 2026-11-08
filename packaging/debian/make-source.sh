#!/usr/bin/env bash
# Builds the Debian source package (orig + debian tarball + .dsc) that dput
# uploads. The work happens in a Debian trixie container so dpkg-source and the
# Rust toolchain match the target distribution. The package name and version
# are read from packaging/debian/changelog, so a version bump needs no edit
# here or anywhere else.
#
#   ./packaging/debian/make-source.sh [output-dir]      # default: dist/source
#   ./packaging/debian/make-source.sh -l [output-dir]   # build here, inside Debian
#
# Options:
#   -l   do not start a container; run packaging/debian/build-source.sh in the
#        current userland. Only for a Debian host that already has cargo,
#        dpkg-dev and debhelper installed.
#
# The result is unsigned: signing needs the maintainer's own GPG key.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
local_run=0

while getopts ":lh" opt; do
  case $opt in
    l) local_run=1 ;;
    h)
      awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "unknown option -$OPTARG (see -h)" >&2
      exit 2
      ;;
  esac
done
shift $((OPTIND - 1))

cd "$repo_root"
out=${1:-dist/source}
mkdir -p "$out"
out=$(cd "$out" && pwd)

git rev-parse --git-dir >/dev/null 2>&1 || {
  echo "error: run this from a git checkout of anonify" >&2
  exit 1
}

# Ship the tracked tree only. The working copy also holds build output and
# local artefacts (dist/, target/, graphify-out/, editor and agent files) that
# are gitignored and must never reach the orig tarball: dist/ even contains a
# previously built copy of this very source package.
srctar=$(mktemp -t anonify-src-XXXXXX.tar)
trap 'rm -f "$srctar"' EXIT
git ls-files -z |
  while IFS= read -r -d '' file; do [ -e "$file" ] && printf '%s\0' "$file"; done |
  tar --null --files-from=- --create --file="$srctar"

builder=$repo_root/packaging/debian/build-source.sh
if [ "$local_run" = 1 ]; then
  exec bash "$builder" "$srctar" "$out"
fi

engine=${CONTAINER_ENGINE:-}
if [ -z "$engine" ]; then
  engine=$(command -v podman || command -v docker || true)
fi
if [ -z "$engine" ]; then
  echo "error: install podman or docker, or run inside Debian with -l" >&2
  exit 1
fi

"$engine" run --rm \
  -v "$srctar":/src.tar:ro \
  -v "$out":/out \
  -v "$builder":/build-source.sh:ro \
  debian:trixie bash -c '
set -euo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  build-essential ca-certificates cargo debhelper dpkg-dev git rustc tar xz-utils
exec bash /build-source.sh /src.tar /out
'
