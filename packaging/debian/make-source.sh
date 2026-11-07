#!/usr/bin/env bash
# Builds the Debian source package (orig + debian tarball + .dsc) that dput
# uploads. Run it on the host; it does the work in a Debian trixie container so
# dpkg-source and the Rust toolchain match the target distribution.
#
#   ./packaging/debian/make-source.sh [output-dir]   # default: dist/source
#
# The result is unsigned: signing needs the maintainer's own GPG key.
set -euo pipefail

cd "$(dirname "$0")/../.."
out=${1:-dist/source}
mkdir -p "$out"
out=$(cd "$out" && pwd)

engine=${CONTAINER_ENGINE:-}
if [ -z "$engine" ]; then
  engine=$(command -v podman || command -v docker || true)
fi
[ -n "$engine" ] || { echo "error: install podman or docker" >&2; exit 1; }

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
git ls-files -z \
  | while IFS= read -r -d '' file; do [ -e "$file" ] && printf '%s\0' "$file"; done \
  | tar --null --files-from=- --create --file="$srctar"

"$engine" run --rm -v "$srctar":/src.tar:ro -v "$out":/out debian:trixie bash -c '
set -euo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  build-essential ca-certificates cargo debhelper dpkg-dev fakeroot git rustc tar xz-utils

rm -rf /work && mkdir -p /work/src
tar -C /work/src -xf /src.tar
cd /work/src
./packaging/vendor.sh

mkdir -p /work/build
tar --exclude=debian --exclude=target --exclude=.git \
  --transform "s,^\\.,anonify-1.0.0," \
  -czf /work/build/anonify_1.0.0.orig.tar.gz .
cd /work/build
tar -xzf anonify_1.0.0.orig.tar.gz
cp -r /work/src/packaging/debian anonify-1.0.0/debian
chmod +x anonify-1.0.0/debian/rules
cd anonify-1.0.0
# -S makes the source-only .changes that dput uploads; both it and the .dsc
# are signed afterwards with the maintainer key.
dpkg-buildpackage -S -us -uc
cp /work/build/anonify_1.0.0-1.dsc /work/build/anonify_1.0.0.orig.tar.gz \
   /work/build/anonify_1.0.0-1.debian.tar.xz /work/build/*_source.buildinfo \
   /work/build/*_source.changes /out/
ls -l /out
'
