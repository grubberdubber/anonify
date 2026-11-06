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

docker run --rm -v "$PWD":/src:ro -v "$out":/out debian:trixie bash -c '
set -euo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  ca-certificates cargo dpkg-dev git rustc tar xz-utils

rm -rf /work && mkdir -p /work/src
tar -C /src -cf - --exclude=target --exclude=.git . | tar -C /work/src -xf -
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
dpkg-source -b .
cp /work/build/anonify_1.0.0-1.dsc /work/build/anonify_1.0.0.orig.tar.gz \
   /work/build/anonify_1.0.0-1.debian.tar.xz /out/
ls -l /out
'
