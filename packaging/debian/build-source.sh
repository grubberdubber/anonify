#!/usr/bin/env bash
# Builds the Debian source package that dput uploads: .dsc, .orig.tar.gz,
# .debian.tar.xz, _source.buildinfo and the _source.changes.
#
# This script runs *inside* a Debian userland: make-source.sh invokes it in a
# debian:trixie container, and the packaging CI job invokes it directly in one.
# Nothing here needs podman or docker.
#
#   build-source.sh <source-tarball> <output-dir>
#
# The package name and version come from packaging/debian/changelog, so bumping
# the version never requires editing this script or its callers. The result is
# unsigned: signing needs the maintainer's own GPG key.
set -euo pipefail

src_tar=${1:?source tarball required}
out=${2:?output directory required}
[ -f "$src_tar" ] || { echo "error: $src_tar does not exist" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/src"
tar -C "$work/src" -xf "$src_tar"
cd "$work/src"

changelog=packaging/debian/changelog
if [ ! -f "$changelog" ]; then
  echo "error: $changelog is missing from the source tarball" >&2
  echo "       package from a checkout of the repository" >&2
  exit 1
fi

package=$(dpkg-parsechangelog -l "$changelog" -S Source)
version=$(dpkg-parsechangelog -l "$changelog" -S Version)
if [ -z "$package" ] || [ -z "$version" ]; then
  echo "error: could not read Source/Version from $changelog" >&2
  exit 1
fi
# 1:2.0.0-1 -> 2.0.0; the Debian revision is whatever follows the last dash.
upstream=${version#*:}
upstream=${upstream%-*}
echo "==> $package $version (upstream $upstream)"

if [ ! -f Cargo.lock ]; then
  echo "error: Cargo.lock missing; the vendored tree would not be reproducible" >&2
  exit 1
fi

echo "==> vendoring crates"
./packaging/vendor.sh

mkdir -p "$work/build"
# --exclude=debian drops the top-level debian/ directory that Debian tooling
# expects to be absent from the upstream tarball, and with it packaging/debian,
# which is copied into the source package below. The working copy also holds
# build output and local artefacts that must never reach the orig tarball.
tar --exclude=debian --exclude=target --exclude=.git \
  --transform "s,^\.,${package}-${upstream}," \
  -czf "$work/build/${package}_${upstream}.orig.tar.gz" .

cd "$work/build"
tar -xzf "${package}_${upstream}.orig.tar.gz"
cp -r "$work/src/packaging/debian" "${package}-${upstream}/debian"
chmod +x "${package}-${upstream}/debian/rules"
cd "${package}-${upstream}"

# -S makes the source-only .changes that dput uploads; both it and the .dsc are
# signed afterwards with the maintainer key.
echo "==> dpkg-buildpackage -S"
dpkg-buildpackage -S -us -uc

mkdir -p "$out"
artifacts=("$work"/build/*.dsc "$work"/build/*.tar.* \
  "$work"/build/*_source.buildinfo "$work"/build/*_source.changes)
cp "${artifacts[@]}" "$out"/

# Drop artefacts of earlier versions from the output directory. They are
# regenerable build output, and a leftover *_source.changes makes upload.sh
# refuse to run because it expects exactly one.
keep=()
for f in "${artifacts[@]}"; do keep+=("$(basename "$f")"); done
shopt -s nullglob
for f in "$out/${package}"_*.dsc "$out/${package}"_*_source.buildinfo \
  "$out/${package}"_*_source.changes "$out/${package}"_*.tar.*; do
  name=$(basename "$f")
  prune=1
  for k in "${keep[@]}"; do
    if [ "$name" = "$k" ]; then prune=0; break; fi
  done
  if [ "$prune" = 1 ]; then
    echo "==> pruning stale $name"
    rm -f "$f"
  fi
done
shopt -u nullglob

ls -l "$out"
