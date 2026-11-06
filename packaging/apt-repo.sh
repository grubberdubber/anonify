#!/usr/bin/env bash
# Builds a signed apt repository from a directory of .deb files.
#
#   ./packaging/apt-repo.sh <debs-dir> <output-dir>
#
# The signing key is taken from $APT_SIGNING_KEY (armored private key text) or
# from the default GnuPG keyring. The public half is published as
# anonify-archive-keyring.gpg so users can pin it with signed-by=.
set -euo pipefail

debs=${1:?usage: apt-repo.sh <debs-dir> <output-dir>}
out=${2:?usage: apt-repo.sh <debs-dir> <output-dir>}
suite=stable
component=main
arch=${APT_ARCH:-amd64}

mkdir -p "$out"
# The output directory may be a mount point, so empty it instead of removing it.
find "$out" -mindepth 1 -delete
mkdir -p "$out/pool/$component/a/anonify" "$out/dists/$suite/$component/binary-$arch"
cp "$debs"/*.deb "$out/pool/$component/a/anonify/"

if [ -n "${APT_SIGNING_KEY:-}" ]; then
  export GNUPGHOME
  GNUPGHOME=$(mktemp -d)
  printf '%s\n' "$APT_SIGNING_KEY" | gpg --batch --import
fi

{
  cd "$out"
  apt-ftparchive packages "pool/$component" > "dists/$suite/$component/binary-$arch/Packages"
  gzip -9 -kf "dists/$suite/$component/binary-$arch/Packages"

  apt-ftparchive \
    -o "APT::FTPArchive::Release::Suite=$suite" \
    -o "APT::FTPArchive::Release::Codename=$suite" \
    -o "APT::FTPArchive::Release::Components=$component" \
    -o "APT::FTPArchive::Release::Architectures=$arch" \
    -o "APT::FTPArchive::Release::Label=anonify" \
    -o "APT::FTPArchive::Release::Origin=anonify" \
    -o "APT::FTPArchive::Release::Description=anonify apt repository" \
    release "dists/$suite" > "dists/$suite/Release"

  gpg --batch --yes --armor --detach-sign -o "dists/$suite/Release.gpg" "dists/$suite/Release"
  gpg --batch --yes --clearsign -o "dists/$suite/InRelease" "dists/$suite/Release"
  gpg --batch --yes --export > anonify-archive-keyring.gpg
  gpg --batch --yes --armor --export > anonify-archive-keyring.asc
}

echo "repository ready in $out"
