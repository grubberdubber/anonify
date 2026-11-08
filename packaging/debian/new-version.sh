#!/usr/bin/env bash
# Opens a new version in packaging/debian/changelog, so the tedious part of a
# release is only the bullet points.
#
#   ./packaging/debian/new-version.sh 1.0.1-1        # new upstream release
#   ./packaging/debian/new-version.sh 1.0.0-2        # Debian-only changes
#   ./packaging/debian/new-version.sh -b 1.0.1-1     # ...and build the source package
#   ./packaging/debian/new-version.sh -D noble 1.0.0-1~noble1   # for an Ubuntu PPA
#
# Options:
#   -D <dist>    distribution for the new entry (default: the current one)
#   -m <text>    first bullet point (default: derived from the version bump)
#   -b           run ./packaging/debian/make-source.sh afterwards
#
# The maintainer line is copied verbatim from the current entry, and the date is
# generated in UTC: this script never invents or rewrites an identity.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

changelog=packaging/debian/changelog
dist=
bullet=
build=0

while getopts ":D:m:bh" opt; do
  case $opt in
    D) dist=$OPTARG ;;
    m) bullet=$OPTARG ;;
    b) build=1 ;;
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

version=${1:-}
if [ -z "$version" ]; then
  echo "error: missing version, e.g. 1.0.1-1 (see -h)" >&2
  exit 2
fi

# Debian version grammar, narrowed to what this package uses.
if ! [[ $version =~ ^([0-9]+:)?[0-9][A-Za-z0-9.+~]*(-[A-Za-z0-9.+~]+)?$ ]]; then
  echo "error: '$version' is not a valid Debian version" >&2
  exit 2
fi
if [[ $version != *-* ]]; then
  echo "error: '$version' has no Debian revision; use e.g. ${version}-1" >&2
  echo "       (anonify ships a separate orig tarball, so it is not a native package)" >&2
  exit 2
fi

[ -f "$changelog" ] || { echo "error: $changelog not found" >&2; exit 1; }

package=$(sed -n '1s/^\([^ ]*\) (.*/\1/p' "$changelog")
current=$(sed -n '1s/^[^ ]* (\([^)]*\)).*/\1/p' "$changelog")
current_dist=$(sed -n '1s/^[^)]*) \([^;]*\);.*/\1/p' "$changelog")
trailer=$(grep -m1 '^ -- ' "$changelog" || true)

if [ -z "$package" ] || [ -z "$current" ] || [ -z "$current_dist" ] || [ -z "$trailer" ]; then
  echo "error: could not parse the top entry of $changelog" >&2
  exit 1
fi
if [ "$version" = "$current" ]; then
  echo "error: $package is already at $current" >&2
  exit 1
fi

who=${trailer# -- }
who=${who%%  *}
date=$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')
dist=${dist:-$current_dist}

upstream_new=${version#*:}
upstream_new=${upstream_new%-*}
upstream_current=${current#*:}
upstream_current=${upstream_current%-*}
if [ -z "$bullet" ]; then
  if [ "$upstream_new" != "$upstream_current" ]; then
    bullet="New upstream release $upstream_new."
  else
    bullet="Debian packaging update."
  fi
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
{
  printf '%s (%s) %s; urgency=medium\n\n' "$package" "$version" "$dist"
  printf '  * %s\n\n' "$bullet"
  printf ' -- %s  %s\n\n' "$who" "$date"
  cat "$changelog"
} >"$tmp"
# mktemp creates 0600; keep the mode the changelog already had.
mode=$(stat -c %a "$changelog" 2>/dev/null || echo 644)
chmod "$mode" "$tmp"
mv "$tmp" "$changelog"
trap - EXIT

echo "==> $changelog: $package ($version) $dist"
echo "    bullet points are a starting point; edit them before building"
echo
echo "next:"
if [ "$build" = 1 ]; then
  echo "  ./packaging/debian/make-source.sh"
  ./packaging/debian/make-source.sh
else
  echo "  ./packaging/debian/make-source.sh          # source package in dist/source"
fi
echo "  ./packaging/debian/upload.sh -k <keyid>    # lintian, sign, upload to mentors"
