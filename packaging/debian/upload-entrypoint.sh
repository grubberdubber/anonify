#!/usr/bin/env bash
# Runs inside the anonify-deb-upload image: lintian, then debsign, then dput.
#
#   upload-entrypoint <changes-file> <key-id|-> <check|sign|upload>
#
# GNUPGHOME is bind-mounted from the host, so the private key never leaves the
# machine and never enters the image.
set -euo pipefail

changes=${1:?changes file required}
keyid=${2:?-}
mode=${3:-check}

cd /src

echo "==> lintian"
lintian --pedantic --fail-on error "$changes"

if [ "$mode" = "check" ]; then
  echo "==> lintian clean, stopping before signing (check mode)"
  exit 0
fi

# A gpg-agent socket inherited from the host is not reachable from this
# namespace; drop it so gpg starts its own agent.
gpgconf --kill gpg-agent >/dev/null 2>&1 || true

echo "==> debsign ($keyid)"
debsign -k "$keyid" "$changes"

if [ "$mode" = "sign" ]; then
  echo "==> signed, stopping before upload (sign mode)"
  exit 0
fi

cat > /tmp/dput.cf <<'EOF'
[mentors]
fqdn = mentors.debian.net
incoming = /upload
method = https
allow_unsigned_uploads = 0
progress_indicator = 2
allowed_distributions = .*
EOF

echo "==> dput mentors"
dput -c /tmp/dput.cf mentors "$changes"
