#!/usr/bin/env bash
# Low-level smoke test for the kernel features anonify relies on.
#
# Everything runs inside a private user, mount, network, and UTS namespace:
# host firewall, hostname, mounts, and interfaces are never touched. The
# privileged cargo tests also install nftables tables, but only when the test
# process is verifiably in a netns different from PID 1's.
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"

for cmd in unshare nft mount cargo; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        printf 'error: falta %s\n' "$cmd" >&2
        exit 1
    fi
done

if [ "$(id -u)" -eq 0 ]; then
    unshare_args=(-m -n -u)
else
    if ! unshare -rn true 2>/dev/null; then
        printf 'error: los namespaces de usuario no están disponibles; ejecuta este script como usuario normal o habilita unprivileged_userns_clone\n' >&2
        exit 1
    fi
    unshare_args=(-r -m -n -u)
fi

exec unshare "${unshare_args[@]}" --fork --kill-child -- bash -s <<'INNER'
set -euo pipefail

workdir=$(mktemp -d)
cleanup() {
    if mountpoint -q "$workdir/target" 2>/dev/null; then
        umount "$workdir/target" || true
    fi
    rm -rf "$workdir"
}
trap cleanup EXIT

# Inside the UTS namespace /proc/sys/kernel/hostname is writable even on
# minimal images that do not ship the `hostname` binary from inetutils.
printf '[*] hostname transitorio\n'
hostname_file=/proc/sys/kernel/hostname
if printf '' >>"$hostname_file" 2>/dev/null; then
    original_hostname=$(cat "$hostname_file")
    printf 'anonify-smoke-%s' "$$" >"$hostname_file"
    [ "$(cat "$hostname_file")" = "anonify-smoke-$$" ]
    printf '%s' "$original_hostname" >"$hostname_file"
else
    # Some container runtimes do not grant CAP_SYS_ADMIN in the new UTS
    # namespace even to uid 0; the module itself needs the same capability.
    printf '    aviso: UTS no escribible en este contenedor; se omite\n'
fi

printf '[*] nftables: crear, listar y borrar una tabla\n'
nft -f - <<'NFT'
table inet anonify_smoke {
  chain out {
    type filter hook output priority 0; policy drop;
  }
}
NFT
nft list table inet anonify_smoke >/dev/null
nft delete table inet anonify_smoke

printf '[*] bind mount privado\n'
printf 'anonify\n' >"$workdir/source"
printf 'original\n' >"$workdir/target"
mount --bind "$workdir/source" "$workdir/target"
[ "$(cat "$workdir/target")" = "anonify" ]
umount "$workdir/target"

printf '[*] sysctl de red por netns (si el kernel lo permite)\n'
sysctl_file=/proc/sys/net/ipv4/icmp_echo_ignore_all
if [ -w "$sysctl_file" ]; then
    old_value=$(cat "$sysctl_file")
    printf '1' >"$sysctl_file"
    [ "$(cat "$sysctl_file")" = "1" ]
    printf '%s' "$old_value" >"$sysctl_file"
else
    printf '    aviso: sysctl de red no escribible en este namespace; se omite\n'
fi

printf '[*] tests unitarios y de integración con nftables\n'
cargo test --offline --quiet -- --test-threads=1
printf '[✓] smoke test completo\n'
INNER
