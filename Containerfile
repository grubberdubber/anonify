FROM archlinux
RUN pacman -Syu --noconfirm --disable-download-timeout rust gcc tor nftables wireguard-tools openresolv iproute2 curl bind tcpdump iputils inetutils diffutils procps-ng bubblewrap util-linux \
 && systemd-sysusers; id tor
