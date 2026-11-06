# Fedora / COPR spec for anonify.
#
# COPR builds in mock, which has no network. The source tarball must therefore
# contain ./vendor and ./.cargo/config.toml (see packaging/vendor.sh); the
# build uses --offline --locked so a missing crate fails loudly instead of
# silently reaching for the network.
#
# Build locally:  rpmbuild -ba packaging/fedora/anonify.spec
# Submit to COPR: see packaging/fedora/README.md

Name:           anonify
Version:        1.0.0
Release:        1%{?dist}
Summary:        Temporary, reversible network privacy hardening

License:        GPL-3.0-only
URL:            https://github.com/grubberdubber/anonify
Source0:        %{url}/releases/download/v%{version}/%{name}-%{version}-vendored.tar.gz
ExclusiveArch:  x86_64 aarch64

# Rust 1.85 is the MSRV (edition 2024); Fedora 41+ ships a newer toolchain.
BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc

# The engine drives these tools at runtime; nothing is bundled or patched.
Requires:       nftables
Requires:       iproute2
Requires:       util-linux

Recommends:     tor
Recommends:     wireguard-tools
Recommends:     NetworkManager
Recommends:     bubblewrap
Recommends:     curl

%description
anonify layers temporary, reversible network-anonymity hardening on Linux:
randomized MAC and hostname, sysctl hardening, IPv6 and DNS leak prevention,
Tor or WireGuard behind a fail-closed nftables kill switch, local discovery
silencing, a leak audit and a per-application sandbox.

All state lives in /run/anonify (tmpfs) and in kernel runtime state.
`anonify restore` (or a reboot) returns the machine to its original
configuration. It never deletes, alters or suppresses logs, audit records,
histories, timestamps or evidence.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release --locked --offline --bins

%install
install -Dpm0755 target/release/anonify %{buildroot}%{_bindir}/anonify
install -Dpm0755 target/release/anonify-browser %{buildroot}%{_bindir}/anonify-browser

%check
cargo test --release --locked --offline

%files
%license LICENSE
%doc README.md CHANGELOG.md docs/install.md docs/stability.md docs/platforms.md
%{_bindir}/anonify
%{_bindir}/anonify-browser

%changelog
* Fri Nov 06 2026 anonify maintainers <grubberdubber@users.noreply.github.com> - 1.0.0-1
- Initial package: reversible network anonymity hardening, `doctor` preflight,
  portable `anonify-browser`.
