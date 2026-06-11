Name:           goddns
Version:        2026.06.11
Release:        1.123332%{?dist}
Summary:        Self-hosted Dynamic DNS over RFC 2136 / TSIG
License:        Apache-2.0
URL:            https://nixpal.com
BuildArch:      x86_64
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Requires(pre): shadow-utils
Requires: ca-certificates

%description
goddns runs an HTTPS endpoint that maps bearer tokens to single DNS records
and pushes signed RFC 2136 dynamic updates to BIND. Includes a
DynDNS2-compatible endpoint for off-the-shelf router clients and optional
self-issued TLS via ACME DNS-01 (no port 80/443 needed).

%pre
# ---------------------------------------------------------------------------
# goddns system user and group
# getent guards make the calls idempotent across installs and upgrades.
# ---------------------------------------------------------------------------
if ! getent group goddns >/dev/null 2>&1; then
    groupadd --system goddns
fi

if ! getent passwd goddns >/dev/null 2>&1; then
    useradd \
        --system \
        --gid goddns \
        --no-create-home \
        --home-dir /var/lib/goddns \
        --shell /sbin/nologin \
        -c "goddns service account" \
        goddns
fi

%prep
# nothing

%build
# nothing

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}

if [ -d "%{pkgroot}/usr" ]; then
  cp -a "%{pkgroot}/usr" "%{buildroot}/"
fi
if [ -d "%{pkgroot}/etc" ]; then
  cp -a "%{pkgroot}/etc" "%{buildroot}/"
fi
if [ -d "%{pkgroot}/var" ]; then
  cp -a "%{pkgroot}/var" "%{buildroot}/"
fi

# ensure canonical shared assets are always shipped, even if %{pkgroot} staging omitted them
mkdir -p "%{buildroot}%{_datadir}/goddns"
if [ -d "%{projectroot}/configs" ]; then
  rm -rf "%{buildroot}%{_datadir}/goddns/configs"
  cp -a "%{projectroot}/configs" "%{buildroot}%{_datadir}/goddns/configs"
fi
if [ -d "%{projectroot}/scripts" ]; then
  rm -rf "%{buildroot}%{_datadir}/goddns/scripts"
  cp -a "%{projectroot}/scripts" "%{buildroot}%{_datadir}/goddns/scripts"
fi

if [ -f "%{buildroot}/lib/systemd/system/goddns.service" ]; then
  mkdir -p "%{buildroot}%{_unitdir}"
  mv "%{buildroot}/lib/systemd/system/goddns.service" "%{buildroot}%{_unitdir}/"
  rm -rf "%{buildroot}/lib/systemd"
fi

install -Dm644 %{projectroot}/LICENSE %{buildroot}/usr/share/licenses/goddns/LICENSE

%files
%license /usr/share/licenses/goddns/LICENSE
%{_bindir}/goddns
%{_unitdir}/goddns.service
%attr(0700,root,root) %dir /etc/goddns
%attr(0640,root,root) %config(noreplace) /etc/goddns/goddns.conf

# shared examples (always overwritten on upgrade)
%dir %{_datadir}/goddns
%dir %{_datadir}/goddns/configs
%{_datadir}/goddns/configs/*
%dir %{_datadir}/goddns/scripts
%{_datadir}/goddns/scripts/*

%post
# /etc/goddns may hold TSIG secrets — force 0700 on upgrade too.
[ -d /etc/goddns ] && chmod 0700 /etc/goddns || true

# secrets env file (GODDNS_TSIG_SECRET, GODDNS_ACME_TSIG_SECRET)
if [ ! -f /etc/goddns/goddns.env ]; then
    touch /etc/goddns/goddns.env
fi
chmod 0600 /etc/goddns/goddns.env

# state dir: SQLite token store + ACME storage, owned by the service user
mkdir -p /var/lib/goddns
chown goddns:goddns /var/lib/goddns
chmod 0750 /var/lib/goddns

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable goddns.service || true
    systemctl restart goddns.service || true
fi

%preun
if [ $1 -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop goddns.service || true
    systemctl disable goddns.service || true
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
