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
  mv "%{buildroot}/lib/systemd/system/goddns-zoned.service" "%{buildroot}%{_unitdir}/" 2>/dev/null || true
  rm -rf "%{buildroot}/lib/systemd"
fi

install -Dm644 %{projectroot}/LICENSE %{buildroot}/usr/share/licenses/goddns/LICENSE

# drop-in dir for proxy vhost fragments (proxy.d/*.conf merged into the config)
mkdir -p "%{buildroot}/etc/goddns/proxy.d"

%files
%license /usr/share/licenses/goddns/LICENSE
%{_bindir}/goddns
%{_unitdir}/goddns.service
%{_unitdir}/goddns-zoned.service
%attr(0750,root,goddns) %dir /etc/goddns
%attr(2770,root,goddns) %dir /etc/goddns/proxy.d
%attr(0640,root,goddns) %config(noreplace) /etc/goddns/goddns.conf
%config(noreplace) /etc/logrotate.d/goddns

# shared examples (always overwritten on upgrade)
%dir %{_datadir}/goddns
%dir %{_datadir}/goddns/configs
%{_datadir}/goddns/configs/*
%dir %{_datadir}/goddns/scripts
%{_datadir}/goddns/scripts/*

%post
# config dir: root-owned but group-readable by the service user — the
# daemon runs as goddns and must be able to read goddns.conf. Secrets stay
# in goddns.env, which only systemd (root) reads via EnvironmentFile.
if [ -d /etc/goddns ]; then
    chown root:goddns /etc/goddns || true
    chmod 0750 /etc/goddns || true
fi
if [ -f /etc/goddns/goddns.conf ]; then
    chown root:goddns /etc/goddns/goddns.conf || true
    chmod 0640 /etc/goddns/goddns.conf || true
fi
# proxy vhost drop-in dir + seed the example template in place.
# 2770 root:goddns — setgid so fragments written by the CLI (as root) or the
# admin UI (as goddns) land group goddns and stay daemon-readable; group-write
# lets the admin UI manage vhosts.
mkdir -p /etc/goddns/proxy.d
chown root:goddns /etc/goddns/proxy.d || true
chmod 2770 /etc/goddns/proxy.d || true
# heal any fragment an older root CLI left root:root (would crash-loop the daemon)
chgrp goddns /etc/goddns/proxy.d/*.conf 2>/dev/null || true
chmod 0640 /etc/goddns/proxy.d/*.conf 2>/dev/null || true
if [ -f %{_datadir}/goddns/configs/vhost.conf.example ] && \
   [ ! -f /etc/goddns/proxy.d/vhost.conf.example ]; then
    install -m0640 -o root -g goddns \
        %{_datadir}/goddns/configs/vhost.conf.example \
        /etc/goddns/proxy.d/vhost.conf.example || true
fi

# secrets env file (GODDNS_TSIG_SECRET, GODDNS_ACME_TSIG_SECRET)
if [ ! -f /etc/goddns/goddns.env ]; then
    touch /etc/goddns/goddns.env
fi
chmod 0600 /etc/goddns/goddns.env

# state dir: SQLite token store + ACME storage, owned by the service user
mkdir -p /var/lib/goddns
chown goddns:goddns /var/lib/goddns
chmod 0750 /var/lib/goddns

# dedicated log files (log_file / access_log in goddns.conf); the
# unprivileged service cannot create files under /var/log itself
for lf in /var/log/goddns.log /var/log/goddns-access.log; do
    touch "$lf" 2>/dev/null || true
    chown goddns:goddns "$lf" || true
    chmod 0640 "$lf" || true
done

# $1 = 1 fresh install, >=2 upgrade. On upgrade: restart only if the
# service is actually running, and never touch the admin's enable state.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    if [ "$1" -eq 1 ]; then
        systemctl enable --now goddns.service || true
    elif systemctl is-active --quiet goddns.service; then
        systemctl restart goddns.service || true
    fi
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
