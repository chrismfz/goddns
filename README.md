# goddns

Self-hosted Dynamic DNS for BIND, over RFC 2136 / TSIG. A single static Go
binary that runs an HTTPS endpoint on its own port (default **:8245**), maps
a bearer token to exactly one FQDN, and pushes a signed dynamic UPDATE to
`named`. Built to replace cPanel's Dynamic DNS web-call after the cpsrvd
X-Forwarded-For regression in 11.136.0.20 — without touching the CFM
DNAT/WAF stack.

## Why this exists

cPanel's `/cpanelwebcall/` DDNS records the client IP. After 11.136.0.20,
cpsrvd stopped trusting `X-Forwarded-For` from its own loopback proxy, so every
record now resolves to `127.0.0.1`. goddns sidesteps it entirely: it listens
on its own dedicated port, so it is never behind a proxy unless you choose to
put it behind one — the TCP peer IP is the real client, no forwarded-header
trust needed. The dedicated port (8245, the historical DynDNS update port)
also makes it portable: it can be dropped onto any server, including cPanel
boxes, without fighting for 80/443.

## Security model

The trust boundary is in **BIND**, not in this program. The TSIG key used by
goddns is granted, via `update-policy`, the right to modify *only the specific
DDNS hostnames* you list — nothing else in the zone. A leaked token (or a
compromised goddns) can at worst flap the IP of those exact records; it can
never rewrite NS, MX, the apex, or any other name.

Tokens are 256-bit random values; only their SHA-256 hash is stored in SQLite.
TSIG secrets are supplied via the systemd `EnvironmentFile`
(`/etc/goddns/goddns.env`, root-only), not the config file.

## Build & packaging (cfm-style workflow)

    make help               # self-documenting target list
    make setup              # first-time: go mod tidy
    make build              # CGO_ENABLED=0 static binary -> ./bin/goddns
    make test               # unit tests (incl. in-process TSIG UPDATE server)
    make deb                # -> build/deb/goddns_YYYY.MM.DD-HHMMSS-1_amd64.deb
    make rpm                # -> packaging/rpm/RPMS/x86_64/goddns-*.rpm
    make sync               # rsync latest deb+rpm to repo.nixpal.com
    make release            # deb+rpm+checksums -> GitHub release (gh)

Date-based versioning, fakeroot/dpkg-deb and rpmbuild staging, remote repo
sync and `gh` release flow are all cloned from the cfm Makefile. Pure-Go
SQLite (modernc.org/sqlite) — no cgo, no libc dependency.

## Setup on a BIND host (e.g. sdns)

1. Dedicated TSIG key (do NOT reuse the certbot rfc2136 key):

       tsig-keygen -a hmac-sha256 ddns-update | sudo tee -a /etc/named/ddns.key

2. In `named.conf`: `include "/etc/named/ddns.key";` and add an
   `update-policy` to the zone granting that key the DDNS names only
   (see `configs/named-update-policy.example`). Then `rndc reload`.

   Note: once a zone is dynamic it is journal-managed. To hand-edit later:
   `rndc freeze myip.gr` / edit the file / `rndc thaw myip.gr`.

3. Install the .deb/.rpm — it creates the `goddns` user, `/etc/goddns`
   (0700) and `/var/lib/goddns`. Put the TSIG secret in the env file:

       printf 'GODDNS_TSIG_SECRET=%s\n' "<base64 from ddns.key>" \
           | sudo tee /etc/goddns/goddns.env      # already chmod 0600

4. Edit `/etc/goddns/goddns.conf` (TLS — see below) and:

       sudo systemctl enable --now goddns

## TLS

Two modes, chosen with `tls_mode`:

- **`files`** (default): point `cert_file`/`key_file` at an existing cert,
  e.g. the wildcard you already distribute via rrsync, or a certbot live
  pair. goddns re-checks the file at every TLS handshake and hot-reloads it
  when certbot renews — **no restart, no reload needed**.

- **`acme`**: goddns issues and renews its own Let's Encrypt certificate
  using the **DNS-01** challenge — it writes the `_acme-challenge` TXT
  record through the same BIND over RFC2136/TSIG. It never needs port
  80/443, so it works on any server (including cPanel boxes where those
  ports are taken). Renewals happen in the background and are served from
  memory — again no restart. Grant the TXT right to a dedicated key
  (`acme_tsig_name`) as shown in `configs/named-update-policy.example`,
  and test with the staging CA first (`acme_ca`).

## Config hot reload

`/etc/goddns/goddns.conf` is polled cfm-style (mtime+SHA-256, every
`reload_interval` seconds; `systemctl reload goddns` / SIGHUP forces it).
TSIG key/secret, `dns_server`, `trusted_proxies` and `reload_interval`
apply live. Changes to `listen`, `tls_mode`, cert paths, `acme_*` or
`db_path` are detected and logged as needing a restart.

## Manage records

    goddns token add  -fqdn home.myip.gr -zone myip.gr -ttl 60   # prints token once
    goddns token list
    goddns token del  -fqdn home.myip.gr

The FQDN must also appear in the zone's `update-policy`, otherwise BIND will
(correctly) refuse the update.

## Client usage

Simple (server reads the source IP from the connection — the public IP as seen
on the wire, which is exactly what you want for DDNS):

    curl "https://sdns.myip.gr:8245/update/<token>"
    curl "https://sdns.myip.gr:8245/update/<token>?ip=203.0.113.10"   # explicit
    curl "https://sdns.myip.gr:8245/update/<token>/203.0.113.10"      # path style

DynDNS2-compatible (for off-the-shelf router clients):

    https://sdns.myip.gr:8245/nic/update?hostname=home.myip.gr&myip=<ip>
    (token as HTTP Basic password, or ?token=)

Responses follow DynDNS2 conventions: `good <ip>`, `nochg <ip>`, `badauth`,
`nohost`. `nochg` skips the DNS write entirely, so a 1-minute cron causes no
zone churn.

MikroTik: import `configs/mikrotik-ddns.rsc`, paste your token, schedule
every 1–3 min.

## If you ever front goddns with CFM

Leave `trusted_proxies` empty while goddns is exposed directly. Only if you
later put it behind CFM/nginx, set `trusted_proxies` to the proxy's source
IP(s); goddns then honours `X-Forwarded-For`, but only from those peers, and
walks the chain right-to-left to find the first untrusted hop — i.e. it does
the forwarded-header validation cpsrvd stopped doing.

## Roadmap

See `BACKLOG.md` — cPanel/DirectAdmin/Virtualmin write backends, admin HTTP
API, `goddns top` termui dashboard, per-zone TSIG keys.
