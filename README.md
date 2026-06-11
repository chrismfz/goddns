# goddns

Self-hosted Dynamic DNS for BIND, over RFC 2136 / TSIG. A single static Go
binary that runs an HTTPS endpoint on its own port (default **:8245**), maps
a bearer token to exactly one FQDN, and pushes a signed dynamic UPDATE to
`named`. Built to replace cPanel's Dynamic DNS web-call after the cpsrvd
X-Forwarded-For regression in 11.136.0.20 — without touching the CFM
DNAT/WAF stack.

> **New here? Start with [QUICKSTART.md](QUICKSTART.md)** — your own DynDNS
> from zero in ~10 minutes, self-issued TLS included, no certbot needed.

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

## Setup (recommended): a dedicated delegated DDNS zone

The recommended layout is to delegate a child zone (e.g. `ddns.myip.gr`)
and let goddns own it, instead of making your main zone dynamic:

- **`myip.gr` stays a normal static zone** — no journal, no
  `rndc freeze/thaw` dance, hand-edit as always.
- **One `wildcard` grant covers every future hostname**: adding
  `chris.ddns.myip.gr` is just `goddns token add` — no named.conf edit,
  no reload, ever.
- **Blast radius**: the TSIG key physically cannot touch anything outside
  `*.ddns.myip.gr`.

Steps on the BIND host (e.g. sdns):

1. Dedicated TSIG key (do NOT reuse the certbot rfc2136 key), then
   `include "/etc/named/ddns.key";` in `named.conf`:

       tsig-keygen -a hmac-sha256 ddns-update | sudo tee -a /etc/named/ddns.key

2. New zone in `named.conf` — the file MUST live under `/var/named/dynamic/`
   so named can create the journal next to it (see Troubleshooting):

       zone "ddns.myip.gr" {
           type master;
           file "dynamic/ddns.myip.gr.hosts";
           update-policy {
               grant ddns-update. wildcard *.ddns.myip.gr. A AAAA;
           };
       };

3. Zone file: copy `configs/ddns-zone.example` (shipped at
   `/usr/share/goddns/configs/ddns-zone.example`) to
   `/var/named/dynamic/ddns.myip.gr.hosts` and adjust the SOA/NS names.

4. Delegate it from the parent — one-time, static edit in `myip.gr.hosts`:

       ddns    IN NS   sdns.myip.gr.

5. Load it:

       named-checkconf -z /etc/named.conf && rndc reconfig

6. Install the goddns .deb/.rpm — it creates the `goddns` user,
   `/etc/goddns` (0750 root:goddns) and `/var/lib/goddns`. Put the TSIG
   secret in the env file:

       printf 'GODDNS_TSIG_SECRET=%s\n' "<base64 from ddns.key>" \
           | sudo tee /etc/goddns/goddns.env      # already chmod 0600

7. Edit `/etc/goddns/goddns.conf` (TLS — see below) and:

       sudo systemctl enable --now goddns

8. From now on, a new hostname is ONLY this — no BIND changes:

       goddns token add -fqdn chris.ddns.myip.gr -zone ddns.myip.gr -ttl 60
       goddns token add -fqdn vpn.ddns.myip.gr   -zone ddns.myip.gr -ttl 60

## Edge case: per-name grants in an existing zone

If you'd rather keep DDNS names directly in the main zone (an explicit
allowlist, no delegation), grant the key each name individually — see the
commented variant in `configs/named-update-policy.example`:

       zone "myip.gr" {
           ...
           update-policy {
               grant ddns-update. name chrisdns.myip.gr. A AAAA;
               grant ddns-update. name vpn.myip.gr.      A AAAA;
           };
       };

Trade-offs: every new hostname needs a named.conf edit + `rndc reconfig`,
and the zone becomes journal-managed — hand-edit afterwards only via
`rndc freeze myip.gr` / edit / `rndc thaw myip.gr`. The zone file must
also move under `/var/named/dynamic/` (journal, see Troubleshooting).

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

MikroTik: import `configs/mikrotik-ddns-minimal.rsc` — a one-shot import
that creates both the script and the 3-minute scheduler (edit the URL
first). `configs/mikrotik-ddns.rsc` is the verbose variant with logging.

**The URL is the credential.** A bare GET with a valid token performs an
update with the caller's source IP — that is the point of DDNS, but it also
means anything that fetches the URL flips your record. Chat apps
(Slack/Discord/Telegram/Teams) auto-fetch pasted links from their preview
bots, and some AV/browser products scan clipboard URLs. Never paste a full
update URL anywhere; if one leaks, `goddns token del` + `add` immediately.

## Reverse proxy mode (optional)

`proxy_enabled = true` turns on a second TLS listener (`proxy_listen`,
default `:443`) that routes by hostname to internal upstreams — built for
things that can never have a proper hostname + certificate on their own:
iDRAC/iLO/IPMI consoles, switches, UPSes.

    proxy_enabled = true
    proxy_listen  = ":443"

    [proxy."orion-idrac.internal.myip.gr"]
    upstream   = "https://10.23.201.200"     # reachable via LAN/VPN
    allow      = ["84.54.49.0/24"]           # client CIDRs — ALWAYS set for BMCs
    rate_limit = 10                          # req/s per client IP (burst 2x)

### DNS + certificates for the proxied names

The records never point at the 10.x addresses — every proxied name
resolves to the goddns host itself (which also avoids DNS-rebind
filtering). What you need depends only on the TLS mode:

**`tls_mode = "files"` with a wildcard cert (`*.internal.myip.gr`)** — the
simple case: **no new zone, no update keys, nothing dynamic.** One static
wildcard record in your existing zone and you're done:

    ; in myip.gr.hosts (static zone, no journal, no policy):
    *.internal    IN A    84.54.49.3        ; the goddns host

**`tls_mode = "acme"`** — each proxied host gets its own Let's Encrypt
cert, so goddns must be able to write `_acme-challenge.<host>` TXT
records. That needs a small dedicated **dynamic** zone, granted to the
**acme key only** — the `ddns-update` key is not involved anywhere:

    zone "internal.myip.gr" {
        type master;
        file "dynamic/internal.myip.gr.hosts";
        update-policy {
            grant acme-update. wildcard *.internal.myip.gr. TXT;
        };
    };

with the wildcard A living statically inside that zone file:

    $TTL 300
    @   IN SOA  sdns.myip.gr. hostmaster.myip.gr. (1 3600 900 604800 60)
        IN NS   sdns.myip.gr.
    *   IN A    84.54.49.3                  ; everything -> goddns

plus the one-time delegation in the parent: `internal IN NS sdns.myip.gr.`
Hosts added to the proxy table at runtime are picked up by the hot
reload, certs included — no restart.

**Adding proxy hosts to an existing DDNS zone** (no second zone): proxied
names can live straight in the `ddns.` zone you already run — and since
goddns owns that zone, it can create the DNS record itself, no
`rndc freeze`/named.conf involved:

    goddns token add -fqdn idrac.ddns.myip.gr -zone ddns.myip.gr
    curl "https://<goddns-host>:8245/update/<token>/<goddns-public-ip>"

then add the `[proxy."idrac.ddns.myip.gr"]` block. First-time
`proxy_enabled = true` needs one restart; everything after that is hot.
For acme certs in that zone, widen the policy once:
`grant acme-update. wildcard *.ddns.myip.gr. TXT;`

What you get per request: host-based routing, per-host client allowlist
(403), per-host per-IP rate limiting (429), an nginx-style access log line
(`proxy-access host peer "GET /" 200 11B 5ms`), upstream errors logged and
returned as 502, websocket/console streams proxied transparently, and
TLS ≥1.2 on the front regardless of how ancient the BMC behind it is.
`proxy_redirect_listen = ":80"` adds an http→https redirect. No root
needed for :80/:443 — the unit ships `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

What this is NOT: an edge/web-acceleration proxy. No caching, no
load-balancing, no WAF — for public web traffic keep angie/CFM in front.
This is an admin-plane proxy for a handful of consoles; treat the
`allow` list as mandatory, and prefer keeping it reachable only over
VPN when possible.

## Troubleshooting

**Service fails with `permission denied` on the config or cert.** The daemon
runs unprivileged (`User=goddns`). The package sets `/etc/goddns` to
root:goddns 0750 and `goddns.conf` to 0640 — but the **TLS cert** must also
be readable: `/etc/letsencrypt/live` and `archive` are root-only, so either
use the shipped certbot deploy hook to mirror the pair where goddns can read
it (recommended, keeps hot reload working):

    /usr/share/goddns/scripts/certbot-deploy-goddns.sh /etc/letsencrypt/live/<name>
    ln -s /usr/share/goddns/scripts/certbot-deploy-goddns.sh \
          /etc/letsencrypt/renewal-hooks/deploy/goddns.sh
    # goddns.conf: cert_file/key_file -> /etc/goddns/certs/{fullchain,privkey}.pem

or switch to `tls_mode = "acme"` (storage under /var/lib/goddns, owned by
the service user — no certbot involved at all).

**Updates fail with `SERVFAIL` (TSIG already accepted).** BIND could not
write the zone journal (`<zonefile>.jnl`). On EL systems `/var/named` is
root:named and NOT writable by named — dynamic zones must live in
`/var/named/dynamic/` (named-writable; also the SELinux-correct location):

    rndc freeze myip.gr 2>/dev/null || true
    mv /var/named/myip.gr.hosts /var/named/dynamic/
    # named.conf: file "dynamic/myip.gr.hosts";
    named-checkconf -z /etc/named.conf && systemctl reload named

Check `journalctl -u named | grep -iE 'journal|update'` to confirm — the
telltale line is `journal open failed: unable to create journal`.

**`REFUSED`** means the update-policy does not grant the key that exact
name/type; **`NOTAUTH`** means the TSIG key name/secret mismatch.

## If you ever front goddns with CFM

Leave `trusted_proxies` empty while goddns is exposed directly. Only if you
later put it behind CFM/nginx, set `trusted_proxies` to the proxy's source
IP(s); goddns then honours `X-Forwarded-For`, but only from those peers, and
walks the chain right-to-left to find the first untrusted hop — i.e. it does
the forwarded-header validation cpsrvd stopped doing.

## Roadmap

See `BACKLOG.md` — cPanel/DirectAdmin/Virtualmin write backends, admin HTTP
API, `goddns top` termui dashboard, per-zone TSIG keys.
