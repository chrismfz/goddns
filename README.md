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

MikroTik: import `configs/mikrotik-ddns.rsc`, paste your token, schedule
every 1–3 min.

**The URL is the credential.** A bare GET with a valid token performs an
update with the caller's source IP — that is the point of DDNS, but it also
means anything that fetches the URL flips your record. Chat apps
(Slack/Discord/Telegram/Teams) auto-fetch pasted links from their preview
bots, and some AV/browser products scan clipboard URLs. Never paste a full
update URL anywhere; if one leaks, `goddns token del` + `add` immediately.

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
