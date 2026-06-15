# goddns

**Own your dynamic DNS — and the front door to everything behind it.**

goddns is a single static Go binary that turns a BIND server you already
run into a self-hosted DynDNS service, and optionally into a TLS reverse
proxy for all the things that could never have a proper hostname,
certificate, or access control on their own.

- **Dynamic DNS server**: one bearer token = one hostname. Clients hit an
  HTTPS endpoint (plain `curl`, or the DynDNS2 protocol every router and
  MikroTik already speaks) and goddns pushes a signed RFC 2136 / TSIG
  update straight into your zone. `nochg` semantics keep aggressive cron
  clients free.
- **TLS without the usual fight**: serve an existing certificate with
  automatic pickup on renewal, or let goddns issue and renew its own
  Let's Encrypt certs via **DNS-01 through the same BIND** — it never
  needs ports 80/443, so it coexists with any web stack on the box.
- **Reverse proxy mode** (optional): hostname-routed TLS front for
  internal services — iDRAC/BMC consoles, NAS UIs, home services on
  dynamic IPs — with per-host CIDR allowlists, HTTP Basic auth (bcrypt),
  per-IP rate limiting, access logging and websocket passthrough.
  Combined with SSH reverse tunnels, it exposes a whole home LAN with
  **zero open ports** at home.
- **Operations-friendly**: flat TOML config, hot-reloaded while running
  (poll + SIGHUP, no restarts); pure Go (no cgo); .deb/.rpm packaging;
  hardened systemd unit running unprivileged; runs on its own port
  (default **:8245**, the historical DynDNS update port) so it drops onto
  any server without touching the existing web stack.

> **New here? Start with [QUICKSTART.md](QUICKSTART.md)** — your own DynDNS
> from zero in ~10 minutes, self-issued TLS included, no certbot needed.

| You want to… | Read |
|---|---|
| Stand up your own DynDNS from zero | [QUICKSTART.md](QUICKSTART.md) |
| Set up the recommended zone layout | [Dedicated delegated zone](#setup-recommended-a-dedicated-delegated-ddns-zone) |
| Create hostnames & tokens | [Manage records](#manage-records) |
| Point routers / MikroTik / cron at it | [Client usage](#client-usage) |
| Serve an existing cert, or self-issue via DNS-01 | [TLS](#tls) |
| Put TLS + auth in front of internal consoles (iDRAC, NAS…) | [Reverse proxy mode](#reverse-proxy-mode-optional) |
| Expose a home service on a dynamic IP | [DDNS + proxy together](#ddns--proxy-together-a-home-service-on-a-dynamic-ip) |
| Expose a whole LAN with zero open ports | [SSH reverse tunnels](#zero-open-ports-ssh-reverse-tunnels-the-whole-lan-not-just-one-box) |
| Manage records from a web dashboard | [Admin web UI](#admin-web-ui-optional) |
| Build .deb/.rpm packages | [Build & packaging](#build--packaging-cfm-style-workflow) |
| Something broke | [Troubleshooting](#troubleshooting) |

## Three ways to run it

1. **Just DDNS** — delegate a small zone (`ddns.example.com`), hand out
   tokens, point your routers at it. Your main zone stays static and
   untouched.
2. **Just the proxy** — one wildcard record (`*.internal.example.com`)
   pointing at goddns, one `[proxy]` block per internal service: real
   hostnames + real certs + auth in front of devices that deserve none of
   the trust they usually get.
3. **Both together** — a proxy rule's upstream can be one of your own DDNS
   names: `monitor.internal.example.com` → `chris.ddns.example.com:8443`
   follows your home IP wherever it moves, with zero propagation delay.

## Security model

The trust boundary is in **BIND**, not in this program. The TSIG key used by
goddns is granted rights via `update-policy` — typically over a small
dedicated zone (`ddns.example.com`), or over an explicit list of names.
A leaked token (or a compromised goddns) can at worst flap the IP of the
records inside that grant; it can never rewrite NS, MX, your main zone's
apex, or any other name.

Tokens are 256-bit random values; only their SHA-256 hash is stored in SQLite.
TSIG secrets are supplied via the systemd `EnvironmentFile`
(`/etc/goddns/goddns.env`, root-only), not the config file.

### TSIG keyring + rotation (`tsig_keys_file`)

Instead of keeping the TSIG secret in two places (named's key file *and*
goddns's env), point goddns at a single **goddns-owned key file** that named
also includes. It is the one source of truth, holds one or more keys, and
goddns can **rotate** a key in it with one command:

    # a goddns-owned key file, readable by named, writable by goddns:
    tsig-keygen -a hmac-sha256 ddns-update | sudo tee /etc/goddns/tsig.keys
    sudo chown goddns:named /etc/goddns/tsig.keys && sudo chmod 0640 /etc/goddns/tsig.keys
    sudo chmod 0751 /etc/goddns          # let the `named` user traverse to the one file
                                         # (0751 = search only; goddns.conf/env stay unreadable)

    # named.conf, once:
    include "/etc/goddns/tsig.keys";

    # goddns.conf — replaces tsig_secret / GODDNS_TSIG_SECRET:
    tsig_keys_file = "/etc/goddns/tsig.keys"
    tsig_name      = "ddns-update"

Then rotation is one keystroke. It is transactional — on any failure it rolls
the file back to the previous secret, so named, the file and the daemon stay
consistent (other keys in the file are untouched):

    sudo goddns rotate-key            # rotates tsig_name; `rotate-key <name>` for another
    # -> new secret -> rndc reconfig -> self-test -> reload goddns

The self-test sends a TSIG-signed query to a zone BIND actually serves and
requires a verified signed answer, so it can't pass on a stray/unsigned reply.
The command reloads the daemon (and it also watches the key file as a fallback),
so the new secret is live without a restart. The legacy `tsig_secret`/env path
still works when `tsig_keys_file` is unset.

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

### Edge case: one shared certbot wildcard for everything (files mode)

If you maintain a certbot wildcard you also distribute to other machines,
you can keep it as the single cert for goddns **and** the proxy names —
but remember: **wildcards match ONE label**. `*.myip.gr` covers
`sdns.myip.gr` but NOT `ha.internal.myip.gr`, so the browser will warn
until the cert also carries `*.internal.myip.gr`. Two steps, once:

1. Grant the certbot key the extra challenge name in the zone's
   `update-policy` (then `rndc reconfig`):

       grant acme-key name _acme-challenge.internal.myip.gr. TXT;

2. Expand the existing lineage — same files, one more SAN, nothing changes
   for whoever else consumes the wildcard:

       certbot certonly --cert-name myip.gr --dns-rfc2136 \
         --dns-rfc2136-credentials /etc/letsencrypt/rfc2136.ini \
         -d "myip.gr" -d "*.myip.gr" -d "*.internal.myip.gr" --expand

The deploy hook (`certbot-deploy-goddns.sh`) re-mirrors the pair to
`/etc/goddns/certs/` and goddns hot-reloads it at the next handshake — no
restarts anywhere. Verify with:

    openssl x509 -in /etc/goddns/certs/fullchain.pem -noout -ext subjectAltName

Note there is no "fallback to ACME" in files mode: the configured pair is
served for every SNI, matching or not. Per-host issuance is what
`tls_mode = "acme"` does.

## Admin web UI (optional)

A built-in dashboard, served as a vhost on the proxy listener (so it shares
the same TLS and port — no extra listener, no port games):

    [admin]
    enabled = true
    host    = "admin.myip.gr"
    allow   = ["84.54.49.0/24", "94.67.0.0/16"]
    users   = ["chris:$2a$10$..."]      # goddns passwd -user chris

It shows the DDNS records (last IP / last seen), the proxy table, and a tail
of the logs, and lets you **add / rotate / delete DDNS tokens** (proxy hosts
stay read-only — edit `goddns.conf`, it hot-reloads). Each record has a
**help** link with ready copy-paste client snippets (curl, cron, MikroTik,
router DynDNS2) for that hostname — set `public_host` so they're filled in
with your server name and port. Tokens are stored hashed and **can't be
shown again**; if one is lost, **rotate** mints a fresh token (the old one
stops working) and shows it once with the snippets filled in. The same is
available on the CLI: `goddns token rotate -fqdn home.ddns.myip.gr`.
DDNS tokens live in SQLite, so CRUD there is natural; full proxy CRUD would
mean moving proxy rules out of the hand-edited config, a deliberate non-goal
for now.

**It can rewrite DNS, so it is gated in depth** — a custom port would be
security theatre; layered auth is the real control:

1. **`allow`** — client CIDRs. A genuine packet filter, not obscurity.
2. **`basic_auth`** (optional) — an outer HTTP Basic gate so scanners never
   reach the login form. bcrypt only.
3. **login session** — `users` are the login credentials; a signed,
   `SameSite=Strict`, HttpOnly cookie. CSRF tokens on every mutating form.

So a single auth bug isn't game over, and every mutation is written to the
event log as an `admin-audit` line. The login form is **rate-limited per
client IP** (fail2ban-style: an attacking source locks itself out with
exponential backoff; legit accounts can't be locked out by others), on top
of bcrypt. Sessions are bound to the user's current credential, so changing
a password — or removing the user — invalidates their outstanding sessions
immediately. The session key is auto-created at `/var/lib/goddns/admin.secret`
(or set `GODDNS_ADMIN_SECRET`, min 16 bytes) and persists across restarts.
`users`/`allow`/`basic_auth` hot-reload; enabling or moving the vhost needs
a restart.

For an **internet-facing** admin host, set a restrictive `allow` and/or
`basic_auth` (goddns logs a warning at startup if both are empty) — the
login throttle protects the form, but a CIDR/Basic gate keeps unauthenticated
traffic away from it entirely.

DNS for the admin name is just a static record at your goddns host — e.g.
`admin.internal.myip.gr` already covered by the `*.internal` wildcard, or a
plain `admin IN A <goddns-ip>`. Keep it on your LAN/VPN where you can.

## Zones (read-only BIND introspection)

A read-only view of the BIND config — what zones exist, which are dynamic,
the TSIG keys, and a health check of the whole setup:

    goddns zones                 # CLI table + checks
    goddns zones -check          # + probe every zone's nameservers for serial agreement
    # …and the "zones" link in the admin dashboard ("check nameservers live" adds the same)

It does **not** edit anything. To stay robust it doesn't parse raw
named.conf (includes/views/comments make that fragile) — it runs
`named-checkconf -p`, i.e. BIND's own parser, and reads the normalised
output. The checks catch the exact foot-guns from day-to-day DDNS:

- a zone that grants a TSIG key which isn't defined (updates would be REFUSED)
- a zone that's dynamic via IP `allow-update` only (no key)
- goddns's own `tsig_name`/`tsig_secret` vs the key in named.conf — flags a
  missing key (REFUSED), a secret mismatch (NOTAUTH), or "✓ matches and is
  granted". Secrets are never printed.

The **CLI** run as root works out of the box. The **web page** needs the
goddns service user to be able to read named.conf and its includes — add it
to the `named` group once:

    usermod -aG named goddns && systemctl restart goddns

`named_conf` in the config overrides the path (default `/etc/named.conf`).

### Per-zone live view (AXFR)

The zones list shows *metadata*; to see the **actual records** of one zone:

    goddns zone home.myip.gr            # SOA/serial, NS, MX, every record + dynamic status
    goddns zone myip.gr -export         # loadable zone-file snapshot (a backup)
    goddns zone myip.gr -check          # + probe each NS live for the serial it serves
    # …or click a zone name in the admin "zones" page

The view always runs the offline **SOA-vs-NS** checks (is the SOA primary in the
NS set? do in-zone nameservers have glue?). `-check` (and the "check nameservers"
link in the admin page) adds the live probe: it queries every apex nameserver
directly for the zone's SOA and reports which serial each one serves — so a
secondary stuck on an old serial (the classic propagation foot-gun) shows up at
a glance instead of via manual `dig`. The nameservers are probed concurrently
with short timeouts. In-zone nameservers are reached via their glue; an
out-of-zone nameserver without glue is resolved through the configured
`dns_server`, so on a pure authoritative host (no recursion) such a nameserver
may show "no address" — point `dns_server` at a recursive resolver if you need
those resolved.

This reads the **live** zone straight from BIND over **AXFR** (zone transfer),
so for a dynamic zone you see the journal-merged contents — exactly what the
server answers — without `rndc freeze`/`thaw`. It's read-only: AXFR is a query.

It needs BIND to allow the transfer. goddns runs locally, so the simplest
one-time enablement covers every zone, in `options { }`:

    allow-transfer { localhost; };
    # or, key-only (no IP is opened — goddns authenticates with its TSIG key):
    allow-transfer { key "ddns-update."; };

goddns tries unauthenticated first, then falls back to the TSIG keys defined
in named.conf automatically (only when the server actually refuses, and
bounded by a deadline). If the transfer is refused, the command/page prints
exactly what to add. goddns never edits named.conf — enabling the transfer
is a deliberate one-line change you make yourself.

If a zone is **DNSSEC-signed**, the view flags it and the `-export` header
warns: the dump includes RRSIG/DNSKEY/NSEC(3), which expire and are managed
by BIND (inline-signing) — restore the unsigned source and let BIND re-sign
rather than re-importing the signed records by hand.

### Zone history (snapshots + diff)

The `serve` loop keeps a versioned history of **every** zone (not just the ones
goddns updates): it watches each zone's SOA serial and, whenever it moves,
transfers the zone and stores a canonical snapshot in the SQLite DB. Strictly
read-only — AXFR + SOA queries, never a write.

    goddns zone myip.gr -history     # list snapshots (serial, time)
    goddns zone myip.gr -diff        # what changed in the most recent snapshot

The admin per-zone page has a **history** link showing the same snapshot list
and the latest change inline.

This answers "who changed what, when" — e.g. a panel client editing their
MX/SPF/DKIM/DMARC and breaking mail: the diff shows exactly which records moved,
and the snapshot is the basis for a future rollback. It captures any master zone
BIND will transfer, including cPanel/DirectAdmin/Virtualmin file-managed ones,
without ever touching how they're managed. Tunables (defaults shown):

    history_interval = 300   # SOA poll period in seconds; 0 disables
    history_keep     = 50    # snapshots retained per zone

### Editing records (`goddns record`)

Edit arbitrary records in a **dynamic** zone via signed RFC2136 UPDATEs — any
type (A/AAAA/CNAME/MX/TXT/SRV/CAA…), not just DDNS A/AAAA. It shows a diff, asks
to confirm, and snapshots the zone first so the change is reversible:

    goddns record add    ddns.myip.gr 'vpn.ddns.myip.gr. 60 IN A 203.0.113.9'
    goddns record del    ddns.myip.gr 'vpn.ddns.myip.gr. 60 IN A 203.0.113.9'
    goddns record delset ddns.myip.gr mail.ddns.myip.gr MX     # delete a whole RRset
        -y    skip the confirmation prompt

Per the invariant it **refuses** a static/panel-managed zone (cPanel/DirectAdmin/
Virtualmin/hand-edited) and never converts one — it only touches zones that are
already dynamic and grant a TSIG key goddns holds, and it targets the
most-specific zone (a record for a delegated child isn't sent to the parent).
The right key is auto-selected from the keyring per the zone's `update-policy`.
goddns checks zone+key; **BIND's `update-policy` is the actual per-name/type
enforcer**, so the blast radius is exactly what that key is granted — an
out-of-policy edit is rejected by named (NOTAUTH/REFUSED). Every change is
snapshotted first (it refuses to mutate if it can't capture a restore point).

The same editing is in the **admin per-zone page**: dynamic zones show an "add
record" box and a `del` button per row, each with a CSRF-checked confirm + diff
(static/panel zones stay read-only). Audited, snapshotted, same invariant.

### Rolling back (`goddns record restore`)

Every record edit — and every external change BIND makes — is snapshotted (see
[history](#history)). Restore rolls a dynamic zone back to any snapshot:

    goddns record restore ddns.myip.gr          # list snapshots (with ids)
    goddns record restore ddns.myip.gr 41       # preview the delta, confirm, apply

It is a point-in-time **content** restore, not a serial rollback: it computes a
*forward* delta (records the snapshot had but live lost → add; records live
gained since → remove) and applies it as one signed UPDATE. The SOA serial keeps
moving forward and DNSSEC stays with BIND — replaying an old serial would break
secondaries and stale signatures would break validation, so SOA/RRSIG/NSEC*/
DNSKEY/CDS/CDNSKEY are left untouched. The restore is itself snapshotted first,
so it is undoable. The admin **history page** has a `restore` button per
snapshot (same confirm + diff, audited). This is the "the client broke their
DKIM at 14:00 — put it back" button.

## Logging

By default goddns logs to stderr (journald under systemd). On a busy DNS
host that journal is shared with named and friends, so the packaged config
sets a dedicated file:

    log_file   = "/var/log/goddns.log"
    access_log = "/var/log/goddns-access.log"

nginx-style split: `access_log` gets only the per-request `proxy-access`
lines, `log_file` keeps the events — DDNS updates, proxy errors/502s,
config reloads. Leave `access_log` empty to merge traffic into `log_file`;
leave both empty for journald. The package creates the files
(goddns:goddns 0640) and ships `/etc/logrotate.d/goddns` (weekly,
copytruncate). Both keys are hot-swappable — change/comment them and they
apply on the next reload tick.

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

### Drop-in vhost fragments (`proxy.d/`)

Besides the inline `[proxy."..."]` blocks above, goddns merges every
`/etc/goddns/proxy.d/*.conf` fragment into the config at load — the nginx
`conf.d` model. A fragment contains only `[proxy."..."]` sections; a host
defined twice (base file or another fragment) is rejected, and a broken
fragment fails the whole reload so the previous config keeps running. Your
hand-edited `goddns.conf` is never touched. The package installs a template at
`/etc/goddns/proxy.d/vhost.conf.example`:

    cp /etc/goddns/proxy.d/vhost.conf.example /etc/goddns/proxy.d/idrac.conf
    $EDITOR /etc/goddns/proxy.d/idrac.conf
    # picked up automatically within reload_interval (~20s), or now:
    systemctl reload goddns

The reload poll watches `proxy.d/` as well as `goddns.conf`, so adding or
editing a fragment is applied like an inline edit. A fragment that fails to
parse or validate is rejected as a whole and the **running config is kept** —
so a typo never takes the proxy (or DDNS) down on reload. One caveat: that
all-or-nothing applies at **startup** too — a broken fragment will stop
`goddns` from booting, so fix fragment errors via a reload (which keeps the old
config live and logs the offending file) before relying on a restart.

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

### DDNS + proxy together: a home service on a dynamic IP

The upstream of a proxy rule doesn't have to be an IP — **it can be one of
your own DDNS hostnames**. That combination gives a service running at
home (dynamic IP, no ports 80/443, self-signed at best) a stable public
name with a real certificate:

    you, anywhere ──► https://monitor.internal.myip.gr (goddns proxy, real cert)
                          │ resolves chris.ddns.myip.gr on the spot —
                          │ authoritatively, on this very server
                          ▼
                      https://chris.ddns.myip.gr:8443 (home, dynamic IP)

Worked example — LibreNMS on port 8443 behind a home connection:

1. The DDNS part you already have: the home router updates
   `chris.ddns.myip.gr` every few minutes (MikroTik script / cron).

2. On the home side: port-forward `8443` to the LibreNMS box, and — since
   the only legitimate client is the proxy — restrict the forward to the
   goddns server's IP in the router's firewall.

3. One proxy rule:

       [proxy."monitor.internal.myip.gr"]
       upstream   = "https://chris.ddns.myip.gr:8443"
       allow      = ["94.67.0.0/16"]      # who may reach LibreNMS
       rate_limit = 20
       # upstream_verify stays off: the home service is self-signed;
       # the *public* side still serves the proper cert.

4. DNS + cert for `monitor.internal.myip.gr` exactly as above (static
   wildcard A → goddns; wildcard cert or acme).

When the home IP changes, the DDNS update lands in BIND and the proxy
picks it up on the next connection — it resolves the upstream name through
the same server that is authoritative for it, so there is no propagation
delay and the record's TTL doesn't even matter locally. Established idle
connections to the old IP age out within ~90 seconds.

Works the same for anything at home: Home Assistant
(`upstream = "http://chris.ddns.myip.gr:8123"`), a NAS UI, an IP camera
NVR — one `[proxy]` block each, all behind real TLS on one stable name.

### Zero open ports: SSH reverse tunnels (the whole LAN, not just one box)

If you can't — or don't want to — open ports at home at all (CGNAT, or
simply as a safety net), flip the direction: one always-on Linux box at
home (a Raspberry Pi is plenty) dials OUT to the goddns server over SSH
and carries the traffic backwards. Nothing at home is addressable from
the internet; every request still passes the proxy's allow list / basic
auth / rate limit / access log.

The key detail: the `-R` forward target is **any address the home box can
reach**, not just itself. One box exposes the entire LAN:

    -R 127.0.0.1:15601:localhost:8443        # LibreNMS on the box itself
    -R 127.0.0.1:15602:192.168.1.50:80       # an IP camera elsewhere on the LAN
    -R 127.0.0.1:15603:192.168.1.60:5000     # the NAS UI
    -R 127.0.0.1:15604:192.168.1.1:443       # even the router's own admin page

Each `-R` makes the service appear on the goddns server as a loopback
port (15601…), which is exactly what the proxy rules point at. Pick a
port range convention (e.g. 156xx = chris-home) and it stays readable.

**On the goddns server (sdns)** — a dedicated tunnel-only account, locked
down to exactly those loopback ports:

    useradd -r -m -s /usr/sbin/nologin tunnel    # -N sessions never spawn the shell

    # /etc/ssh/sshd_config.d/tunnel.conf
    Match User tunnel
        AllowTcpForwarding remote
        PermitListen 127.0.0.1:15601 127.0.0.1:15602 127.0.0.1:15603 127.0.0.1:15604
        PermitTTY no
        X11Forwarding no
        AllowAgentForwarding no

    # ~tunnel/.ssh/authorized_keys — key restricted to forwarding only:
    restrict,port-forwarding ssh-ed25519 AAAA... homebox-tunnel

`PermitListen` pins the loopback ports this key may claim; default
loopback binding means only the local proxy can reach them.

**On the home box** — a systemd unit that keeps the tunnel alive:

    # /etc/systemd/system/sdns-tunnel.service
    [Unit]
    Description=reverse tunnel to sdns (no inbound ports at home)
    After=network-online.target
    Wants=network-online.target

    [Service]
    ExecStart=/usr/bin/ssh -N \
        -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes \
        -o StrictHostKeyChecking=accept-new \
        -i /etc/tunnel/id_ed25519 \
        -R 127.0.0.1:15601:localhost:8443 \
        -R 127.0.0.1:15602:192.168.1.50:80 \
        -R 127.0.0.1:15603:192.168.1.60:5000 \
        tunnel@sdns.myip.gr
    Restart=always
    RestartSec=10

    [Install]
    WantedBy=multi-user.target

`ExitOnForwardFailure=yes` + `Restart=always` is the self-healing pair:
if a forward can't be established the process exits and systemd retries.

**And the proxy rules** — one per service, exactly like any other upstream:

    [proxy."monitor.internal.myip.gr"]
    upstream   = "https://127.0.0.1:15601"
    basic_auth = ["chris:$2a$10$..."]
    rate_limit = 20

    [proxy."cam.internal.myip.gr"]
    upstream   = "http://127.0.0.1:15602"
    allow      = ["94.67.0.0/16"]
    basic_auth = ["chris:$2a$10$..."]
    rate_limit = 10

Adding another device later = one `-R` line, one `PermitListen` port, one
`[proxy]` block (hot-reloaded). A native `goddns tunnel` subcommand —
same model without sshd — is sketched in `BACKLOG.md`.

What you get per request: host-based routing, per-host client allowlist
(403), per-host HTTP Basic auth (401), per-host per-IP rate limiting
(429), an nginx-style access log line
(`proxy-access host peer "GET /" 200 11B 5ms`), upstream errors logged and
returned as 502, websocket/console streams proxied transparently, and
TLS ≥1.2 on the front regardless of how ancient the BMC behind it is.

**Basic auth** covers the case a CIDR allowlist can't: clients on CGNAT or
mobile networks with no stable source IP. Passwords are stored as bcrypt
hashes (the config refuses anything else); generate entries with:

    goddns passwd -user chris        # prompts, prints chris:$2a$10$...

    [proxy."monitor.internal.myip.gr"]
    upstream   = "https://chris.ddns.myip.gr:8443"
    rate_limit = 20                       # brute force hits 429 before auth
    basic_auth = ["chris:$2a$10$..."]     # instead of (or on top of) allow

When both `allow` and `basic_auth` are set, **both** must pass. The
`Authorization` header is consumed by goddns and never forwarded to the
upstream. Note: Basic sends the password on every request — it's fine
over the proxy's TLS, but treat it as a door lock for humans, not as a
substitute for the upstream's own login.
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

### Surviving manual edits on a dynamic BIND zone

The moment a zone has an `update-policy` (even just an ACME TXT grant) it
is **dynamic and journal-managed**, and three classic traps appear. Rules
learned the hard way:

- **Never edit-and-reload.** The only safe cycle is:

      rndc freeze <zone>                       # flush journal, pause updates
      $EDITOR zonefile                         # edit AND bump the serial
      named-checkzone <zone> /path/zonefile    # needs the file argument!
      rndc thaw <zone>                         # reload + fresh journal + NOTIFY

  `rndc reload <zone>` on a dynamic zone is *refused* by design
  ("dynamic zone"), and a bare `rndc reload` silently *skips* dynamic
  zones while reporting success — always verify with
  `dig +short SOA <zone> @localhost` afterwards.

- **`rndc: 'reload' failed: out of range`** = a stale journal that no
  longer matches the hand-edited file. Fix: `rndc freeze <zone>`,
  delete the `.jnl` next to the zone file, `rndc thaw <zone>`.

- **Slaves serve old data with the SAME serial.** Equal serial means "I'm
  current" — no transfer, ever. If you edited without bumping (or bumped
  before the final edit), the change is invisible to the world while
  `@localhost` looks fine. Bump again, thaw, then compare:

      for ns in localhost ns1.example.com ns2.example.com; do
        echo -n "$ns: "; dig +short SOA example.com @$ns
      done

  And remember public resolvers cache NXDOMAIN up to the SOA negative
  TTL — verify against the authoritative servers directly.

## If you ever front goddns with another proxy

Leave `trusted_proxies` empty while goddns is exposed directly — the safe
default. Only if you later put it behind a reverse proxy (CFM/angie/nginx),
set `trusted_proxies` to the proxy's source IP(s); goddns then honours
`X-Forwarded-For`, but only from those peers, and walks the chain
right-to-left to find the first untrusted hop — proper forwarded-header
validation instead of blind trust.

## Roadmap

See `BACKLOG.md` — cPanel/DirectAdmin/Virtualmin write backends, admin HTTP
API, `goddns top` termui dashboard, per-zone TSIG keys.
