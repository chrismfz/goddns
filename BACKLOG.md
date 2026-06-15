# goddns backlog

v1 is deliberately lean: serve + CLI token management + cfm-style config
hot-reload + deb/rpm packaging. Everything below is planned but explicitly
out of v1 scope.

## Roadmap: from read-only introspection to a zone-management layer

The read-only introspection shipped so far (zone viewer, AXFR export, SOA/NS
and delegation checks, live per-nameserver serial check) is the ground floor of
a bigger building: a zone-management layer over BIND — versioned history,
scoped record CRUD, health-driven automation, and eventually a multi-tenant API
(e.g. a zonecloud.io connector). It is built in phases so the blast radius and
the trust model grow deliberately, not all at once.

### Hard invariant (applies to EVERY phase): goddns never changes a zone's ownership model

goddns MUST NOT convert a zone to dynamic on its own (i.e. never add an
`update-policy` to a zone that doesn't have one). File-managed zones belong to
other systems — **cPanel, DirectAdmin, Virtualmin, or the operator's own
`nano` + `rndc reload`** — and those systems write the zone *file* directly.
Turning such a zone dynamic makes BIND serve a file/journal mix, so the panel's
(or operator's) file edits and goddns's journal updates diverge: it
re-introduces the exact `rndc freeze/thaw`, `tmp-*` orphan and "journal out of
range" foot-guns this project exists to remove, and silently fights the panel's
own DNS management.

Instead goddns DETECTS who owns each zone (it already classifies dynamic vs
static-file from `named-checkconf -p`) and picks the matching mechanism — or
refuses and stays read-only:

- **dynamic zone** → RFC 2136 `UPDATE`, scoped by the zone's `update-policy`.
- **panel-managed zone** → the panel's API backend (see "Write backends below"),
  never the file/journal.
- **hand-edited static zone** → strictly read-only (history/diff/audit only).

Converting a zone to dynamic is always an explicit, informed operator decision
— never something goddns does to "make CRUD work".

### Phase 1 — History / diff / audit (read-only; highest value-to-risk)

Snapshot each zone (canonical AXFR — exactly what `goddns zone <name> -export`
already produces) on every detected change (SOA-serial bump), store the
snapshots (the existing SQLite store, or a `.d/` of zone files), and show diffs.
Answers "what changed in this zone, when, and from what" — the killer feature
for the *cPanel client broke their DKIM / SPF / DMARC / MX (Outlook/Gmail
stopped working)* scenario. 100% read-only, zero new write risk, and the
foundation every later phase needs: it is the "undo" that makes CRUD safe.
- trigger: poll SOA serials; on change, AXFR + store + diff vs the previous snapshot.
- surface: per-zone history + diff in the admin UI and `goddns zone <name> -history` / `-diff`; retention/pruning policy.

Phase 2 has two distinct CRUD tracks that share the admin auth + audit
substrate but write very different things, with different trust models:

### Phase 2A — Scoped BIND record CRUD via UPDATE (dynamic zones only)

Add / edit / delete arbitrary RR types (A/AAAA/CNAME/MX/TXT/SRV…) on zones that
are ALREADY dynamic, via RFC 2136 `UPDATE` — never file rewrites. Includes the
already-sketched `rotate-key` (rotate goddns's own TSIG secret in its dedicated
key include file + its own config + `rndc reconfig`). Every write is gated by
admin auth + a confirmation/diff preview and takes an automatic Phase-1 snapshot
first, so rollback is one click. Per the invariant it REFUSES on non-dynamic
zones, pointing the operator at the panel backend or an explicit conversion.
The trust boundary is BIND's `update-policy`; blast radius stays bounded by what
the key grants.

### Phase 2B — goddns-owned object CRUD (proxy vhosts) — SHIPPED

A SEPARATE track: CRUD of goddns's OWN config objects, not BIND records. It
writes only goddns state, so the trust model is self-contained (admin auth, no
BIND/panel invariant). DDNS tokens already work this way (SQLite, full CRUD);
this brought the proxy vhosts up to the same.

- **Proxy vhosts → managed `proxy.d/` fragments** — DONE (`internal/vhostmut`,
  `goddns vhost list|set|del`, admin add/edit/del). The nginx `conf.d` model:
  the hand-authored `goddns.conf` stays 100% operator-owned; the UI/CLI writes
  ONLY `proxy.d/<host>.conf` TOML fragments (one vhost per file), validated
  before write and applied atomically (temp + rename + fsync). A vhost defined
  in the base config — or in a fragment goddns didn't name `<host>.conf` — is
  reported as not-managed and refused for set/del (the ownership invariant).
  An immediate reload (SIGHUP) follows a UI write; the loader already merges
  base + fragments and rejects a broken fragment as a whole, keeping the
  previous config live. This also closed the older "Proxy CRUD from the UI" item.
- **Tunnels → NOT building a native `goddns tunnel`.** The supported path is
  **SSH reverse tunnels**, fully documented in the README (a dedicated
  forwarding-only `tunnel` account + a `systemd` keep-alive unit, proxy upstream
  pointed at the local tunnel end). It needs zero new moving parts in goddns and
  the proxy already does everything in front of it (TLS, allow, basic_auth,
  rate-limit, access log). The native-tunnel sketch below is kept only as a
  someday-maybe; there is no plan to build it.

### Phase 3 — Health-driven automation (failover / round-robin / IP checks)

A control loop: read (health-check an endpoint) → write (flip / rotate the
A/CNAME via the Phase-2 `UPDATE` primitive) over a specific, configured record
set. This is "DDNS driven by health checks instead of a client push" — it
reuses the exact write engine, scoped to named records, with the same audit +
snapshot. No full CRUD needed; just scoped writes plus the loop. Knobs: check
type/interval, failover policy, round-robin member set, TTL discipline.

### Phase 4 — Platform: backends, multi-tenant RBAC, external API

The big step that changes the threat model — goddns now holds broad write power
and becomes a high-value target, so it needs scoped keys, rate limits and an
approval workflow on top of the audit/history substrate:

- **Panel backends** (see "Write backends beyond RFC2136" below): cPanel
  whmapi1/UAPI, DirectAdmin, Virtualmin — so panel-managed zones get CRUD
  through the panel's own API (honouring the invariant), letting goddns run as a
  standalone DNS + history layer *alongside* a panel.
- **Multi-tenant authz / RBAC**: who may read/edit which zones and which record
  types. goauth (or any SSO/2FA) gates the door; this is the app-level model
  behind it, with per-tenant audit + history.
- **External API / connectors**: a machine API (bearer / mTLS, rate-limited,
  audited) and a **zonecloud.io** connector that syncs zones/records to/from
  zonecloud over its API — a thin adapter on the clean internal record model +
  history, not a special case.

## Write backends beyond RFC2136

`internal/ddns.Backend` is the seam — one interface method:
`Update(fqdn, zone string, ip net.IP, ttl uint32) error`.

- **cPanel** (the actual replacement target): write through the WHM API so
  records survive cPanel zone resyncs, instead of raw dynamic updates that
  cPanel may clobber. Candidates: `whmapi1 mass_edit_dns_zone` (serial-safe
  edit; needs fetch-then-edit of the existing record) or UAPI
  `DNS::mass_edit_zone` per account. Config: per-zone backend selection +
  WHM API token (host, token, allowlist note: token should be restricted to
  the DNS functions).
- **DirectAdmin**: `CMD_API_DNS_CONTROL` (domain=, action=edit).
- **Virtualmin**: `virtualmin modify-dns --domain X --update-record ...`
  via remote API.

Config sketch: `[zone "example.com"] backend = "cpanel" ...` sections —
which also unlocks per-zone TSIG keys for the rfc2136 backend.

## Admin web UI — shipped (read-only + DDNS CRUD); follow-ups

The `[admin]` dashboard (DDNS records, proxy table, log tail, DDNS token
add/delete, login session + CIDR/Basic gates) is in. Still open:

- **Proxy CRUD** from the UI — needs moving proxy rules out of the
  hand-edited TOML into SQLite (or a managed `.d/` dir) so the daemon can
  merge file-config + DB-config without clobbering comments. The real
  design fork before this can happen.
- A machine API (`POST/GET/DELETE /api/v1/records` + admin bearer token /
  mTLS) for provisioning scripts, distinct from the human UI.
- htmx polish (inline add/delete without full reloads), live log streaming.
- Per-record disable/enable toggle in the UI (column already in the schema).

## termui dashboard

`goddns top` — live table like cfm's `cfm bots`/`cfm kernsec` (termui v3):
FQDN, zone, last IP, last update age, update counter, last client UA.
Needs a hits counter column in the records table (cheap migration).

## `goddns tunnel` — reverse tunnel for services behind CGNAT/NAT

The cloudflared/frp model, native: when the home side cannot port-forward
at all, the only working direction is outbound — an agent dials the goddns
server and keeps a persistent connection; inbound proxy traffic rides it
backwards.

Why it's worth building even where port-forwarding IS possible: it is a
safety net. Zero inbound ports at home means the NAT acts as a firewall
and the service is not addressable from the internet at all — it exists
only through the tunnel, and every request still passes the proxy's
allow list / basic auth / rate limit / access log at one central point,
instead of policy being scattered across router port-forwards.

Design sketch:

- Same binary, new subcommand:
  `goddns tunnel -server sdns:8245 -token <t> -local 127.0.0.1:5678`
- Server side: websocket (or h2) endpoint on the existing listener,
  authenticated with a tunnel token from the existing store; stream
  multiplexing via yamux; reconnect with backoff on the agent.
- Proxy rules grow `upstream = "tunnel://<name>"`, resolved to the live
  tunnel session instead of a dial.
- Until then the documented workaround is an SSH reverse tunnel
  (`ssh -N -R 127.0.0.1:15678:localhost:5678 tunnel@sdns`) with the proxy
  upstream pointed at the local tunnel end — zero new moving parts.

## Reverse proxy mode — shipped (v1.1), possible follow-ups

The `proxy_enabled` knob, host→upstream table, allowlists, per-IP rate
limiting and access logging are implemented. Candidate extensions:

- ~~Basic-auth per host~~ — shipped (`basic_auth` + `goddns passwd`).
  Still open: forward-auth (delegating to an external auth endpoint).
- Unmanage ACME certs of removed proxy hosts (certmagic
  Cache.RemoveManaged) so deleted names stop renewing forever.
- Count bytes/duration of hijacked (websocket) sessions in the access log
  (today they log as 101/0B at upgrade time).
- mTLS (client certificates) for the really sensitive consoles.
- Separate access_log file / JSON log format (today: journald via stdout).
- Per-host upstream CA pinning instead of the verify on/off switch.
- Connection/concurrency caps per host in addition to request rate.

## Misc

- Per-token rate limiting (a misbehaving client should not be able to spam
  UPDATEs even when the IP changes every call).
- Optional per-token source CIDR allowlist (e.g. only the owner's ISP
  ranges may update) — limits the blast radius of a leaked update URL,
  e.g. one fetched by a chat-app link-preview bot.
- Single call updating both A and AAAA when the client is dual-stack
  (today the IP family of the observed peer wins).
- Optional `webhook_url` per record (notify on IP change).
- `goddns token disable/enable` CLI (column already exists in the schema).
- Prometheus `/metrics` (updates total, per-rcode errors, nochg ratio).
- Live listener swap on `listen`/`tls_mode` change (today: logged as
  "needs restart").
