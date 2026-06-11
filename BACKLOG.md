# goddns backlog

v1 is deliberately lean: serve + CLI token management + cfm-style config
hot-reload + deb/rpm packaging. Everything below is planned but explicitly
out of v1 scope.

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

## Admin HTTP API

Token CRUD over HTTPS (what the CLI does today) guarded by a separate admin
bearer token, so zones/records can be managed remotely / from provisioning
scripts: `POST/GET/DELETE /api/v1/records`. Goes behind its own listener or
path prefix; consider mTLS for server-to-server use.

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
