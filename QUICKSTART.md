# goddns Quickstart — your own DynDNS in ~10 minutes

For anyone fed up with cPanel's Dynamic DNS, no-ip/DynDNS subscriptions, or
random third-party DDNS services. At the end you own the whole chain: your
domain, your DNS server, your update endpoint, your tokens.

**You need:** a Linux server with a public IP (any small VPS works), a domain
you control (`example.com` below), and 10 minutes. No certbot, no port
80/443 — goddns issues its own TLS certificate over DNS.

The plan: delegate one subdomain (`ddns.example.com`) to your server, let
goddns own it, and every DDNS hostname lives under it
(`home.ddns.example.com`, `vpn.ddns.example.com`, ...) — added with one
command, no config edits ever.

---

## 1. Install BIND and goddns

EL (Alma/Rocky/CentOS):

    dnf install -y bind bind-utils
    dnf install -y ./goddns-*.rpm          # from the GitHub releases page
    systemctl enable --now named

Debian/Ubuntu:

    apt install -y bind9 bind9-dnsutils
    apt install -y ./goddns_*_amd64.deb
    systemctl enable --now named           # 'bind9' on older releases

(Or build from source: `make build` — single static binary, no
dependencies.)

> **Debian paths:** this guide uses EL paths. On Debian, named.conf lives in
> `/etc/bind/named.conf.local`, zone files go in `/var/cache/bind/` (the
> named-writable directory), and the service may be called `bind9`.

## 2. Generate the two TSIG keys

One key for record updates, one for the TLS certificate's DNS challenge:

    tsig-keygen -a hmac-sha256 ddns-update | tee -a /etc/named/ddns.key
    tsig-keygen -a hmac-sha256 acme-update | tee -a /etc/named/ddns.key
    chmod 640 /etc/named/ddns.key && chown root:named /etc/named/ddns.key

Keep the two `secret "..."` values handy for steps 3 and 5.

## 3. The DDNS zone in named.conf

Append to `/etc/named.conf`:

    include "/etc/named/ddns.key";

    zone "ddns.example.com" {
        type master;
        file "dynamic/ddns.example.com.hosts";
        update-policy {
            // any current or FUTURE hostname under ddns.example.com:
            grant ddns-update. wildcard *.ddns.example.com. A AAAA;
            // lets goddns issue/renew its own TLS cert:
            grant acme-update. name _acme-challenge.ddns.example.com. TXT;
        };
    };

The zone file (`/var/named/dynamic/ddns.example.com.hosts`) — note it MUST
be in the `dynamic/` directory so named can write its journal:

    $TTL 60
    @   IN SOA  ddns.example.com. hostmaster.example.com. (1 3600 900 604800 60)
        IN NS   ddns.example.com.
        IN A    203.0.113.50        ; <-- YOUR SERVER'S PUBLIC IP

    cat > /var/named/dynamic/ddns.example.com.hosts   # paste the above
    chown named:named /var/named/dynamic/ddns.example.com.hosts
    named-checkconf -z /etc/named.conf && systemctl reload named

## 4. Delegate the subdomain to your server

Wherever `example.com`'s DNS lives (registrar panel, Cloudflare, your own
BIND — anywhere), add two records:

    ddns.example.com.    NS    ddns.example.com.
    ddns.example.com.    A     203.0.113.50          ; glue for the NS

That's the only thing you ever touch outside your server. Verify:

    dig +short NS ddns.example.com

## 5. Configure goddns

`/etc/goddns/goddns.conf` — only these lines matter, the package ships the
rest commented:

    listen      = ":8245"
    tls_mode    = "acme"
    acme_domain = "ddns.example.com"
    acme_email  = "you@example.com"
    dns_server  = "127.0.0.1:53"
    tsig_name   = "ddns-update"
    acme_tsig_name = "acme-update"

Secrets go in the root-only env file (never in the conf):

    cat > /etc/goddns/goddns.env <<EOF
    GODDNS_TSIG_SECRET=<secret of ddns-update>
    GODDNS_ACME_TSIG_SECRET=<secret of acme-update>
    EOF
    chmod 600 /etc/goddns/goddns.env

Open the port and start (first start takes ~30s — it's getting your
certificate from Let's Encrypt):

    firewall-cmd --permanent --add-port=8245/tcp && firewall-cmd --reload
    systemctl enable --now goddns
    journalctl -u goddns -f      # watch the cert get issued

> Already have a wildcard/certbot cert and prefer it? Use
> `tls_mode = "files"` instead — see README → TLS and Troubleshooting.

## 6. Create hostnames and point your devices at them

Each hostname = one command, prints its token once:

    goddns token add -fqdn home.ddns.example.com -zone ddns.example.com -ttl 60

From the device whose IP you want tracked (cron every 1–3 minutes):

    curl "https://ddns.example.com:8245/update/<token>"

Responses: `good <ip>` (updated), `nochg <ip>` (no change — costs nothing,
hammer away). The server uses the connection's source IP, so the client
never needs to know its own address.

- **MikroTik:** edit the URL in `configs/mikrotik-ddns-minimal.rsc`
  (shipped in `/usr/share/goddns/configs/`), upload it and
  `/import mikrotik-ddns-minimal.rsc` — script + 3-minute scheduler in
  one shot.
- **Routers with "Custom DynDNS":** server `ddns.example.com:8245`, path
  `/nic/update`, the token as the password.
- **Plain cron:**
  `*/3 * * * * curl -fsS "https://ddns.example.com:8245/update/<token>" >/dev/null`

⚠️ **The URL is the credential.** Don't paste it in chats (Slack/Discord
link previews will fetch it and "update" your record from an AWS IP — ask
us how we know). If a token leaks: `goddns token del` + `add`.

## Bonus: TLS for your internal consoles (reverse proxy mode)

The same binary can also put a real hostname + real certificate + access
control in front of things that can never have them on their own (iDRAC,
iLO, switches):

    proxy_enabled = true
    proxy_listen  = ":443"

    [proxy."idrac.internal.example.com"]
    upstream   = "https://10.0.0.200"
    allow      = ["YOUR.ISP.CIDR.0/24"]
    rate_limit = 10

With `tls_mode = "acme"` it issues per-host certs through the same DNS
mechanism. DNS needs one wildcard record pointing at this server — full
recipe (including the zone/update-policy for acme) in
[README → Reverse proxy mode](README.md#reverse-proxy-mode-optional).

## Done. What you got

- `home.ddns.example.com` always points at your current IP, TTL 60.
- New hostnames: one `goddns token add` — never touch BIND again.
- A leaked token can only flap its own record; the TSIG key can only touch
  `*.ddns.example.com`; your main zone is untouchable and stays static.
- TLS renews itself over DNS; config edits hot-reload without restarts.

Day-2 details, the certbot/`files` TLS variant, per-name update policies,
and troubleshooting (SERVFAIL = journal permissions, etc.): see
[README.md](README.md).
