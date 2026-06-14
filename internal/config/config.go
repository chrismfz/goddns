// Package config loads /etc/goddns/goddns.conf (flat TOML, key = "value")
// and applies environment overrides for secrets. The serve loop re-loads it
// on change (cfm-style polling hot reload) — see cmd/goddns.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// TLS modes.
const (
	TLSFiles = "files" // cert_file/key_file from disk, hot-reloaded on renewal
	TLSACME  = "acme"  // self-issued Let's Encrypt cert via DNS-01 over RFC2136
)

// Config holds the server configuration. Secrets can be overridden by env
// (GODDNS_TSIG_SECRET, GODDNS_ACME_TSIG_SECRET) so they never have to live
// in the config file on disk.
type Config struct {
	Listen         string `toml:"listen"`          // e.g. ":8245" or "84.54.49.3:8245"
	DBPath         string `toml:"db_path"`         // SQLite token store
	ReloadInterval int    `toml:"reload_interval"` // config re-check period, seconds
	LogFile        string `toml:"log_file"`        // dedicated log file; empty = stderr/journald. Hot-swappable.
	AccessLog      string `toml:"access_log"`      // separate file for proxy-access lines; empty = into log_file. Hot-swappable.
	PublicHost     string `toml:"public_host"`     // hostname clients use to reach the DDNS endpoint (e.g. sdns.myip.gr); fills the admin help snippets. Optional.
	NamedConf      string `toml:"named_conf"`      // path to named.conf for the read-only Zones view (default /etc/named.conf)

	// TLS
	TLSMode  string `toml:"tls_mode"`  // "files" or "acme"
	CertFile string `toml:"cert_file"` // files mode: TLS cert (fullchain)
	KeyFile  string `toml:"key_file"`  // files mode: TLS private key

	// ACME (tls_mode = "acme"): the DNS-01 challenge TXT record is written
	// through the same BIND via RFC2136, so no port 80/443 is ever needed.
	ACMEDomain     string `toml:"acme_domain"`      // certificate hostname, e.g. sdns.myip.gr
	ACMEEmail      string `toml:"acme_email"`       // account contact (optional)
	ACMECA         string `toml:"acme_ca"`          // directory URL; empty = Let's Encrypt production
	ACMEStorage    string `toml:"acme_storage"`     // cert/account storage dir
	ACMETSIGName   string `toml:"acme_tsig_name"`   // defaults to tsig_name
	ACMETSIGAlgo   string `toml:"acme_tsig_algo"`   // defaults to tsig_algo
	ACMETSIGSecret string `toml:"acme_tsig_secret"` // defaults to tsig_secret; prefer env

	// DNS / TSIG (the DDNS update key)
	DNSServer  string `toml:"dns_server"`  // where to send the UPDATE, e.g. 127.0.0.1:53
	TSIGName   string `toml:"tsig_name"`   // key name as defined in named.conf
	TSIGAlgo   string `toml:"tsig_algo"`   // hmac-sha256 (default)
	TSIGSecret string `toml:"tsig_secret"` // base64; prefer env GODDNS_TSIG_SECRET

	// Trusted proxies: if the request comes from one of these CIDRs we honour
	// X-Forwarded-For. Leave empty when goddns is exposed directly (the safe
	// default), so the connection peer IP is always the client.
	TrustedProxies []string `toml:"trusted_proxies"`

	// Reverse proxy mode: a second TLS listener that routes by SNI/Host to
	// internal upstreams (iDRAC, switches, anything without proper TLS).
	// Off by default — pure-DDNS deployments are unaffected.
	ProxyEnabled        bool                 `toml:"proxy_enabled"`
	ProxyListen         string               `toml:"proxy_listen"`          // e.g. ":443" (CAP_NET_BIND_SERVICE in the unit covers low ports)
	ProxyRedirectListen string               `toml:"proxy_redirect_listen"` // optional plain-HTTP listener (e.g. ":80") that 308-redirects to https
	Proxy               map[string]ProxyRule `toml:"proxy"`                 // host -> rule; hot-reloadable

	// Admin web UI: a built-in vhost on the proxy listener that shows the
	// DDNS records + proxy table + logs and allows DDNS token CRUD. Off by
	// default; this is high-value (can rewrite DNS), so it stacks CIDR
	// allow + optional HTTP Basic + a login session.
	Admin AdminConfig `toml:"admin"`

	trustedNets []*net.IPNet
}

// AdminConfig configures the admin web UI (see internal/admin).
type AdminConfig struct {
	Enabled    bool     `toml:"enabled"`
	Host       string   `toml:"host"`        // vhost served on the proxy listener, e.g. admin.myip.gr
	Allow      []string `toml:"allow"`       // client CIDRs (a real filter, not obscurity); empty = anywhere
	BasicAuth  []string `toml:"basic_auth"`  // optional outer HTTP Basic gate ("user:bcrypt"); keeps scanners off the login form
	Users      []string `toml:"users"`       // "user:bcrypt" for the login session (generate: goddns passwd)
	SessionTTL int      `toml:"session_ttl"` // session lifetime in hours (default 8)

	allowNets []*net.IPNet
}

// AllowNets returns the parsed admin allow CIDRs.
func (a *AdminConfig) AllowNets() []*net.IPNet { return a.allowNets }

// IsAllowed reports whether ip passes the admin CIDR allowlist. An empty
// list allows everyone (the operator relies on auth instead).
func (a *AdminConfig) IsAllowed(ip net.IP) bool {
	if len(a.allowNets) == 0 {
		return true
	}
	for _, n := range a.allowNets {
		if ip != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// ProxyRule routes one public hostname to one internal upstream.
type ProxyRule struct {
	Upstream       string   `toml:"upstream"`        // http(s)://ip-or-host[:port]
	UpstreamVerify bool     `toml:"upstream_verify"` // verify the upstream's TLS cert (default off: BMCs are self-signed)
	PreserveHost   bool     `toml:"preserve_host"`   // keep the inbound Host header instead of the upstream's
	Allow          []string `toml:"allow"`           // client CIDRs; empty = allow everyone (set it for BMCs!)
	RateLimit      int      `toml:"rate_limit"`      // max requests/sec per client IP (burst 2x); 0 = unlimited
	BasicAuth      []string `toml:"basic_auth"`      // "user:bcrypt-hash" entries (generate: goddns passwd); for clients on CGNAT/mobile where CIDRs can't work
}

func defaults() Config {
	return Config{
		Listen:         ":8245",
		DBPath:         "/var/lib/goddns/goddns.db",
		ReloadInterval: 20,
		TLSMode:        TLSFiles,
		ACMEStorage:    "/var/lib/goddns/acme",
		DNSServer:      "127.0.0.1:53",
		TSIGName:       "ddns-update",
		TSIGAlgo:       "hmac-sha256",
		NamedConf:      "/etc/named.conf",
	}
}

// Load reads the config file (missing file = pure defaults), applies env
// overrides and validates. Used both at startup and by the hot-reload loop.
func Load(path string) (*Config, error) {
	c := defaults()
	if path != "" {
		md, err := toml.DecodeFile(path, &c)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("config %s: %w", path, err)
			}
		} else if undec := md.Undecoded(); len(undec) > 0 {
			// Reject unrecognised keys loudly. The classic footgun is a
			// top-level key placed AFTER a [section] header, which TOML then
			// scopes into that section (e.g. proxy_enabled written under
			// [admin] becomes admin.proxy_enabled and is silently ignored).
			keys := make([]string, 0, len(undec))
			for _, k := range undec {
				keys = append(keys, k.String())
			}
			return nil, fmt.Errorf("config %s: unrecognised key(s): %s — in TOML every key "+
				"after a [section] header belongs to that section, so put top-level keys "+
				"(listen, proxy_enabled, proxy_listen, log_file, tsig_*, ...) ABOVE the first "+
				"[admin] or [proxy.\"...\"] section", path, strings.Join(keys, ", "))
		}
	}
	if v := os.Getenv("GODDNS_TSIG_SECRET"); v != "" {
		c.TSIGSecret = v
	}
	if v := os.Getenv("GODDNS_ACME_TSIG_SECRET"); v != "" {
		c.ACMETSIGSecret = v
	}

	// ACME TSIG falls back to the main DDNS key. A dedicated key is better
	// (the DDNS key then never needs TXT grants), but one key works too.
	if c.ACMETSIGName == "" {
		c.ACMETSIGName = c.TSIGName
	}
	if c.ACMETSIGAlgo == "" {
		c.ACMETSIGAlgo = c.TSIGAlgo
	}
	if c.ACMETSIGSecret == "" {
		c.ACMETSIGSecret = c.TSIGSecret
	}

	c.TSIGName = canonKeyName(c.TSIGName)
	c.ACMETSIGName = canonKeyName(c.ACMETSIGName)

	switch c.TLSMode {
	case TLSFiles:
		if c.CertFile == "" || c.KeyFile == "" {
			return nil, fmt.Errorf("tls_mode \"files\" requires cert_file and key_file")
		}
	case TLSACME:
		if c.ACMEDomain == "" {
			return nil, fmt.Errorf("tls_mode \"acme\" requires acme_domain")
		}
	default:
		return nil, fmt.Errorf("tls_mode must be %q or %q (got %q)", TLSFiles, TLSACME, c.TLSMode)
	}

	for _, cidr := range c.TrustedProxies {
		_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies %q: %w", cidr, err)
		}
		c.trustedNets = append(c.trustedNets, n)
	}

	if c.ProxyListen == "" {
		c.ProxyListen = ":443"
	}
	// Normalise host keys (lowercase, no trailing dot) and validate rules so
	// a broken reload is rejected as a whole and the old config stays live.
	if len(c.Proxy) > 0 {
		norm := make(map[string]ProxyRule, len(c.Proxy))
		for host, rule := range c.Proxy {
			h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
			if h == "" || strings.ContainsAny(h, "/: \t") {
				return nil, fmt.Errorf("proxy: invalid hostname key %q", host)
			}
			if _, dup := norm[h]; dup {
				return nil, fmt.Errorf("proxy: duplicate hostname %q after normalisation", h)
			}
			u, err := url.Parse(rule.Upstream)
			if err != nil || u.Host == "" || u.User != nil ||
				(u.Scheme != "http" && u.Scheme != "https") {
				return nil, fmt.Errorf("proxy %q: upstream must be http(s)://host[:port] (got %q)", h, rule.Upstream)
			}
			for _, cidr := range rule.Allow {
				if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
					return nil, fmt.Errorf("proxy %q: allow %q: %w", h, cidr, err)
				}
			}
			for _, cred := range rule.BasicAuth {
				user, hash, ok := strings.Cut(cred, ":")
				// bcrypt only — refuse anything that could be a plaintext
				// password pasted into the config by mistake.
				if !ok || user == "" || !strings.HasPrefix(hash, "$2") {
					return nil, fmt.Errorf("proxy %q: basic_auth entries must be \"user:bcrypt-hash\" (generate with: goddns passwd)", h)
				}
			}
			norm[h] = rule
		}
		c.Proxy = norm
	}

	if c.Admin.Enabled {
		if !c.ProxyEnabled {
			return nil, fmt.Errorf("admin requires proxy_enabled = true (it is served as a vhost on proxy_listen)")
		}
		c.Admin.Host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.Admin.Host)), ".")
		if c.Admin.Host == "" || strings.ContainsAny(c.Admin.Host, "/: \t") {
			return nil, fmt.Errorf("admin: host must be a hostname (e.g. admin.myip.gr)")
		}
		if _, dup := c.Proxy[c.Admin.Host]; dup {
			return nil, fmt.Errorf("admin: host %q also has a [proxy] rule — pick a distinct name", c.Admin.Host)
		}
		if len(c.Admin.Users) == 0 {
			return nil, fmt.Errorf("admin: at least one users entry is required (generate: goddns passwd)")
		}
		for _, cred := range append(append([]string{}, c.Admin.Users...), c.Admin.BasicAuth...) {
			user, hash, ok := strings.Cut(cred, ":")
			if !ok || user == "" || !strings.HasPrefix(hash, "$2") {
				return nil, fmt.Errorf("admin: users/basic_auth entries must be \"user:bcrypt-hash\" (generate with: goddns passwd)")
			}
			// '|' is the session field separator and whitespace is a footgun;
			// the username is everything before the first ':' so ':' is moot.
			if strings.ContainsAny(user, "| \t") {
				return nil, fmt.Errorf("admin: username %q must not contain '|' or whitespace", user)
			}
		}
		for _, cidr := range c.Admin.Allow {
			_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err != nil {
				return nil, fmt.Errorf("admin: allow %q: %w", cidr, err)
			}
			c.Admin.allowNets = append(c.Admin.allowNets, n)
		}
		if c.Admin.SessionTTL <= 0 {
			c.Admin.SessionTTL = 8
		}
	}
	return &c, nil
}

// ProxyHosts returns the proxied hostnames, sorted (stable for comparisons
// and for handing the set to the ACME manager).
func (c *Config) ProxyHosts() []string {
	hosts := make([]string, 0, len(c.Proxy))
	for h := range c.Proxy {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

func canonKeyName(s string) string {
	s = strings.TrimSpace(s)
	if s != "" && !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// IsTrusted reports whether ip belongs to a configured trusted proxy.
func (c *Config) IsTrusted(ip net.IP) bool {
	for _, n := range c.trustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// NeedsRestart reports whether switching from old to new requires a process
// restart (listener/TLS plumbing cannot be swapped live in v1).
func (c *Config) NeedsRestart(old *Config) []string {
	var fields []string
	if c.Listen != old.Listen {
		fields = append(fields, "listen")
	}
	if c.TLSMode != old.TLSMode {
		fields = append(fields, "tls_mode")
	}
	if c.TLSMode == TLSFiles && (c.CertFile != old.CertFile || c.KeyFile != old.KeyFile) {
		fields = append(fields, "cert_file/key_file")
	}
	if c.TLSMode == TLSACME &&
		(c.ACMEDomain != old.ACMEDomain || c.ACMECA != old.ACMECA ||
			c.ACMEEmail != old.ACMEEmail ||
			c.ACMEStorage != old.ACMEStorage || c.ACMETSIGName != old.ACMETSIGName ||
			c.ACMETSIGAlgo != old.ACMETSIGAlgo || c.ACMETSIGSecret != old.ACMETSIGSecret) {
		fields = append(fields, "acme_*")
	}
	if c.DBPath != old.DBPath {
		fields = append(fields, "db_path")
	}
	if c.ProxyEnabled != old.ProxyEnabled || c.ProxyListen != old.ProxyListen ||
		c.ProxyRedirectListen != old.ProxyRedirectListen {
		fields = append(fields, "proxy_enabled/proxy_listen")
	}
	// admin.users / allow / basic_auth hot-reload via the live config
	// accessor; only enabling/disabling or moving the vhost needs a restart.
	if c.Admin.Enabled != old.Admin.Enabled || c.Admin.Host != old.Admin.Host {
		fields = append(fields, "admin.enabled/host")
	}
	return fields
}
