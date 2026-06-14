package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "goddns.conf")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAndFiles(t *testing.T) {
	p := write(t, `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8245" {
		t.Fatalf("default listen: %q", c.Listen)
	}
	if c.TLSMode != TLSFiles || c.DNSServer != "127.0.0.1:53" || c.ReloadInterval != 20 {
		t.Fatalf("defaults: %+v", c)
	}
	if c.TSIGName != "ddns-update." {
		t.Fatalf("tsig name not canonicalised: %q", c.TSIGName)
	}
	// ACME key falls back to main key
	if c.ACMETSIGName != "ddns-update." || c.ACMETSIGAlgo != "hmac-sha256" {
		t.Fatalf("acme tsig fallback: %q %q", c.ACMETSIGName, c.ACMETSIGAlgo)
	}
}

func TestFilesModeRequiresCert(t *testing.T) {
	if _, err := Load(write(t, `tls_mode = "files"`)); err == nil {
		t.Fatal("files mode without cert accepted")
	}
}

func TestACMEModeRequiresDomain(t *testing.T) {
	if _, err := Load(write(t, `tls_mode = "acme"`)); err == nil {
		t.Fatal("acme mode without domain accepted")
	}
	c, err := Load(write(t, `
tls_mode    = "acme"
acme_domain = "sdns.myip.gr"
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.ACMEStorage != "/var/lib/goddns/acme" {
		t.Fatalf("acme storage default: %q", c.ACMEStorage)
	}
}

func TestBadTLSMode(t *testing.T) {
	if _, err := Load(write(t, `tls_mode = "bogus"`)); err == nil {
		t.Fatal("bogus tls_mode accepted")
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("GODDNS_TSIG_SECRET", "from-env")
	c, err := Load(write(t, `
cert_file   = "/tmp/c.pem"
key_file    = "/tmp/k.pem"
tsig_secret = "from-file"
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.TSIGSecret != "from-env" {
		t.Fatalf("env override: %q", c.TSIGSecret)
	}
	if c.ACMETSIGSecret != "from-env" {
		t.Fatalf("acme secret fallback: %q", c.ACMETSIGSecret)
	}
}

func TestTrustedProxies(t *testing.T) {
	c, err := Load(write(t, `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
trusted_proxies = ["127.0.0.1/32", "10.0.0.0/8"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsTrusted(net.ParseIP("127.0.0.1")) || !c.IsTrusted(net.ParseIP("10.1.2.3")) {
		t.Fatal("trusted ip not matched")
	}
	if c.IsTrusted(net.ParseIP("8.8.8.8")) {
		t.Fatal("untrusted ip matched")
	}
	if _, err := Load(write(t, `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
trusted_proxies = ["not-a-cidr"]
`)); err == nil {
		t.Fatal("invalid cidr accepted")
	}
}

func TestMissingFileUsesDefaultsButFailsValidation(t *testing.T) {
	// Default tls_mode is "files" with no cert paths -> must error loudly
	// rather than start without TLS material.
	if _, err := Load(filepath.Join(t.TempDir(), "absent.conf")); err == nil {
		t.Fatal("missing config with files defaults accepted")
	}
}

func TestNeedsRestart(t *testing.T) {
	base := func() string {
		return `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
`
	}
	a, err := Load(write(t, base()))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(write(t, base()+`listen = ":443"`))
	if err != nil {
		t.Fatal(err)
	}
	if f := b.NeedsRestart(a); len(f) != 1 || f[0] != "listen" {
		t.Fatalf("needs restart: %v", f)
	}
	c2, _ := Load(write(t, base()+`tsig_name = "other-key"`))
	if f := c2.NeedsRestart(a); len(f) != 0 {
		t.Fatalf("tsig change should hot-reload, got %v", f)
	}
}

func TestProxyConfig(t *testing.T) {
	c, err := Load(write(t, `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
proxy_enabled = true

[proxy."Orion-IDRAC.internal.myip.gr."]
upstream   = "https://10.23.201.200"
allow      = ["84.54.49.0/24"]
rate_limit = 10
`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.ProxyEnabled || c.ProxyListen != ":443" {
		t.Fatalf("proxy defaults: %+v", c)
	}
	r, ok := c.Proxy["orion-idrac.internal.myip.gr"] // normalised key
	if !ok {
		t.Fatalf("host key not normalised: %v", c.ProxyHosts())
	}
	if r.Upstream != "https://10.23.201.200" || r.RateLimit != 10 || r.UpstreamVerify {
		t.Fatalf("rule: %+v", r)
	}

	if _, err := Load(write(t, `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
[proxy."a.x"]
upstream = "ftp://nope"
`)); err == nil {
		t.Fatal("bad upstream scheme accepted")
	}
	if _, err := Load(write(t, `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
[proxy."a.x"]
upstream = "https://10.0.0.1"
allow    = ["not-a-cidr"]
`)); err == nil {
		t.Fatal("bad allow cidr accepted")
	}
}

func TestProxyNeedsRestart(t *testing.T) {
	base := `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
`
	a, _ := Load(write(t, base))
	b, _ := Load(write(t, base+"proxy_enabled = true"))
	if f := b.NeedsRestart(a); len(f) == 0 {
		t.Fatal("enabling proxy should need restart")
	}
	// adding a host while enabled is hot
	c1, _ := Load(write(t, base+`
proxy_enabled = true
[proxy."a.x"]
upstream = "https://10.0.0.1"
`))
	c2, _ := Load(write(t, base+`
proxy_enabled = true
[proxy."a.x"]
upstream = "https://10.0.0.1"
[proxy."b.x"]
upstream = "https://10.0.0.2"
`))
	if f := c2.NeedsRestart(c1); len(f) != 0 {
		t.Fatalf("adding a proxy host should be hot: %v", f)
	}
}

func TestLogFile(t *testing.T) {
	c, err := Load(write(t, `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.LogFile != "" {
		t.Fatalf("log_file default should be empty (journald): %q", c.LogFile)
	}
	c, err = Load(write(t, `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
log_file  = "/var/log/goddns.log"
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.LogFile != "/var/log/goddns.log" {
		t.Fatalf("log_file: %q", c.LogFile)
	}
	// hot-swappable: must NOT appear in NeedsRestart
	a, _ := Load(write(t, "cert_file = \"/tmp/c.pem\"\nkey_file = \"/tmp/k.pem\"\n"))
	if f := c.NeedsRestart(a); len(f) != 0 {
		t.Fatalf("log_file change should be hot: %v", f)
	}
}

func TestAccessLog(t *testing.T) {
	c, err := Load(write(t, `
cert_file  = "/tmp/c.pem"
key_file   = "/tmp/k.pem"
access_log = "/var/log/goddns-access.log"
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessLog != "/var/log/goddns-access.log" {
		t.Fatalf("access_log: %q", c.AccessLog)
	}
	a, _ := Load(write(t, "cert_file = \"/tmp/c.pem\"\nkey_file = \"/tmp/k.pem\"\n"))
	if a.AccessLog != "" {
		t.Fatalf("access_log default should be empty: %q", a.AccessLog)
	}
	if f := c.NeedsRestart(a); len(f) != 0 {
		t.Fatalf("access_log change should be hot: %v", f)
	}
}

func TestRejectsMisscopedKey(t *testing.T) {
	// The exact footgun: proxy_enabled placed AFTER [admin] becomes
	// admin.proxy_enabled and must now be a loud error, not silently ignored.
	_, err := Load(write(t, `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
[admin]
enabled = true
host    = "admin.x"
users   = ["a:$2a$10$abc"]
proxy_enabled = true
`))
	if err == nil {
		t.Fatal("misscoped proxy_enabled under [admin] should error")
	}
	if !strings.Contains(err.Error(), "proxy_enabled") {
		t.Fatalf("error should name the offending key: %v", err)
	}
	// A typo inside a proxy rule is caught too.
	if _, err := Load(write(t, `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
proxy_enabled = true
[proxy."a.x"]
upstream  = "https://10.0.0.1"
upstreamm = "typo"
`)); err == nil {
		t.Fatal("typo'd key inside a proxy rule should error")
	}
	// A correctly-ordered config still loads clean.
	if _, err := Load(write(t, `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
proxy_enabled = true
[admin]
enabled = true
host    = "admin.x"
users   = ["a:$2a$10$abc"]
[proxy."a.x"]
upstream = "https://10.0.0.1"
`)); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// TestShippedExampleLoads guards against the shipped configs/goddns.conf
// ever drifting into a layout that strict decoding rejects (e.g. a
// top-level key accidentally placed below a [section]).
func TestShippedExampleLoads(t *testing.T) {
	if _, err := Load("../../configs/goddns.conf"); err != nil {
		t.Fatalf("shipped configs/goddns.conf does not load: %v", err)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProxyFragments(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "goddns.conf")
	mustWrite(t, main, `
tls_mode = "files"
cert_file = "/x/c.pem"
key_file = "/x/k.pem"
[proxy."a.example"]
upstream = "https://10.0.0.1"
`)
	pd := filepath.Join(dir, "proxy.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(pd, "b.conf"), `
[proxy."b.example"]
upstream = "http://10.0.0.2"
allow = ["10.0.0.0/8"]
`)

	c, err := Load(main)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := c.Proxy["a.example"]; !ok {
		t.Error("base proxy host missing after merge")
	}
	if _, ok := c.Proxy["b.example"]; !ok {
		t.Error("fragment proxy host missing after merge")
	}

	// a host defined in both base and a fragment is rejected
	dup := filepath.Join(pd, "dup.conf")
	mustWrite(t, dup, "[proxy.\"a.example\"]\nupstream = \"http://10.0.0.9\"\n")
	if _, err := Load(main); err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Errorf("expected duplicate-host error, got %v", err)
	}
	os.Remove(dup)

	// a fragment may contain only [proxy."..."] sections
	bad := filepath.Join(pd, "bad.conf")
	mustWrite(t, bad, "listen = \":9999\"\n")
	if _, err := Load(main); err == nil || !strings.Contains(err.Error(), "only [proxy") {
		t.Errorf("expected fragment-scope error, got %v", err)
	}
}
