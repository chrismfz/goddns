package config

import (
	"net"
	"os"
	"path/filepath"
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
