package tlsmgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCert generates a self-signed cert for the given SANs and validity
// window, writes cert.pem/key.pem into a temp dir, and returns their paths.
func writeCert(t *testing.T, notBefore, notAfter time.Time, sans ...string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sans[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     sans,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// fakeACME is a stand-in cert source: it records calls and returns a sentinel
// cert (or an error) without touching a real CA.
type fakeACME struct {
	calls []string
	fail  bool
	cert  *tls.Certificate
}

func (f *fakeACME) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.calls = append(f.calls, hello.ServerName)
	if f.fail {
		return nil, errors.New("acme boom")
	}
	return f.cert, nil
}

func hello(name string) *tls.ClientHelloInfo { return &tls.ClientHelloInfo{ServerName: name} }

func newFilesFor(t *testing.T, notBefore, notAfter time.Time, sans ...string) *Files {
	t.Helper()
	c, k := writeCert(t, notBefore, notAfter, sans...)
	f, err := NewFiles(c, k)
	if err != nil {
		t.Fatalf("NewFiles: %v", err)
	}
	return f
}

func TestHybridFileCoversName(t *testing.T) {
	now := time.Now()
	f := newFilesFor(t, now.Add(-time.Hour), now.Add(time.Hour), "*.internal.myip.gr", "internal.myip.gr")
	fa := &fakeACME{cert: &tls.Certificate{}}
	h := NewHybrid(f)
	h.SetACME(fa)
	h.SetAllowed([]string{"ha.internal.myip.gr"})

	// a wildcard-covered name is served from the file; ACME is never consulted
	cert, err := h.GetCertificate(hello("ha.internal.myip.gr"))
	if err != nil || cert != f.cert {
		t.Fatalf("expected the file cert, got cert=%p err=%v", cert, err)
	}
	if len(fa.calls) != 0 {
		t.Fatalf("ACME must not be called when the file covers the name: %v", fa.calls)
	}
}

func TestHybridFallsBackToACME(t *testing.T) {
	now := time.Now()
	f := newFilesFor(t, now.Add(-time.Hour), now.Add(time.Hour), "internal.myip.gr")
	acmeCert := &tls.Certificate{}
	fa := &fakeACME{cert: acmeCert}
	h := NewHybrid(f)
	h.SetACME(fa)
	h.SetAllowed([]string{"sub.tou-filou.com"})

	// a name the file does NOT cover, but which IS on the allowlist -> ACME
	cert, err := h.GetCertificate(hello("sub.tou-filou.com"))
	if err != nil || cert != acmeCert {
		t.Fatalf("expected the ACME cert, got cert=%p err=%v", cert, err)
	}
	if len(fa.calls) != 1 || fa.calls[0] != "sub.tou-filou.com" {
		t.Fatalf("ACME should have been asked once for the name: %v", fa.calls)
	}
}

func TestHybridOffListNeverHitsACME(t *testing.T) {
	now := time.Now()
	f := newFilesFor(t, now.Add(-time.Hour), now.Add(time.Hour), "internal.myip.gr")
	fa := &fakeACME{cert: &tls.Certificate{}}
	h := NewHybrid(f)
	h.SetACME(fa)
	h.SetAllowed([]string{"known.myip.gr"}) // attacker SNI is NOT here

	// an uncovered, off-allowlist SNI must NOT trigger an ACME order (rate-limit
	// guard); it falls through to the file cert as a last resort.
	cert, err := h.GetCertificate(hello("evil-random-scan.example"))
	if err != nil || cert != f.cert {
		t.Fatalf("off-list name should last-resort to the file cert, got cert=%p err=%v", cert, err)
	}
	if len(fa.calls) != 0 {
		t.Fatalf("an off-allowlist name must never reach ACME: %v", fa.calls)
	}
	if h.Decide("evil-random-scan.example") == nil {
		t.Fatal("Decide must refuse an off-allowlist name")
	}
	if h.Decide("known.myip.gr") != nil {
		t.Fatal("Decide must allow an on-allowlist name")
	}
}

func TestHybridExpiredFileFallsBack(t *testing.T) {
	now := time.Now()
	// file cert covers the name but is EXPIRED -> not served; ACME picks it up
	f := newFilesFor(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour), "sdns.myip.gr")
	acmeCert := &tls.Certificate{}
	fa := &fakeACME{cert: acmeCert}
	h := NewHybrid(f)
	h.SetACME(fa)
	h.SetAllowed([]string{"sdns.myip.gr"})

	if c := f.matching("sdns.myip.gr", now); c != nil {
		t.Fatal("an expired file cert must not match")
	}
	cert, err := h.GetCertificate(hello("sdns.myip.gr"))
	if err != nil || cert != acmeCert {
		t.Fatalf("expired file should fall back to ACME, got cert=%p err=%v", cert, err)
	}
}

func TestHybridACMEErrorLastResortsToFile(t *testing.T) {
	now := time.Now()
	f := newFilesFor(t, now.Add(-time.Hour), now.Add(time.Hour), "internal.myip.gr")
	fa := &fakeACME{fail: true}
	h := NewHybrid(f)
	h.SetACME(fa)
	h.SetAllowed([]string{"sub.tou-filou.com"})

	// allowed name, but ACME issuance fails -> serve the (mismatched) file cert
	// rather than abort the handshake
	cert, err := h.GetCertificate(hello("sub.tou-filou.com"))
	if err != nil || cert != f.cert {
		t.Fatalf("ACME failure should last-resort to the file cert, got cert=%p err=%v", cert, err)
	}
	if len(fa.calls) != 1 {
		t.Fatalf("ACME should have been attempted once: %v", fa.calls)
	}
}

func TestHybridNoFileBaseUsesACME(t *testing.T) {
	acmeCert := &tls.Certificate{}
	fa := &fakeACME{cert: acmeCert}
	h := NewHybrid(nil) // file pair failed to load
	h.SetACME(fa)
	h.SetAllowed([]string{"sdns.myip.gr"})

	cert, err := h.GetCertificate(hello("sdns.myip.gr"))
	if err != nil || cert != acmeCert {
		t.Fatalf("with no file base, an allowed name should come from ACME, got cert=%p err=%v", cert, err)
	}
}

func TestHybridEmptySNI(t *testing.T) {
	now := time.Now()
	f := newFilesFor(t, now.Add(-time.Hour), now.Add(time.Hour), "internal.myip.gr")
	fa := &fakeACME{cert: &tls.Certificate{}}
	h := NewHybrid(f)
	h.SetACME(fa)
	h.SetAllowed([]string{"internal.myip.gr"})

	// no SNI (bare IP client): never matches a name, never issues, last-resorts
	// to the file cert
	cert, err := h.GetCertificate(hello(""))
	if err != nil || cert != f.cert {
		t.Fatalf("empty SNI should last-resort to the file cert, got cert=%p err=%v", cert, err)
	}
	if len(fa.calls) != 0 {
		t.Fatalf("empty SNI must not reach ACME: %v", fa.calls)
	}
}

func TestHybridAllowlistNormalisation(t *testing.T) {
	h := NewHybrid(nil)
	h.SetAllowed([]string{"Foo.MyIP.gr.", "  bar.myip.gr  "})
	if !h.allowed("foo.myip.gr") || !h.allowed("BAR.MYIP.GR.") {
		t.Fatal("allowlist lookups should be case/trailing-dot/space insensitive")
	}
	if h.allowed("baz.myip.gr") {
		t.Fatal("unexpected name allowed")
	}
}
