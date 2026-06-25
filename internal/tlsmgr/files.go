// Package tlsmgr provides the certificate sources behind the server's
// tls.Config.GetCertificate: "files" (existing cert/key on disk, reloaded
// when the file changes — certbot renewals are picked up with no restart),
// "acme" (self-issued via DNS-01 over RFC2136, see acme.go), and "hybrid"
// (files when they cover the SNI, else ACME on-demand, see hybrid.go).
package tlsmgr

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"sync"
	"time"
)

// Files serves the TLS cert from disk and reloads it when the file changes
// on disk (so certbot renewals are picked up without a restart).
type Files struct {
	certFile, keyFile string
	mu                sync.RWMutex
	cert              *tls.Certificate
	leaf              *x509.Certificate // parsed leaf, for hybrid SNI/expiry checks
	modTime           time.Time
}

func NewFiles(certFile, keyFile string) (*Files, error) {
	f := &Files{certFile: certFile, keyFile: keyFile}
	if err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

func (c *Files) load() error {
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return err
	}
	// Parse the leaf once so hybrid mode can test it against the SNI and the
	// validity window per handshake without re-parsing. LoadX509KeyPair leaves
	// Leaf populated on recent Go, but parse defensively to be version-proof.
	leaf := cert.Leaf
	if leaf == nil && len(cert.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	st, _ := os.Stat(c.certFile)
	c.mu.Lock()
	c.cert = &cert
	c.leaf = leaf
	if st != nil {
		c.modTime = st.ModTime()
	}
	c.mu.Unlock()
	return nil
}

// reloadIfStale reloads the cert when the file's mtime advanced (a renewal).
func (c *Files) reloadIfStale() {
	st, err := os.Stat(c.certFile)
	if err != nil {
		return
	}
	c.mu.RLock()
	stale := st.ModTime().After(c.modTime)
	c.mu.RUnlock()
	if !stale {
		return
	}
	if err := c.load(); err != nil {
		log.Printf("cert reload failed: %v", err)
	} else {
		log.Printf("reloaded TLS certificate from %s", c.certFile)
	}
}

// GetCertificate is plugged into tls.Config.GetCertificate.
func (c *Files) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.reloadIfStale()
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert, nil
}

// matching returns the file cert IF it is currently valid (within its
// not-before/not-after window) AND covers name (CN/SAN, including wildcards).
// It returns nil otherwise — the signal hybrid mode uses to fall back to ACME.
// An empty name (no SNI) never matches, so a bare-IP/blank-SNI client falls
// through to the fallback rather than being served a name-mismatched cert.
func (c *Files) matching(name string, now time.Time) *tls.Certificate {
	if name == "" {
		return nil
	}
	c.reloadIfStale()
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cert == nil || c.leaf == nil {
		return nil
	}
	if now.Before(c.leaf.NotBefore) || now.After(c.leaf.NotAfter) {
		return nil
	}
	if c.leaf.VerifyHostname(name) != nil {
		return nil
	}
	return c.cert
}
