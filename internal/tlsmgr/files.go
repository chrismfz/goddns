// Package tlsmgr provides the two certificate sources behind the server's
// tls.Config.GetCertificate: "files" (existing cert/key on disk, reloaded
// when the file changes — certbot renewals are picked up with no restart)
// and "acme" (self-issued via DNS-01 over RFC2136, see acme.go).
package tlsmgr

import (
	"crypto/tls"
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
	st, _ := os.Stat(c.certFile)
	c.mu.Lock()
	c.cert = &cert
	if st != nil {
		c.modTime = st.ModTime()
	}
	c.mu.Unlock()
	return nil
}

// GetCertificate is plugged into tls.Config.GetCertificate.
func (c *Files) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if st, err := os.Stat(c.certFile); err == nil {
		c.mu.RLock()
		stale := st.ModTime().After(c.modTime)
		c.mu.RUnlock()
		if stale {
			if err := c.load(); err != nil {
				log.Printf("cert reload failed: %v", err)
			} else {
				log.Printf("reloaded TLS certificate from %s", c.certFile)
			}
		}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert, nil
}
