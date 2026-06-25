package tlsmgr

import (
	"crypto/tls"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"
)

// certSource is the subset of a cert provider hybrid needs from ACME; kept an
// interface so tests can inject a fake without a live CA.
type certSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// Hybrid serves the static file certificate whenever it covers the requested
// SNI and is in date, and falls back to ACME on-demand for any other name on
// the allowlist. It is the "tls_mode = hybrid" source:
//
//  1. file cert is valid and covers the name        -> serve it (free, instant)
//  2. else name is on the allowlist and ACME is set  -> ACME on-demand (cached)
//  3. else                                           -> file cert as a last
//     resort (a clear expired/mismatch error beats aborting the handshake)
//
// The allowlist is the security boundary: the proxy listener is public, so
// only names goddns already knows (proxy hosts / acme_domain / admin host /
// public_host) may trigger an ACME order. It is swapped atomically on reload.
type Hybrid struct {
	files *Files     // the static base; may be nil if the file pair won't load
	acme  certSource // ACME on-demand fallback; nil = files-only (degraded)
	allow atomic.Pointer[map[string]struct{}]
}

// NewHybrid builds a hybrid source over an optional file base. Call SetACME to
// attach the fallback and SetAllowed to seed the allowlist before serving.
func NewHybrid(files *Files) *Hybrid {
	h := &Hybrid{files: files}
	empty := map[string]struct{}{}
	h.allow.Store(&empty)
	return h
}

// SetACME attaches (or clears) the ACME on-demand fallback.
func (h *Hybrid) SetACME(a certSource) { h.acme = a }

// SetAllowed replaces the set of names ACME on-demand may be invoked for.
// Names are normalised (lowercased, trailing dot stripped) to match SNI.
func (h *Hybrid) SetAllowed(names []string) {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		if n = NormName(n); n != "" {
			m[n] = struct{}{}
		}
	}
	h.allow.Store(&m)
}

// Decide is the gate handed to ACME's on-demand solver: nil = allowed.
func (h *Hybrid) Decide(name string) error {
	if h.allowed(name) {
		return nil
	}
	return fmt.Errorf("on-demand issuance for %q refused: not a configured host", name)
}

func (h *Hybrid) allowed(name string) bool {
	m := *h.allow.Load()
	_, ok := m[NormName(name)]
	return ok
}

// GetCertificate is plugged into tls.Config.GetCertificate.
func (h *Hybrid) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := NormName(hello.ServerName)

	// 1. The static file cert, if it actually covers this name and is in date.
	if h.files != nil {
		if cert := h.files.matching(name, time.Now()); cert != nil {
			return cert, nil
		}
	}

	// 2. ACME on-demand, but only for names on the allowlist (the gate). The
	//    allowlist check here mirrors Decide so an off-list name never even
	//    reaches the solver.
	if h.acme != nil && name != "" && h.allowed(name) {
		if cert, err := h.acme.GetCertificate(hello); err == nil && cert != nil {
			return cert, nil
		} else if err != nil {
			log.Printf("hybrid: ACME fallback for %q failed: %v", name, err)
		}
	}

	// 3. Last resort: serve the file cert even if stale/mismatched (the client
	//    gets a clear certificate error rather than a dead handshake), else the
	//    ACME source, else fail.
	if h.files != nil {
		return h.files.GetCertificate(hello)
	}
	if h.acme != nil {
		return h.acme.GetCertificate(hello)
	}
	return nil, fmt.Errorf("hybrid: no certificate source available for %q", name)
}

// NormName canonicalises a hostname for SNI/allowlist comparison: trimmed,
// lowercased, trailing dot stripped. Exported so callers building the allowlist
// (serve.go) normalise names exactly as the matcher does.
func NormName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
