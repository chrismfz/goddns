// Package server implements the HTTPS update endpoints:
//
//	/update/<token>            IP from connection, or ?ip= / ?myip=
//	/update/<token>/<ip>       path style
//	/nic/update                DynDNS2-compatible (router "Custom DDNS" clients)
//	/healthz
//
// Responses follow DynDNS2 conventions: good <ip>, nochg <ip>, badauth,
// nohost. nochg skips the DNS write entirely.
package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/store"
)

// Server reads its config and backend through accessor funcs so the serve
// loop can hot-swap them on config reload without restarting the listener.
type Server struct {
	Cfg     func() *config.Config
	Backend func() ddns.Backend
	Store   *store.Store
	GetCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/update/", s.handleSimple)
	mux.HandleFunc("/nic/update", s.handleDynDNS2)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	return mux
}

// Run blocks serving HTTPS on the listen address from the startup config.
func (s *Server) Run() error {
	cfg := s.Cfg()
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: s.GetCert,
		},
	}
	log.Printf("goddns listening on %s (tls=%s dns=%s key=%s)",
		cfg.Listen, cfg.TLSMode, cfg.DNSServer, cfg.TSIGName)
	// ListenAndServeTLS with empty paths -> uses GetCertificate.
	return srv.ListenAndServeTLS("", "")
}

// clientIP returns the source IP to register. Priority:
//  1. explicit override (param), validated
//  2. X-Forwarded-For, ONLY if the peer is a configured trusted proxy
//  3. the raw connection peer
func (s *Server) clientIP(r *http.Request, override string) (net.IP, error) {
	if override != "" {
		ip := net.ParseIP(strings.TrimSpace(override))
		if ip == nil {
			return nil, fmt.Errorf("invalid ip %q", override)
		}
		// RFC1918 is allowed (VPN/internal DDNS is a legitimate use), but
		// loopback/unspecified/multicast/link-local in a public record is
		// only ever a rebinding primitive — reject.
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return nil, fmt.Errorf("refusing non-routable ip %q", override)
		}
		return ip, nil
	}
	cfg := s.Cfg()
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer != nil && cfg.IsTrusted(peer) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			// Walk right-to-left; first hop that is NOT a trusted proxy is the client.
			for i := len(parts) - 1; i >= 0; i-- {
				cand := net.ParseIP(strings.TrimSpace(parts[i]))
				if cand != nil && !cfg.IsTrusted(cand) {
					return cand, nil
				}
			}
		}
	}
	if peer == nil {
		return nil, fmt.Errorf("could not determine client ip")
	}
	return peer, nil
}

func (s *Server) doUpdate(rec store.Record, ip net.IP) (changed bool, err error) {
	if rec.LastIP == ip.String() {
		// nochg: skip the DNS write, but still record the check-in so the
		// dashboard's "last seen" reflects that the client is alive and
		// polling even when its IP is stable. Best-effort: a stamp failure
		// here must not turn a healthy nochg into an error to the client.
		if err := s.Store.MarkSeen(rec.ID); err != nil {
			log.Printf("warning: could not persist last-seen for %s "+
				"(check /var/lib/goddns ownership): %v", rec.FQDN, err)
		}
		return false, nil
	}
	if err := s.Backend().Update(rec.FQDN, rec.Zone, ip, rec.TTL); err != nil {
		return false, err
	}
	// The DNS update succeeded; persist last-seen for the dashboard/CLI.
	// A failure here is NOT fatal (DNS is already updated) but must be
	// surfaced: a silent write failure (e.g. a root-owned WAL when the
	// daemon runs as goddns) leaves the record permanently "changed", so
	// every poll re-writes DNS and the dashboard shows stale "never".
	if err := s.Store.MarkUpdated(rec.ID, ip.String()); err != nil {
		log.Printf("warning: DNS updated but could not persist last-seen for %s "+
			"(dashboard will show stale data; check /var/lib/goddns ownership — the "+
			"daemon runs as the goddns user): %v", rec.FQDN, err)
	}
	return true, nil
}

func (s *Server) handleSimple(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/update/")
	rest = strings.Trim(rest, "/")
	if rest == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	segs := strings.SplitN(rest, "/", 2)
	token := segs[0]
	override := r.URL.Query().Get("ip")
	if override == "" {
		override = r.URL.Query().Get("myip")
	}
	if override == "" && len(segs) == 2 {
		override = segs[1]
	}

	rec, err := s.Store.Lookup(token)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "badauth", http.StatusForbidden)
		return
	} else if err != nil {
		http.Error(w, "911", http.StatusInternalServerError)
		log.Printf("lookup error: %v", err)
		return
	}

	ip, err := s.clientIP(r, override)
	if err != nil {
		http.Error(w, "badip", http.StatusBadRequest)
		return
	}

	changed, err := s.doUpdate(rec, ip)
	if err != nil {
		log.Printf("update %s -> %s failed: %v", rec.FQDN, ip, err)
		http.Error(w, "dnserr", http.StatusBadGateway)
		return
	}
	status := "nochg"
	if changed {
		status = "good"
		log.Printf("updated %s -> %s", rec.FQDN, ip)
	}
	fmt.Fprintf(w, "%s %s\n", status, ip)
}

// handleDynDNS2 implements the de-facto DynDNS2 update protocol so off-the-shelf
// router DDNS clients can be pointed straight at this server.
func (s *Server) handleDynDNS2(w http.ResponseWriter, r *http.Request) {
	// Token may arrive as Basic-auth password (username ignored) or ?token=.
	token := r.URL.Query().Get("token")
	if token == "" {
		if _, pass, ok := r.BasicAuth(); ok {
			token = pass
		}
	}
	if token == "" {
		fmt.Fprintln(w, "badauth")
		return
	}
	rec, err := s.Store.Lookup(token)
	if err != nil {
		fmt.Fprintln(w, "badauth")
		return
	}
	// Optional hostname check: if supplied it must match the token's FQDN.
	if h := r.URL.Query().Get("hostname"); h != "" && store.FQDN(h) != rec.FQDN {
		fmt.Fprintln(w, "nohost")
		return
	}

	override := r.URL.Query().Get("myip")
	ip, err := s.clientIP(r, override)
	if err != nil {
		fmt.Fprintln(w, "badip")
		return
	}
	changed, err := s.doUpdate(rec, ip)
	if err != nil {
		log.Printf("dyndns2 update %s -> %s failed: %v", rec.FQDN, ip, err)
		fmt.Fprintln(w, "dnserr 911")
		return
	}
	if changed {
		log.Printf("updated %s -> %s", rec.FQDN, ip)
		fmt.Fprintf(w, "good %s\n", ip)
	} else {
		fmt.Fprintf(w, "nochg %s\n", ip)
	}
}
