package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/chrismfz/goddns/internal/admin"
	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/filewatch"
	"github.com/chrismfz/goddns/internal/history"
	"github.com/chrismfz/goddns/internal/proxy"
	"github.com/chrismfz/goddns/internal/server"
	"github.com/chrismfz/goddns/internal/tlsmgr"
)

// runtime is the hot-swappable bundle the request handlers read through an
// atomic pointer: a config edit is picked up by the cfm-style polling loop
// below and swapped in without dropping the listener.
type runtime struct {
	cfg     *config.Config
	backend ddns.Backend
}

// tlsSource is what buildTLS hands back: the handshake callback plus, in
// acme mode, the ability to bring new hostnames under management at reload.
type tlsSource struct {
	getCert    func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	manage     func(context.Context, []string) error // nil outside acme mode
	setAllowed func([]string)                        // nil outside hybrid mode; updates the on-demand allowlist
}

// logTarget owns one hot-swappable log file (log_file / access_log in the
// config). Empty path = the fallback (stderr/journald for the main log,
// merged-into-main for the access log). Rotation is handled by the shipped
// logrotate config with copytruncate, so no reopen signal is needed.
type logTarget struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// swap opens path and returns (writer, changed). nil writer with
// changed=true means "path cleared, revert to the fallback".
func (t *logTarget) swap(path string) (*os.File, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if path == t.path {
		return nil, false, nil
	}
	var f *os.File
	if path != "" {
		var err error
		f, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, false, err
		}
	}
	if t.f != nil {
		t.f.Close()
	}
	t.f, t.path = f, path
	return f, true, nil
}

var (
	mainLogTarget   logTarget
	accessLogTarget logTarget
)

func applyLogConfig(cfg *config.Config) error {
	if f, changed, err := mainLogTarget.swap(cfg.LogFile); err != nil {
		return fmt.Errorf("log_file %s: %w", cfg.LogFile, err)
	} else if changed {
		if f == nil {
			log.SetOutput(os.Stderr)
		} else {
			log.SetOutput(f)
		}
	}
	if f, changed, err := accessLogTarget.swap(cfg.AccessLog); err != nil {
		return fmt.Errorf("access_log %s: %w", cfg.AccessLog, err)
	} else if changed {
		if f == nil {
			proxy.SetAccessLogger(nil)
		} else {
			proxy.SetAccessLogger(log.New(f, "", log.LstdFlags))
		}
	}
	return nil
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "config file")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("%v", err)
	}
	if err := applyLogConfig(cfg); err != nil {
		fatal("%v", err)
	}
	backend, err := ddns.NewRFC2136(cfg.DNSServer, cfg.TSIGName, cfg.TSIGAlgo, cfg.TSIGSecret)
	if err != nil {
		fatal("%v", err)
	}

	var cur atomic.Pointer[runtime]
	cur.Store(&runtime{cfg: cfg, backend: backend})

	st := openStore(cfg)
	defer st.Close()

	// Zone history poller (read-only): snapshots zones on SOA-serial change.
	// Self-disables when history_interval <= 0, re-checked at reload.
	go (&history.Poller{Cfg: func() *config.Config { return cur.Load().cfg }, Store: st}).Run(context.Background())

	src, err := buildTLS(cfg)
	if err != nil {
		fatal("%v", err)
	}

	srv := &server.Server{
		Cfg:     func() *config.Config { return cur.Load().cfg },
		Backend: func() ddns.Backend { return cur.Load().backend },
		Store:   st,
		GetCert: src.getCert,
	}

	var px *proxy.Proxy
	if cfg.ProxyEnabled {
		px = proxy.New()
		if err := px.Update(cfg); err != nil {
			fatal("proxy: %v", err)
		}
		var adminH http.Handler
		if cfg.Admin.Enabled {
			secret, err := admin.LoadSecret(filepath.Join(filepath.Dir(cfg.DBPath), "admin.secret"))
			if err != nil {
				fatal("admin secret: %v", err)
			}
			ah := admin.New(func() *config.Config { return cur.Load().cfg }, st, secret, Version)
			// Live per-host proxy traffic counters for the dashboard panel.
			ah.SetProxyStats(px.Stats)
			// Let the admin UI manage proxy.d/ vhost fragments, and reload
			// immediately after a write (SIGHUP, same path the poll uses).
			ah.EnableVhostEditing(*cfgPath, func() {
				_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)
			})
			adminH = ah
			log.Printf("admin UI enabled at https://%s%s", cfg.Admin.Host, cfg.ProxyListen)
			if len(cfg.Admin.Allow) == 0 && len(cfg.Admin.BasicAuth) == 0 {
				log.Printf("WARNING: admin has no 'allow' CIDR list and no 'basic_auth' — the login " +
					"form is reachable from anywhere (login throttling is on, but set allow and/or " +
					"basic_auth for an internet-facing host)")
			}
		}
		go runProxy(cfg, px, src, adminH)
	}

	go reloadLoop(*cfgPath, &cur, px, src)

	if err := srv.Run(); err != nil {
		fatal("server: %v", err)
	}
}

func buildTLS(cfg *config.Config) (*tlsSource, error) {
	switch cfg.TLSMode {
	case config.TLSACME:
		var extra []string
		if cfg.ProxyEnabled {
			extra = cfg.ProxyHosts()
		}
		a, err := tlsmgr.NewACME(context.Background(), tlsmgr.ACMEOptions{
			Domain:       cfg.ACMEDomain,
			ExtraDomains: extra,
			Email:        cfg.ACMEEmail,
			CA:           cfg.ACMECA,
			Storage:      cfg.ACMEStorage,
			DNSServer:    cfg.DNSServer,
			TSIGName:     cfg.ACMETSIGName,
			TSIGAlgo:     cfg.ACMETSIGAlgo,
			TSIGSecret:   cfg.ACMETSIGSecret,
		})
		if err != nil {
			return nil, err
		}
		return &tlsSource{getCert: a.GetCertificate, manage: a.Manage}, nil
	case config.TLSHybrid:
		// Static file cert is the base; ACME on-demand is the gated fallback.
		// A bad file pair shouldn't kill TLS if ACME can still serve, so a load
		// failure degrades to ACME-only with a warning rather than a fatal.
		f, err := tlsmgr.NewFiles(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			log.Printf("hybrid: file cert unusable (%v) — relying on ACME on-demand", err)
			f = nil
		}
		h := tlsmgr.NewHybrid(f)
		h.SetAllowed(hybridNames(cfg))
		if cfg.ACMETSIGSecret == "" {
			log.Printf("hybrid: ACME fallback disabled (no acme_tsig_secret / tsig_secret) — " +
				"serving the file cert only until a TSIG secret is set")
		} else {
			a, err := tlsmgr.NewACME(context.Background(), tlsmgr.ACMEOptions{
				Domain:     cfg.ACMEDomain,
				Email:      cfg.ACMEEmail,
				CA:         cfg.ACMECA,
				Storage:    cfg.ACMEStorage,
				DNSServer:  cfg.DNSServer,
				TSIGName:   cfg.ACMETSIGName,
				TSIGAlgo:   cfg.ACMETSIGAlgo,
				TSIGSecret: cfg.ACMETSIGSecret,
				OnDemand:   true,
				Decide:     h.Decide,
			})
			if err != nil {
				log.Printf("hybrid: ACME fallback disabled (%v) — serving the file cert only", err)
			} else {
				h.SetACME(a)
			}
		}
		return &tlsSource{getCert: h.GetCertificate, setAllowed: h.SetAllowed}, nil
	default: // config.TLSFiles (validated in config.Load)
		f, err := tlsmgr.NewFiles(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		return &tlsSource{getCert: f.GetCertificate}, nil
	}
}

// hybridNames is the on-demand allowlist for tls_mode = hybrid: every name
// goddns already knows about and would legitimately terminate TLS for. Any SNI
// outside this set is refused an ACME order (the public-listener rate-limit
// guard). Recomputed on each reload so new proxy hosts become eligible.
func hybridNames(cfg *config.Config) []string {
	set := map[string]struct{}{}
	add := func(s string) {
		if s = tlsmgr.NormName(s); s != "" {
			set[s] = struct{}{}
		}
	}
	if cfg.ProxyEnabled {
		for _, h := range cfg.ProxyHosts() {
			add(h)
		}
	}
	add(cfg.ACMEDomain)
	add(cfg.PublicHost)
	if cfg.Admin.Enabled {
		add(cfg.Admin.Host)
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}

// runProxy blocks serving the reverse-proxy listener; fatal on exit, same
// contract as the DDNS listener. The optional plain-HTTP redirect listener
// is a convenience: failure to bind logs and is otherwise ignored.
func runProxy(cfg *config.Config, px *proxy.Proxy, src *tlsSource, adminH http.Handler) {
	// The admin UI is a built-in vhost: requests for admin.Host go to it,
	// everything else to the reverse proxy. Same TLS, same listener.
	var handler http.Handler = px
	if adminH != nil {
		adminHost := cfg.Admin.Host
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := strings.ToLower(r.Host)
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if strings.TrimSuffix(host, ".") == adminHost {
				adminH.ServeHTTP(w, r)
				return
			}
			px.ServeHTTP(w, r)
		})
	}
	if cfg.ProxyRedirectListen != "" {
		httpsPort := "443"
		if _, p, err := net.SplitHostPort(cfg.ProxyListen); err == nil {
			httpsPort = p
		}
		go func() {
			rs := &http.Server{
				Addr:              cfg.ProxyRedirectListen,
				Handler:           px.RedirectHandler(httpsPort),
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       2 * time.Minute,
			}
			if err := rs.ListenAndServe(); err != nil {
				log.Printf("proxy redirect listener (%s) failed: %v — continuing without it",
					cfg.ProxyRedirectListen, err)
			}
		}()
	}
	ps := &http.Server{
		Addr:              cfg.ProxyListen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: BMC console sessions are long-lived streams.
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: src.getCert,
		},
	}
	log.Printf("goddns proxy listening on %s (%d hosts)", cfg.ProxyListen, len(cfg.Proxy))
	if err := ps.ListenAndServeTLS("", ""); err != nil {
		fatal("proxy server: %v", err)
	}
}

// watchSig is a cheap signature of the side files the reload poll must track
// even though filewatch only hashes the main config file: the proxy.d/*.conf
// fragments and the tsig_keys_file. A change in either triggers a reload (so a
// `goddns rotate-key` is picked up by the running daemon automatically).
func watchSig(confPath string, cfg *config.Config) string {
	var b strings.Builder
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(confPath), "proxy.d", "*.conf"))
	slices.Sort(files)
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil {
			fmt.Fprintf(&b, "%s:%d:%d\n", f, fi.Size(), fi.ModTime().UnixNano())
		}
	}
	if cfg.TSIGKeysFile != "" {
		if fi, err := os.Stat(cfg.TSIGKeysFile); err == nil {
			fmt.Fprintf(&b, "tsig:%d:%d\n", fi.Size(), fi.ModTime().UnixNano())
		}
	}
	return b.String()
}

// reloadLoop polls the config file (mtime+sha256, like cfm's main tick loop)
// and swaps the runtime bundle on change. SIGHUP forces an immediate check.
func reloadLoop(path string, cur *atomic.Pointer[runtime], px *proxy.Proxy, src *tlsSource) {
	w := filewatch.New(path)
	w.Changed() // prime with the already-loaded state

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	// Proxy state is tracked separately from cur so that a failed apply
	// (route compile error, transient ACME failure) is retried on every
	// tick instead of being masked by the already-stored new config.
	appliedHosts := cur.Load().cfg.ProxyHosts()
	proxyDirty := false

	applyProxy := func(cfg *config.Config) {
		if px == nil {
			return
		}
		if !cfg.ProxyEnabled {
			// Fail-safe: flipping the knob off empties the table (all 404)
			// even though dropping the listener itself needs a restart.
			if len(appliedHosts) > 0 {
				_ = px.Update(&config.Config{})
				appliedHosts = nil
			}
			proxyDirty = false
			return
		}
		if err := px.Update(cfg); err != nil {
			log.Printf("proxy reload failed, keeping previous routes (will retry): %v", err)
			proxyDirty = true
			return
		}
		hosts := cfg.ProxyHosts()
		if src.manage != nil && !slices.Equal(hosts, appliedHosts) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			err := src.manage(ctx, hosts)
			cancel()
			if err != nil {
				log.Printf("acme: managing proxy hosts (will retry): %v", err)
				proxyDirty = true
				return
			}
		}
		appliedHosts = hosts
		proxyDirty = false
	}

	interval := time.Duration(cur.Load().cfg.ReloadInterval) * time.Second
	if interval <= 0 {
		interval = 20 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	// proxy.d/ fragments and the tsig key file aren't the watched file, so
	// track their signature separately and reload when it changes (matches
	// inline-edit ergonomics; picks up a key rotation automatically).
	lastSig := watchSig(path, cur.Load().cfg)

	for {
		select {
		case <-t.C:
			_, mainChanged := w.Changed()
			sig := watchSig(path, cur.Load().cfg)
			if !mainChanged && sig == lastSig {
				if proxyDirty {
					applyProxy(cur.Load().cfg)
				}
				continue
			}
			lastSig = sig
		case <-hup:
			log.Printf("SIGHUP: re-reading config")
			w.Changed() // refresh watcher state so the ticker doesn't re-fire
			lastSig = watchSig(path, cur.Load().cfg)
		}

		old := cur.Load()
		cfg, err := config.Load(path)
		if err != nil {
			log.Printf("config reload failed, keeping previous config: %v", err)
			continue
		}
		backend, err := ddns.NewRFC2136(cfg.DNSServer, cfg.TSIGName, cfg.TSIGAlgo, cfg.TSIGSecret)
		if err != nil {
			log.Printf("config reload failed, keeping previous config: %v", err)
			continue
		}
		if fields := cfg.NeedsRestart(old.cfg); len(fields) > 0 {
			log.Printf("config reloaded, but changes to %s need a restart to take effect",
				strings.Join(fields, ", "))
		}
		if err := applyLogConfig(cfg); err != nil {
			log.Printf("%v — keeping current log output", err)
		}

		applyProxy(cfg)

		// hybrid mode: a reload may have added/removed proxy hosts (or moved
		// the admin/public name), so refresh the on-demand allowlist.
		if src.setAllowed != nil {
			src.setAllowed(hybridNames(cfg))
		}

		cur.Store(&runtime{cfg: cfg, backend: backend})
		log.Printf("config reloaded from %s", path)

		if d := time.Duration(cfg.ReloadInterval) * time.Second; d > 0 && d != interval {
			interval = d
			t.Reset(interval)
		}
	}
}
