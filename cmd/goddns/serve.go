package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/filewatch"
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
	getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	manage  func(context.Context, []string) error // nil in files mode
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "config file")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
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
		go runProxy(cfg, px, src)
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
	default: // config.TLSFiles (validated in config.Load)
		f, err := tlsmgr.NewFiles(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		return &tlsSource{getCert: f.GetCertificate}, nil
	}
}

// runProxy blocks serving the reverse-proxy listener; fatal on exit, same
// contract as the DDNS listener. The optional plain-HTTP redirect listener
// is a convenience: failure to bind logs and is otherwise ignored.
func runProxy(cfg *config.Config, px *proxy.Proxy, src *tlsSource) {
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
		Handler:           px,
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

	for {
		select {
		case <-t.C:
			if _, ok := w.Changed(); !ok {
				if proxyDirty {
					applyProxy(cur.Load().cfg)
				}
				continue
			}
		case <-hup:
			log.Printf("SIGHUP: re-reading config")
			w.Changed() // refresh watcher state so the ticker doesn't re-fire
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

		applyProxy(cfg)

		cur.Store(&runtime{cfg: cfg, backend: backend})
		log.Printf("config reloaded from %s", path)

		if d := time.Duration(cfg.ReloadInterval) * time.Second; d > 0 && d != interval {
			interval = d
			t.Reset(interval)
		}
	}
}
