package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/filewatch"
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

	getCert, err := buildTLS(cfg)
	if err != nil {
		fatal("%v", err)
	}

	srv := &server.Server{
		Cfg:     func() *config.Config { return cur.Load().cfg },
		Backend: func() ddns.Backend { return cur.Load().backend },
		Store:   st,
		GetCert: getCert,
	}

	go reloadLoop(*cfgPath, &cur)

	if err := srv.Run(); err != nil {
		fatal("server: %v", err)
	}
}

func buildTLS(cfg *config.Config) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), error) {
	switch cfg.TLSMode {
	case config.TLSACME:
		a, err := tlsmgr.NewACME(context.Background(), tlsmgr.ACMEOptions{
			Domain:     cfg.ACMEDomain,
			Email:      cfg.ACMEEmail,
			CA:         cfg.ACMECA,
			Storage:    cfg.ACMEStorage,
			DNSServer:  cfg.DNSServer,
			TSIGName:   cfg.ACMETSIGName,
			TSIGAlgo:   cfg.ACMETSIGAlgo,
			TSIGSecret: cfg.ACMETSIGSecret,
		})
		if err != nil {
			return nil, err
		}
		return a.GetCertificate, nil
	default: // config.TLSFiles (validated in config.Load)
		f, err := tlsmgr.NewFiles(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		return f.GetCertificate, nil
	}
}

// reloadLoop polls the config file (mtime+sha256, like cfm's main tick loop)
// and swaps the runtime bundle on change. SIGHUP forces an immediate check.
func reloadLoop(path string, cur *atomic.Pointer[runtime]) {
	w := filewatch.New(path)
	w.Changed() // prime with the already-loaded state

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

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
		cur.Store(&runtime{cfg: cfg, backend: backend})
		log.Printf("config reloaded from %s", path)

		if d := time.Duration(cfg.ReloadInterval) * time.Second; d > 0 && d != interval {
			interval = d
			t.Reset(interval)
		}
	}
}
