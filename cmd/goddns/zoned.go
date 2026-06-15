package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/zoned"
)

// cmdZoned runs the privileged write helper (design option b): a root service
// that performs static-zone file edits + rndc reloads on behalf of the
// unprivileged daemon, which connects over a goddns-group-only unix socket and
// sends only structured ops. The helper re-validates everything from its own
// config — so the internet-facing daemon never holds a /var/named descriptor.
func cmdZoned(args []string) {
	fs := flag.NewFlagSet("zoned", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "config file")
	socket := fs.String("socket", "", "unix socket path (default: zoned_socket from config, else /run/goddns/zoned.sock)")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("%v", err)
	}
	sock := *socket
	if sock == "" {
		sock = cfg.ZonedSocket
	}
	if sock == "" {
		sock = "/run/goddns/zoned.sock"
	}

	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		fatal("socket dir: %v", err)
	}
	_ = os.Remove(sock) // clear a stale socket
	ln, err := net.Listen("unix", sock)
	if err != nil {
		fatal("listen %s: %v", sock, err)
	}
	defer os.Remove(sock)
	// root:goddns 0660 — only the goddns group (the daemon) may connect.
	if gid, gerr := lookupGID("goddns"); gerr == nil {
		_ = os.Chown(sock, 0, gid)
	}
	_ = os.Chmod(sock, 0o660)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("goddns-zoned: root write helper listening on %s", sock)
	srv := &zoned.Server{Cfg: func() (*config.Config, error) { return config.Load(*cfgPath) }}
	srv.Serve(ctx, ln)
	log.Printf("goddns-zoned: shut down")
}

func lookupGID(group string) (int, error) {
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}
