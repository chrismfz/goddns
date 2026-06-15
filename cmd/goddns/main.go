// goddns — self-hosted Dynamic DNS over RFC 2136 / TSIG.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/store"
)

// Injected by the Makefile via -ldflags (cfm-style date versioning).
var (
	Version   = "dev"
	BuildTime = "unknown"
)

const defaultConf = "/etc/goddns/goddns.conf"

func usage() {
	fmt.Fprintf(os.Stderr, `goddns %s — self-hosted Dynamic DNS over RFC 2136 / TSIG

Usage:
  goddns serve  [-config %s]
  goddns token add  -fqdn home.myip.gr -zone myip.gr [-ttl 60] [-config ...]
  goddns token list [-config ...]
  goddns token rotate -fqdn home.myip.gr [-config ...]  # new token, old stops
  goddns token del  -fqdn home.myip.gr [-config ...]
  goddns passwd -user chris        # bcrypt entry for proxy basic_auth
  goddns rotate-key [name]         # rotate a TSIG key in tsig_keys_file + rndc reconfig
  goddns record add|del|delset ... # edit records (dynamic: RFC2136; static: in-place file edit if enabled)
  goddns zone enable <zone>        # check a static zone is safe to add to editable_zones
  goddns zone edit|import|export <zone> [file]  # raw whole-file edit / import / export of an enabled static zone
  goddns vhost list|set|del ...    # manage reverse-proxy vhosts (proxy.d/ fragments)
  goddns zones [-check]                        # read-only: zones, dynamic, TSIG health (-check: NS serials)
  goddns zone home.myip.gr [-export|-check]    # read-only: live records via AXFR (+ backup, NS serials)
  goddns zone myip.gr -history | -diff         # zone snapshot history / what changed last
  goddns version
`, Version, defaultConf)
}

func cmdPasswd(args []string) {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	user := fs.String("user", "", "username for the basic_auth entry")
	fs.Parse(args)
	if *user == "" || strings.Contains(*user, ":") {
		fatal("passwd requires -user (without ':')")
	}

	readPass := func(prompt string) []byte {
		fmt.Fprint(os.Stderr, prompt)
		if term.IsTerminal(int(os.Stdin.Fd())) {
			p, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				fatal("reading password: %v", err)
			}
			return p
		}
		// piped input (scripting): one password per line
		var s string
		if _, err := fmt.Fscanln(os.Stdin, &s); err != nil {
			fatal("reading password: %v", err)
		}
		return []byte(s)
	}

	pass := readPass("Password: ")
	if len(pass) < 8 {
		fatal("password too short (min 8 characters)")
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		again := readPass("Repeat:   ")
		if string(pass) != string(again) {
			fatal("passwords do not match")
		}
	}
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
	if err != nil {
		fatal("bcrypt: %v", err)
	}
	fmt.Printf("%s:%s\n", *user, hash)
	fmt.Fprintf(os.Stderr, "\nAdd to the host's [proxy.\"...\"] section:\n  basic_auth = [\"%s:%s\"]\n", *user, hash)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "token":
		cmdToken(os.Args[2:])
	case "passwd":
		cmdPasswd(os.Args[2:])
	case "rotate-key":
		cmdRotateKey(os.Args[2:])
	case "record":
		cmdRecord(os.Args[2:])
	case "vhost":
		cmdVhost(os.Args[2:])
	case "zones":
		cmdZones(os.Args[2:])
	case "zone":
		cmdZone(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("goddns %s (built %s)\n", Version, BuildTime)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

// healDBOwnership keeps the SQLite files owned by the data dir's owner (the
// goddns service user). Running the CLI as root otherwise leaves the WAL/SHM
// files root-owned, after which the unprivileged daemon can't persist
// last-seen updates. No-op unless we're root and can chown.
func healDBOwnership(dbPath string) {
	if os.Geteuid() != 0 {
		return
	}
	fi, err := os.Stat(filepath.Dir(dbPath))
	if err != nil {
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Chown(dbPath+suffix, int(st.Uid), int(st.Gid))
	}
}

func openStore(cfg *config.Config) *store.Store {
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o750); err != nil {
		fatal("create db dir: %v", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		fatal("open store: %v", err)
	}
	return st
}

func cmdToken(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "config file")
	fqdnArg := fs.String("fqdn", "", "fully-qualified record name")
	zoneArg := fs.String("zone", "", "zone the record lives in")
	ttlArg := fs.Int("ttl", 60, "TTL for the record")
	fs.Parse(args[1:])

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("%v", err)
	}
	st := openStore(cfg)
	// LIFO: Close first, then heal ownership of the (now-flushed) db files.
	defer healDBOwnership(cfg.DBPath)
	defer st.Close()

	switch sub {
	case "add":
		if *fqdnArg == "" || *zoneArg == "" {
			fatal("token add requires -fqdn and -zone")
		}
		rec, tok, err := st.Add(*fqdnArg, *zoneArg, uint32(*ttlArg))
		if err != nil {
			fatal("add: %v", err)
		}
		fmt.Printf("Created %s (zone %s, ttl %d)\n", rec.FQDN, rec.Zone, rec.TTL)
		fmt.Printf("Token (store it now, shown once):\n  %s\n\n", tok)
		fmt.Printf("Test:\n  curl \"https://%s%s/update/%s\"\n", serverHost(cfg), listenPort(cfg), tok)
		fmt.Printf("\nNote: the URL IS the credential. Anything that fetches it (chat link\npreviews, URL scanners) triggers an update — never paste it into chats.\n")
	case "list":
		recs, err := st.List()
		if err != nil {
			fatal("list: %v", err)
		}
		if len(recs) == 0 {
			fmt.Println("(no records)")
			return
		}
		for _, r := range recs {
			fmt.Println(r)
		}
	case "rotate":
		if *fqdnArg == "" {
			fatal("token rotate requires -fqdn")
		}
		rec, tok, err := st.Rotate(*fqdnArg)
		if err != nil {
			fatal("rotate: %v", err)
		}
		fmt.Printf("Rotated %s — the previous token no longer works.\n", rec.FQDN)
		fmt.Printf("New token (store it now, shown once):\n  %s\n", tok)
	case "del":
		if *fqdnArg == "" {
			fatal("token del requires -fqdn")
		}
		if err := st.Del(*fqdnArg); err != nil {
			fatal("del: %v", err)
		}
		fmt.Printf("Deleted %s\n", store.FQDN(*fqdnArg))
	default:
		usage()
		os.Exit(2)
	}
}

// serverHost picks the best name for example URLs: the ACME domain when
// configured (that's the name on the cert), otherwise the machine hostname.
func serverHost(cfg *config.Config) string {
	if cfg.ACMEDomain != "" {
		return cfg.ACMEDomain
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "<this-host>"
}

// listenPort renders the ":port" suffix of the configured listen address
// (empty for :443 so example URLs stay clean).
func listenPort(cfg *config.Config) string {
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil || port == "" || port == "443" {
		return ""
	}
	return ":" + port
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "goddns: "+format+"\n", a...)
	os.Exit(1)
}
