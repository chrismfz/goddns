package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/recordmut"
	"github.com/chrismfz/goddns/internal/tsig"
)

// cmdRecord edits records in a DYNAMIC zone via signed RFC2136 UPDATEs. It
// shows a diff and asks for confirmation, snapshots the zone first (Phase 1),
// and refuses static/panel-managed zones (the invariant).
//
//	goddns record add    <zone> '<rr in zone-file syntax>'
//	goddns record del    <zone> '<exact rr>'
//	goddns record delset <zone> <name> <type>
func cmdRecord(args []string) {
	if len(args) < 1 {
		recordUsage()
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "config file")
	yes := fs.Bool("y", false, "apply without the confirmation prompt")
	fs.Parse(args[1:])
	rest := fs.Args()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("%v", err)
	}

	var zone string
	var ops []ddns.Op
	switch sub {
	case "add", "del":
		if len(rest) != 2 {
			fatal("usage: goddns record %s <zone> '<rr>'", sub)
		}
		zone = rest[0]
		rr, err := dns.NewRR(rest[1])
		if err != nil || rr == nil {
			fatal("parse record %q: %v", rest[1], err)
		}
		act := ddns.AddRR
		if sub == "del" {
			act = ddns.DelRR
		}
		ops = []ddns.Op{{Action: act, RR: rr}}
	case "delset":
		if len(rest) != 3 {
			fatal("usage: goddns record delset <zone> <name> <type>")
		}
		zone = rest[0]
		rrtype, ok := dns.StringToType[strings.ToUpper(rest[2])]
		if !ok {
			fatal("unknown record type %q", rest[2])
		}
		ops = []ddns.Op{{Action: ddns.DelRRset, RR: &dns.RFC3597{Hdr: dns.RR_Header{
			Name: dns.Fqdn(rest[1]), Rrtype: rrtype, Class: dns.ClassINET}}}}
	default:
		recordUsage()
		os.Exit(2)
	}

	st := openStore(cfg)
	defer healDBOwnership(cfg.DBPath)
	defer st.Close()
	ed := &recordmut.Editor{
		NamedConf: cfg.NamedConf, DNSServer: cfg.DNSServer,
		Keys: editorKeys(cfg), Snap: st, Keep: cfg.HistoryKeep,
	}

	res, err := ed.Preview(zone, ops)
	if err != nil {
		fatal("%v", err)
	}
	printRecordDiff(res)
	if len(res.Added) == 0 && len(res.Removed) == 0 {
		fmt.Println("(nothing would change)")
		return
	}
	if !*yes && !confirmPrompt("apply to "+zone+"?") {
		fmt.Println("aborted")
		return
	}

	res, err = ed.Apply(zone, ops)
	if err != nil {
		fatal("apply: %v", err)
	}
	fmt.Printf("applied to %s (key %s)", res.Zone, res.Key)
	if res.Snapshot != 0 {
		fmt.Printf(" — snapshot taken; `goddns zone %s -diff` to review, restore is the next feature", res.Zone)
	}
	fmt.Println()
}

func printRecordDiff(res *recordmut.Result) {
	for _, l := range res.Removed {
		fmt.Printf("- %s\n", l)
	}
	for _, l := range res.Added {
		fmt.Printf("+ %s\n", l)
	}
}

// editorKeys returns goddns's keyring (from tsig_keys_file) or the single key.
func editorKeys(cfg *config.Config) []tsig.Key {
	if ks := cfg.TSIGKeys(); len(ks) > 0 {
		return ks
	}
	return []tsig.Key{{
		Name:   strings.TrimSuffix(cfg.TSIGName, "."),
		Algo:   cfg.TSIGAlgo,
		Secret: cfg.TSIGSecret,
	}}
}

func confirmPrompt(q string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", q)
	var s string
	fmt.Fscanln(os.Stdin, &s)
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "y" || s == "yes"
}

func recordUsage() {
	fmt.Fprintf(os.Stderr, `goddns record — edit records in a dynamic zone (RFC2136 UPDATE)

  goddns record add    <zone> '<rr>'            e.g. 'host.ddns.myip.gr. 60 IN A 1.2.3.4'
  goddns record del    <zone> '<rr>'            delete an exact record
  goddns record delset <zone> <name> <type>     delete a whole RRset
    -y    apply without the confirmation prompt
`)
}
