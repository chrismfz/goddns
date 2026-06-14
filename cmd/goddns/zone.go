package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/named"
)

// cmdZone is the read-only per-zone viewer: it pulls the LIVE zone contents
// from BIND via AXFR (journal-merged, so it shows exactly what the server
// answers, not a possibly-stale zone file) and prints every record. With
// -export it emits a loadable zone-file snapshot, handy as a backup. It never
// writes anything.
func cmdZone(args []string) {
	// The zone name is the first positional arg; allow it before the flags.
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet("zone", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "goddns config (for dns_server + TSIG keys)")
	namedConf := fs.String("named-conf", "", "named.conf path (default: from goddns.conf / /etc/named.conf)")
	server := fs.String("server", "", "DNS server to AXFR from (default: dns_server from goddns.conf)")
	keyName := fs.String("key", "", "force a specific named.conf TSIG key for the transfer")
	export := fs.Bool("export", false, "print a zone-file snapshot (loadable backup) instead of a table")
	fs.Parse(args)
	if name == "" {
		name = fs.Arg(0)
	}
	if name == "" {
		fatal("usage: goddns zone <name> [-export] [-server host] [-key name]")
	}

	var tsigName, srv, nc string
	if cfg, err := config.Load(*cfgPath); err == nil {
		tsigName, srv, nc = cfg.TSIGName, cfg.DNSServer, cfg.NamedConf
	}
	if *namedConf != "" {
		nc = *namedConf
	}
	if nc == "" {
		nc = "/etc/named.conf"
	}
	if *server != "" {
		srv = *server
	}
	if srv == "" {
		srv = "127.0.0.1:53"
	}

	// The named.conf inventory gives us the zone's dynamic flag and the TSIG
	// keys (with secrets) to authenticate the transfer. It's best-effort: if
	// we can't read named.conf we still attempt an unauthenticated AXFR.
	var inv *named.Inventory
	if data, err := named.CheckConf(nc); err == nil {
		inv = named.Parse(data)
	} else {
		inv = &named.Inventory{}
		fmt.Fprintf(os.Stderr, "note: %v (trying unauthenticated AXFR)\n\n", err)
	}
	z := inv.ZoneByName(name)

	records, err := transfer(inv, z, name, srv, tsigName, *keyName)
	if err != nil {
		fatal("%v\n\nIf this is REFUSED, allow the transfer on the server, e.g. in the zone or options:\n  allow-transfer { localhost; };   (goddns runs locally)\nor force a key with -key <name>.", err)
	}

	named.SortZone(records)

	if *export {
		// A canonical, loadable snapshot. Comments/$ORIGIN from the original
		// file are not preserved (AXFR carries records, not source text), but
		// it reloads cleanly and is a fine backup of the live state.
		for _, rr := range records {
			fmt.Println(rr.String())
		}
		return
	}

	printZoneHeader(name, z, records)

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTTL\tTYPE\tDATA")
	for _, row := range named.Rows(records) {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", row.Name, row.TTL, row.Type, row.Data)
	}
	w.Flush()
}

// transfer picks the authentication path: a forced key, or the automatic
// fallback (unauthenticated, then each candidate key from named.conf).
func transfer(inv *named.Inventory, z *named.Zone, name, server, goddnsKey, forceKey string) ([]dns.RR, error) {
	if forceKey != "" {
		want := strings.TrimSuffix(forceKey, ".")
		for _, k := range inv.Keys {
			if k.Name == want {
				return named.Transfer(name, server, &named.TSIGKey{Name: k.Name, Algo: k.Algorithm, Secret: k.Secret})
			}
		}
		return nil, fmt.Errorf("key %q not found in named.conf", forceKey)
	}
	return named.TransferAuto(name, server, inv.AXFRKeys(z, goddnsKey))
}

// printZoneHeader writes the one-line summary: zone kind, dynamic status, the
// update keys, and the SOA serial — the "is this dynamic?" answer up front.
func printZoneHeader(name string, z *named.Zone, records []dns.RR) {
	kind, dyn := "(not in named.conf)", ""
	if z != nil {
		kind = z.Kind()
		if z.Dynamic {
			keys := strings.Join(z.UpdateKeys, ", ")
			if keys == "" {
				keys = z.AllowUpdate
			}
			dyn = "  DYNAMIC (updates: " + keys + ")"
		} else {
			dyn = "  static (hand-edited file)"
		}
	}
	fmt.Printf("zone: %s   [%s]%s\n", name, kind, dyn)
	if soa := named.SOAOf(records); soa != nil {
		fmt.Printf("serial: %d   primary: %s   %d records\n\n", soa.Serial, strings.TrimSuffix(soa.Ns, "."), len(records))
	} else {
		fmt.Printf("%d records\n\n", len(records))
	}
}
