package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/named"
)

// cmdZones is the read-only BIND introspection: zones, dynamic flags, TSIG
// keys and a consistency check against goddns's own key. It never edits.
func cmdZones(args []string) {
	fs := flag.NewFlagSet("zones", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "goddns config (for the TSIG cross-check)")
	namedConf := fs.String("named-conf", "", "named.conf path (default: from goddns.conf / /etc/named.conf)")
	dump := fs.String("dump", "", "read a pre-captured 'named-checkconf -p' file instead of running it")
	all := fs.Bool("all", false, "include BIND's built-in empty zones")
	check := fs.Bool("check", false, "probe each zone's nameservers for the serial they serve")
	fs.Parse(args)

	// goddns config is best-effort: the TSIG cross-check and the AXFR/probe
	// server (dns_server) come from it.
	var tsigName, tsigSecret, nc, server string
	if cfg, err := config.Load(*cfgPath); err == nil {
		tsigName, tsigSecret, nc, server = cfg.TSIGName, cfg.TSIGSecret, cfg.NamedConf, cfg.DNSServer
	}
	if *namedConf != "" {
		nc = *namedConf
	}
	if nc == "" {
		nc = "/etc/named.conf"
	}
	if server == "" {
		server = "127.0.0.1:53"
	}

	var data []byte
	var err error
	if *dump != "" {
		data, err = os.ReadFile(*dump)
	} else {
		data, err = named.CheckConf(nc)
	}
	if err != nil {
		fatal("%v", err)
	}

	inv := named.Parse(data)
	zones := inv.Zones
	if !*all {
		zones = inv.UserZones()
	}

	if inv.Directory != "" {
		fmt.Printf("directory: %s\n\n", inv.Directory)
	}
	hasView := false
	for _, z := range zones {
		if z.View != "" {
			hasView = true
			break
		}
	}

	// On demand: probe every zone's nameservers concurrently for the serial
	// they serve (read-only AXFR + SOA queries).
	nsv := make([]string, len(zones))
	if *check {
		var wg sync.WaitGroup
		for i := range zones {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				nsv[i] = zoneSerial(zones[i], inv, server, tsigName)
			}(i)
		}
		wg.Wait()
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	header := "ZONE\tKIND\tFILE\tKEY(S)"
	if hasView {
		header = "VIEW\t" + header
	}
	if *check {
		header += "\tNS"
	}
	fmt.Fprintln(w, header)
	for i, z := range zones {
		keys := strings.Join(z.UpdateKeys, ", ")
		if keys == "" {
			keys = "-"
		}
		file := z.Path
		if file == "" {
			file = "-"
		} else if st := named.FileStatus(z.Path, z.Dynamic); st != "" {
			file += " (" + st + ")"
		}
		var b strings.Builder
		if hasView {
			fmt.Fprintf(&b, "%s\t", z.View)
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s", z.Name, z.Kind(), file, keys)
		if *check {
			fmt.Fprintf(&b, "\t%s", nsv[i])
		}
		fmt.Fprintln(w, b.String())
	}
	w.Flush()
	if !*all {
		if n := len(inv.Zones) - len(zones); n > 0 {
			fmt.Printf("(+ %d built-in empty zones; -all to show)\n", n)
		}
	}

	fmt.Println("\nTSIG keys:")
	if len(inv.Keys) == 0 {
		fmt.Println("  (none)")
	}
	kw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	for _, k := range inv.Keys {
		fmt.Fprintf(kw, "  %s\t%s\n", k.Name, k.Algorithm) // secret never printed
	}
	kw.Flush()

	fmt.Println("\nChecks:")
	findings := inv.Check(tsigName, tsigSecret)
	if len(findings) == 0 {
		fmt.Println("  (nothing to report)")
	}
	for _, f := range findings {
		mark := map[named.Severity]string{named.OK: "✓", named.Info: "·", named.Warn: "⚠", named.Error: "✗"}[f.Severity]
		if f.Zone != "" {
			fmt.Printf("  %s %s: %s\n", mark, f.Zone, f.Message)
		} else {
			fmt.Printf("  %s %s\n", mark, f.Message)
		}
	}
}

// zoneSerial probes one zone's nameservers (AXFR to learn the apex NS, then a
// direct SOA query to each) and returns a short serial-agreement verdict.
// Non-master zones have no apex NS to compare. Read-only.
func zoneSerial(z named.Zone, inv *named.Inventory, server, tsigName string) string {
	switch z.Kind() {
	case "static file", "dynamic":
	default:
		return "-"
	}
	records, _, err := named.TransferAuto(z.Name, server, inv.AXFRKeys(&z, tsigName))
	if err != nil {
		return "axfr-err"
	}
	checks := named.CheckNameservers(z.Name, records, server)
	if len(checks) == 0 {
		return "no-NS"
	}
	agree, seen := named.SerialsAgree(checks)
	switch {
	case len(seen) == 0:
		return "unreachable"
	case agree:
		for s := range seen {
			return fmt.Sprintf("✓ %d", s)
		}
	}
	return "✗ MISMATCH"
}
