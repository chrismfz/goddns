package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
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
	fs.Parse(args)

	// goddns config is best-effort: only used to cross-check the TSIG key.
	var tsigName, tsigSecret, nc string
	if cfg, err := config.Load(*cfgPath); err == nil {
		tsigName, tsigSecret, nc = cfg.TSIGName, cfg.TSIGSecret, cfg.NamedConf
	}
	if *namedConf != "" {
		nc = *namedConf
	}
	if nc == "" {
		nc = "/etc/named.conf"
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

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "ZONE\tTYPE\tDYNAMIC\tKEY(S)")
	for _, z := range zones {
		dyn := "-"
		if z.Dynamic {
			dyn = "yes"
		}
		keys := strings.Join(z.UpdateKeys, ", ")
		if keys == "" {
			keys = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", z.Name, z.Type, dyn, keys)
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
