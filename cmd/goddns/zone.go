package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/history"
	"github.com/chrismfz/goddns/internal/named"
)

// cmdZoneHistory handles `goddns zone <name> -history` (list snapshots) and
// `-diff` (show the change in the most recent snapshot). Read-only: it only
// reads the snapshots the serve loop has stored.
func cmdZoneHistory(name, cfgPath string, list bool) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fatal("%v", err)
	}
	st := openStore(cfg)
	defer healDBOwnership(cfg.DBPath)
	defer st.Close()

	if list {
		snaps, err := st.SnapshotList(name, 0)
		if err != nil {
			fatal("history: %v", err)
		}
		if len(snaps) == 0 {
			fmt.Printf("no snapshots for %s yet (serve captures them; history_interval=%ds)\n", name, cfg.HistoryInterval)
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "SERIAL\tTAKEN\tID")
		for _, s := range snaps {
			fmt.Fprintf(w, "%d\t%s\t%d\n", s.Serial, s.TakenAt.Format("2006-01-02 15:04"), s.ID)
		}
		w.Flush()
		fmt.Printf("\n%d snapshots. See the latest change: goddns zone %s -diff\n", len(snaps), name)
		return
	}

	snaps, err := st.SnapshotList(name, 2)
	if err != nil {
		fatal("history: %v", err)
	}
	if len(snaps) < 2 {
		fmt.Printf("need at least two snapshots of %s to diff (have %d)\n", name, len(snaps))
		return
	}
	newer, _, _ := st.SnapshotByID(snaps[0].ID)
	older, _, _ := st.SnapshotByID(snaps[1].ID)
	added, removed := history.Diff(older.Content, newer.Content)
	fmt.Printf("zone %s: serial %d → %d   (%s → %s)\n\n",
		name, older.Serial, newer.Serial,
		older.TakenAt.Format("2006-01-02 15:04"), newer.TakenAt.Format("2006-01-02 15:04"))
	for _, l := range removed {
		fmt.Printf("- %s\n", l)
	}
	for _, l := range added {
		fmt.Printf("+ %s\n", l)
	}
	if len(added) == 0 && len(removed) == 0 {
		fmt.Println("(no record changes between these two snapshots)")
	}
}

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
	check := fs.Bool("check", false, "also probe each apex nameserver live for the SOA serial they serve")
	histList := fs.Bool("history", false, "list stored history snapshots for the zone")
	histDiff := fs.Bool("diff", false, "show what changed in the most recent snapshot (vs the previous)")
	fs.Parse(args)
	if name == "" {
		name = fs.Arg(0)
	}
	if name == "" {
		fatal("usage: goddns zone <name> [-export|-check|-history|-diff] [-server host] [-key name]")
	}

	if *histList || *histDiff {
		cmdZoneHistory(name, *cfgPath, *histList)
		return
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

	records, auth, err := transfer(inv, z, name, srv, tsigName, *keyName)
	if err != nil {
		fatal("%v\n\nIf this is REFUSED, allow the transfer on the server, e.g. in the zone or options:\n  allow-transfer { localhost; };   (goddns runs locally)\nor force a key with -key <name>.", err)
	}

	named.SortZone(records)

	if *export {
		writeExport(os.Stdout, name, srv, auth, z, records)
		return
	}

	printZoneHeader(name, auth, z, records)

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTTL\tTYPE\tDATA")
	for _, row := range named.Rows(records) {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", row.Name, row.TTL, row.Type, row.Data)
	}
	w.Flush()

	printChecks(name, srv, records, *check)
}

// printChecks renders the Tier 1 (offline SOA-vs-NS) findings always, and the
// Tier 2 (live per-nameserver SOA serial) probe when requested.
func printChecks(name, resolver string, records []dns.RR, live bool) {
	mark := map[named.Severity]string{named.OK: "✓", named.Info: "·", named.Warn: "⚠", named.Error: "✗"}
	fmt.Println("\nSOA / NS checks:")
	for _, f := range named.CheckDelegation(name, records) {
		fmt.Printf("  %s %s\n", mark[f.Severity], f.Message)
	}
	if !live {
		fmt.Println("  (add -check to probe each nameserver's live serial)")
		return
	}

	checks := named.CheckNameservers(name, records, resolver)
	if len(checks) == 0 {
		return
	}
	fmt.Println("\nNameservers (live):")
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "  NS\tADDRESS\tSERIAL\tSTATUS")
	for _, c := range checks {
		addr, serial, status := "-", "-", "ok"
		if len(c.Addrs) > 0 {
			addr = c.Addrs[0]
		}
		if c.Serial != 0 {
			serial = fmt.Sprintf("%d", c.Serial)
		}
		if !c.OK {
			if status = c.Note; status == "" {
				status = "?"
			}
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", c.Name, addr, serial, status)
	}
	w.Flush()

	agree, seen := named.SerialsAgree(checks)
	switch {
	case len(seen) == 0:
		fmt.Println("  ⚠ no nameserver answered authoritatively")
	case agree:
		for s := range seen {
			fmt.Printf("  ✓ all nameservers agree on serial %d\n", s)
		}
	default:
		fmt.Println("  ✗ SERIAL MISMATCH across nameservers:")
		for _, c := range checks {
			if c.OK {
				fmt.Printf("      %s → %d\n", c.Name, c.Serial)
			}
		}
	}
}

// transfer picks the authentication path: a forced key, or the automatic
// fallback (unauthenticated, then each candidate key from named.conf).
func transfer(inv *named.Inventory, z *named.Zone, name, server, goddnsKey, forceKey string) ([]dns.RR, string, error) {
	if forceKey != "" {
		want := strings.TrimSuffix(forceKey, ".")
		for _, k := range inv.Keys {
			if k.Name == want {
				rrs, err := named.Transfer(name, server, &named.TSIGKey{Name: k.Name, Algo: k.Algorithm, Secret: k.Secret})
				return rrs, `key "` + k.Name + `"`, err
			}
		}
		return nil, "", fmt.Errorf("key %q not found in named.conf", forceKey)
	}
	return named.TransferAuto(name, server, inv.AXFRKeys(z, goddnsKey))
}

// writeExport emits a canonical, loadable zone-file snapshot prefixed with a
// comment header that records what the zone is (dynamic vs static) and how to
// restore it BY HAND — because goddns never writes BIND files, the operator
// re-imports, and the safe procedure differs for dynamic vs static zones.
// The header is all comments (lines starting with ';'), so the file still
// loads cleanly as a zone file.
func writeExport(w io.Writer, name, server, auth string, z *named.Zone, records []dns.RR) {
	path := "/var/named/" + name + ".hosts"
	if z != nil && z.Path != "" {
		path = z.Path
	}

	fmt.Fprintf(w, "; goddns export of zone %s\n", name)
	fmt.Fprintf(w, "; taken %s from %s via AXFR (%s; for a dynamic zone this is journal-merged)\n",
		time.Now().UTC().Format(time.RFC3339), server, auth)
	if soa := named.SOAOf(records); soa != nil {
		fmt.Fprintf(w, "; serial %d, %d records\n", soa.Serial, len(records))
	}
	if signed, n := named.Signed(records); signed {
		fmt.Fprintf(w, ";\n; *** DNSSEC-SIGNED ZONE (%d signing records) ***\n", n)
		fmt.Fprint(w, "; This dump INCLUDES RRSIG/DNSKEY/NSEC(3) records. They expire and are\n")
		fmt.Fprint(w, "; normally generated and rotated by BIND (inline-signing / auto-dnssec),\n")
		fmt.Fprint(w, "; so restoring them by hand is usually WRONG: prefer restoring the\n")
		fmt.Fprint(w, "; UNSIGNED source zone and letting BIND re-sign, or use dnssec tooling.\n")
		fmt.Fprint(w, "; The signatures in this snapshot may already be near expiry.\n")
	}
	fmt.Fprint(w, ";\n; NOTE: this is a record snapshot. Comments / $ORIGIN / $INCLUDE / record\n")
	fmt.Fprint(w, "; ordering from the original source file are NOT preserved (AXFR carries\n")
	fmt.Fprint(w, "; records, not source text). It reloads cleanly as-is.\n;\n")
	fmt.Fprint(w, "; ---- restore by hand (goddns never writes BIND files) ----\n")

	switch {
	case z == nil:
		fmt.Fprintf(w, "; kind: UNKNOWN — %s is not in named.conf. If it's a normal static\n", name)
		fmt.Fprint(w, ";   zone, follow the STATIC steps; if it accepts dynamic updates, the\n")
		fmt.Fprint(w, ";   DYNAMIC steps. Both are below.\n;\n")
		writeStaticRestore(w, name, path)
		fmt.Fprint(w, ";\n")
		writeDynamicRestore(w, name, path)
	case z.Dynamic:
		keys := strings.Join(z.UpdateKeys, ", ")
		if keys == "" {
			keys = z.AllowUpdate
		}
		fmt.Fprintf(w, "; kind: DYNAMIC (updates via: %s)\n;\n", keys)
		writeDynamicRestore(w, name, path)
	default:
		fmt.Fprint(w, "; kind: static (hand-edited zone file)\n;\n")
		writeStaticRestore(w, name, path)
	}
	fmt.Fprint(w, "; ----------------------------------------------------------\n")
	fmt.Fprint(w, "$ORIGIN .\n")

	for _, rr := range records {
		fmt.Fprintln(w, rr.String())
	}
}

func writeStaticRestore(w io.Writer, name, path string) {
	fmt.Fprint(w, "; STATIC restore:\n")
	fmt.Fprintf(w, ";   1. save this file as the zone file, e.g. %s\n", path)
	fmt.Fprintf(w, ";   2. named-checkzone %s %s\n", name, path)
	fmt.Fprintf(w, ";   3. rndc reload %s     (bump the SOA serial first if it refuses)\n", name)
}

func writeDynamicRestore(w io.Writer, name, path string) {
	fmt.Fprint(w, "; DYNAMIC restore — do NOT just overwrite the live file (journal foot-gun):\n")
	fmt.Fprint(w, ";   option A — replace the file, keep the zone dynamic:\n")
	fmt.Fprintf(w, ";     rndc freeze %s\n", name)
	fmt.Fprintf(w, ";     install this snapshot as %s\n", path)
	fmt.Fprintf(w, ";     named-checkzone %s %s\n", name, path)
	fmt.Fprintf(w, ";     rndc thaw %s     (rebuilds; a fresh journal starts on the next update)\n", name)
	fmt.Fprint(w, ";   option B — re-inject records via dynamic update, no freeze:\n")
	fmt.Fprintf(w, ";     nsupdate -k <keyfile>  ->  zone %s; update add <each record>; send\n", name)
}

// printZoneHeader writes the one-line summary: zone kind, dynamic status, the
// update keys, and the SOA serial — the "is this dynamic?" answer up front.
func printZoneHeader(name, auth string, z *named.Zone, records []dns.RR) {
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
		fmt.Printf("serial: %d   primary: %s   %d records\n", soa.Serial, strings.TrimSuffix(soa.Ns, "."), len(records))
	} else {
		fmt.Printf("%d records\n", len(records))
	}
	if signed, n := named.Signed(records); signed {
		fmt.Printf("DNSSEC: signed (%d signing records — managed by BIND, not hand-restorable)\n", n)
	}
	fmt.Printf("transfer: %s\n\n", auth)
}
