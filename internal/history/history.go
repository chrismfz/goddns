// Package history captures versioned snapshots of every zone (Phase 1 of the
// zone-management roadmap): a background poller watches each zone's SOA serial
// and, when it changes, transfers the zone (AXFR) and stores a canonical
// snapshot, so an operator can see what changed, when, and roll back. It is
// strictly READ-ONLY toward BIND — AXFR + SOA queries only, never a write.
package history

import (
	"context"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/store"
)

// Diff returns the records added and removed going from old to new. A zone is a
// SET of records, so this is a set difference on canonical lines (order doesn't
// matter); the SOA's serial bump shows as a single removed/added pair.
func Diff(old, new string) (added, removed []string) {
	o, n := lineSet(old), lineSet(new)
	for line := range n {
		if !o[line] {
			added = append(added, line)
		}
	}
	for line := range o {
		if !n[line] {
			removed = append(removed, line)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func lineSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			m[l] = true
		}
	}
	return m
}

// Poller periodically snapshots every master zone whose SOA serial has moved.
type Poller struct {
	Cfg   func() *config.Config // live config (named_conf, dns_server, tsig, history_*)
	Store *store.Store
}

// Run loops until ctx is cancelled, re-reading the interval each cycle so a
// config reload of history_interval takes effect (0 = disabled, re-checked
// every minute so it can be turned back on without a restart).
func (p *Poller) Run(ctx context.Context) {
	for {
		cfg := p.Cfg()
		if cfg.HistoryInterval <= 0 {
			if !sleep(ctx, time.Minute) {
				return
			}
			continue
		}
		p.sweep(cfg)
		if !sleep(ctx, time.Duration(cfg.HistoryInterval)*time.Second) {
			return
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (p *Poller) sweep(cfg *config.Config) {
	nc := cfg.NamedConf
	if nc == "" {
		nc = "/etc/named.conf"
	}
	server := cfg.DNSServer
	if server == "" {
		server = "127.0.0.1:53"
	}
	keep := cfg.HistoryKeep
	if keep <= 0 {
		keep = 50
	}
	data, err := named.CheckConf(nc)
	if err != nil {
		log.Printf("history: cannot read BIND config: %v", err)
		return
	}
	inv := named.Parse(data)
	for _, z := range inv.UserZones() {
		switch z.Kind() {
		case "static file", "dynamic": // master zones with a record set to snapshot
			p.capture(z, inv, server, cfg.TSIGName, keep)
		}
	}
}

// capture snapshots one zone only if its live SOA serial differs from the last
// stored snapshot (so a steady zone costs just one SOA query per cycle).
func (p *Poller) capture(z named.Zone, inv *named.Inventory, server, tsigName string, keep int) {
	serial, ok := named.CurrentSerial(z.Name, server)
	if !ok {
		return
	}
	latest, has, err := p.Store.SnapshotLatest(z.Name)
	if err != nil {
		// Don't fall through to capture on a read error (e.g. a transient
		// "database is locked"): that would AXFR + write every cycle and
		// amplify the very contention that caused the error.
		log.Printf("history: read latest %s: %v", z.Name, err)
		return
	}
	if has && latest.Serial == serial {
		return // unchanged since the last snapshot
	}
	records, _, err := named.TransferAuto(z.Name, server, inv.AXFRKeys(&z, tsigName))
	if err != nil {
		log.Printf("history: axfr %s: %v", z.Name, err)
		return
	}
	if soa := named.SOAOf(records); soa != nil {
		serial = soa.Serial // trust the transferred SOA
	}
	if _, err := p.Store.SnapshotPut(z.Name, serial, named.Canonical(records), keep); err != nil {
		log.Printf("history: store %s: %v", z.Name, err)
		return
	}
	log.Printf("history: snapshot %s serial %d (%d records)", z.Name, serial, len(records))
}
