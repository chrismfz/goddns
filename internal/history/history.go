// Package history captures versioned snapshots of every zone (Phase 1 of the
// zone-management roadmap): a background poller watches each zone's SOA serial
// and, when it changes, transfers the zone (AXFR) and stores a canonical
// snapshot, so an operator can see what changed, when, and roll back. It is
// strictly READ-ONLY toward BIND — AXFR + SOA queries only, never a write.
package history

import (
	"context"
	"fmt"
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

// DropSOA removes SOA-record lines (type is the 4th field: name TTL CLASS TYPE
// …). The SOA serial bumps on every change, so its line always differs; callers
// that show the serial transition separately drop it to de-noise the diff.
func DropSOA(lines []string) []string {
	out := lines[:0:0]
	for _, l := range lines {
		if f := strings.Fields(l); len(f) >= 4 && f[3] == "SOA" {
			continue
		}
		out = append(out, l)
	}
	return out
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

	// Logf is where the poller logs (nil ⇒ log.Printf).
	Logf func(format string, a ...any)

	// failing remembers the last error logged per key (the BIND config, or a
	// zone), so a condition that persists across cycles — e.g. goddns not
	// allowed to run named-checkconf — is logged once, not every few
	// minutes, and its recovery once more (issue #62). Run is the only
	// goroutine touching it.
	failing map[string]string
}

func (p *Poller) logf(format string, a ...any) {
	if p.Logf != nil {
		p.Logf(format, a...)
		return
	}
	log.Printf(format, a...)
}

// fail logs msg for key unless it is the same message logged last time.
func (p *Poller) fail(key, msg string) {
	if p.failing == nil {
		p.failing = map[string]string{}
	}
	if p.failing[key] == msg {
		return
	}
	p.failing[key] = msg
	p.logf("%s (logged once; again only if it changes)", msg)
}

// prune forgets failures of zones that left named.conf, so the map can't
// grow forever and a zone re-added later starts with a clean slate.
func (p *Poller) prune(inv *named.Inventory) {
	if len(p.failing) == 0 {
		return
	}
	live := map[string]bool{"BIND config": true}
	for _, z := range inv.UserZones() {
		live[z.Name] = true
	}
	for k := range p.failing {
		if !live[k] {
			delete(p.failing, k)
		}
	}
}

// ok clears key's failure, logging the recovery if there was one.
func (p *Poller) ok(key string) {
	if _, was := p.failing[key]; was {
		delete(p.failing, key)
		p.logf("history: %s: working again", key)
	}
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
		p.fail("BIND config", fmt.Sprintf("history: cannot read BIND config: %v — zone snapshots paused (history_interval = 0 turns history off)", err))
		return
	}
	p.ok("BIND config")
	inv := named.Parse(data)
	p.prune(inv)
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
		p.fail(z.Name, fmt.Sprintf("history: read latest %s: %v", z.Name, err))
		return
	}
	if has && latest.Serial == serial {
		p.ok(z.Name) // reachable and up to date: a past failure has cleared
		return       // unchanged since the last snapshot
	}
	records, _, err := named.TransferAuto(z.Name, server, inv.AXFRKeys(&z, tsigName))
	if err != nil {
		p.fail(z.Name, fmt.Sprintf("history: axfr %s: %v", z.Name, err))
		return
	}
	if soa := named.SOAOf(records); soa != nil {
		serial = soa.Serial // trust the transferred SOA
	}
	if _, err := p.Store.SnapshotPut(z.Name, serial, named.Canonical(records), keep); err != nil {
		p.fail(z.Name, fmt.Sprintf("history: store %s: %v", z.Name, err))
		return
	}
	p.ok(z.Name)
	p.logf("history: snapshot %s serial %d (%d records)", z.Name, serial, len(records))
}
