// Package recordmut is the Phase 2A record-mutation pipeline: it edits records
// in a DYNAMIC BIND zone via signed RFC2136 UPDATEs (ddns.Mutator), enforcing
// the roadmap invariant — goddns never touches a static/panel-managed zone, and
// never converts a zone. Every change snapshots the zone first (Phase 1) so it
// is reversible, and reports a diff of what it removed/added.
package recordmut

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/tsig"
)

// Snapshotter is the slice of the store the editor needs (Phase-1 snapshots).
type Snapshotter interface {
	SnapshotPut(zone string, serial uint32, content string, keep int) (int64, error)
}

// Editor applies record mutations to dynamic zones.
type Editor struct {
	NamedConf string      // path to named.conf (for the dynamic/grant check)
	DNSServer string      // where to send the UPDATE / AXFR (e.g. 127.0.0.1:53)
	Keys      []tsig.Key  // the TSIG keys goddns holds (keyring or the single key)
	Snap      Snapshotter // optional: snapshot-before-write
	Keep      int         // snapshots retained per zone
}

// Result describes what a mutation did (or would do, for a preview).
type Result struct {
	Zone, Key string
	Snapshot  int64    // id of the pre-change snapshot (0 if none taken)
	Added     []string // records added (zone-file form)
	Removed   []string // records removed (resolved against the live zone)
}

// Preview validates the request and computes the diff WITHOUT changing anything.
func (e *Editor) Preview(zone string, ops []ddns.Op) (*Result, error) {
	_, key, live, err := e.prepare(zone, ops)
	if err != nil {
		return nil, err
	}
	return buildResult(zone, key.Name, ops, live), nil
}

// Apply validates, snapshots the zone, then applies ops in one signed UPDATE.
func (e *Editor) Apply(zone string, ops []ddns.Op) (*Result, error) {
	_, key, live, err := e.prepare(zone, ops)
	if err != nil {
		return nil, err
	}
	res := buildResult(zone, key.Name, ops, live)

	// Snapshot before the change is a guarantee, not best-effort: refuse to
	// mutate if we couldn't capture a restore point.
	if e.Snap != nil {
		var serial uint32
		if soa := named.SOAOf(live); soa != nil {
			serial = soa.Serial
		}
		id, err := e.Snap.SnapshotPut(zone, serial, named.Canonical(live), e.Keep)
		if err != nil {
			return nil, fmt.Errorf("snapshot before change failed (%w) — refusing to mutate without a restore point", err)
		}
		res.Snapshot = id
	}

	be, err := ddns.NewRFC2136(e.DNSServer, key.Name, key.Algo, key.Secret)
	if err != nil {
		return nil, err
	}
	if err := be.Apply(zone, ops); err != nil {
		return nil, err
	}
	return res, nil
}

// prepare reads the inventory, validates, and transfers the live zone.
func (e *Editor) prepare(zone string, ops []ddns.Op) (*named.Zone, *tsig.Key, []dns.RR, error) {
	nc := e.NamedConf
	if nc == "" {
		nc = "/etc/named.conf"
	}
	data, err := named.CheckConf(nc)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read named.conf: %w", err)
	}
	inv := named.Parse(data)
	z, key, err := e.validate(inv, zone, ops)
	if err != nil {
		return nil, nil, nil, err
	}
	server := e.DNSServer
	if server == "" {
		server = "127.0.0.1:53"
	}
	// AXFR is required: it's both the snapshot (restore point) and the basis of
	// the diff. If the zone can't be transferred, don't proceed on a blind diff.
	live, _, err := named.TransferAuto(zone, server, inv.AXFRKeys(z, key.Name))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("can't transfer %q to snapshot/diff it (%w) — "+
			"record editing needs the zone transferable: allow-transfer { localhost; } or a key", zone, err)
	}
	return z, key, live, nil
}

// validate enforces the invariant: the zone must exist, be dynamic, grant a key
// goddns holds, and every op's name must lie inside the zone.
func (e *Editor) validate(inv *named.Inventory, zone string, ops []ddns.Op) (*named.Zone, *tsig.Key, error) {
	if len(ops) == 0 {
		return nil, nil, fmt.Errorf("no record operations given")
	}
	z := inv.ZoneByName(zone)
	if z == nil {
		return nil, nil, fmt.Errorf("zone %q is not in named.conf", zone)
	}
	if !z.Dynamic {
		return nil, nil, fmt.Errorf("zone %q is %s — goddns only edits dynamic zones and never converts one; "+
			"manage it the way its owner does (hand-edit / panel)", zone, z.Kind())
	}
	key := e.keyFor(z)
	if key == nil {
		return nil, nil, fmt.Errorf("no goddns TSIG key with a secret is granted update on %q (zone grants: %s)",
			zone, strings.Join(z.UpdateKeys, ", "))
	}
	target := dns.CanonicalName(zone)
	for _, op := range ops {
		if op.RR == nil {
			return nil, nil, fmt.Errorf("a record operation has no record")
		}
		// The name must belong to THIS zone as its most-specific enclosing
		// zone — so a record for a delegated child isn't sent to the parent.
		owner := mostSpecificZone(inv, op.RR.Header().Name)
		name := strings.TrimSuffix(dns.CanonicalName(op.RR.Header().Name), ".")
		if owner == "" {
			return nil, nil, fmt.Errorf("record %q is not inside any zone served here", name)
		}
		if owner != target {
			return nil, nil, fmt.Errorf("record %q belongs to the more specific zone %q — target that zone",
				name, strings.TrimSuffix(owner, "."))
		}
	}
	return z, key, nil
}

// keyFor returns the first key goddns HOLDS (with a secret) that the zone grants.
func (e *Editor) keyFor(z *named.Zone) *tsig.Key {
	for i := range e.Keys {
		if e.Keys[i].Secret == "" {
			continue
		}
		for _, gk := range z.UpdateKeys {
			if strings.EqualFold(strings.TrimSuffix(e.Keys[i].Name, "."), strings.TrimSuffix(gk, ".")) {
				return &e.Keys[i]
			}
		}
	}
	return nil
}

// CanEdit reports whether goddns can edit this zone: it must be dynamic and
// grant a TSIG key goddns holds. Used to show edit controls only where they work.
func (e *Editor) CanEdit(z *named.Zone) bool {
	return z != nil && z.Dynamic && e.keyFor(z) != nil
}

// mostSpecificZone returns the canonical name of the longest user zone that
// encloses name (the zone authoritative for that record), or "" if none.
func mostSpecificZone(inv *named.Inventory, name string) string {
	cn := dns.CanonicalName(name)
	best := ""
	for _, z := range inv.UserZones() {
		zn := dns.CanonicalName(z.Name)
		if cn == zn || strings.HasSuffix(cn, "."+zn) {
			if len(zn) > len(best) {
				best = zn
			}
		}
	}
	return best
}

// buildResult renders the added records and resolves the removed ones against
// the live zone (so a DelRRset/DelName shows exactly which records will go).
func buildResult(zone, keyName string, ops []ddns.Op, live []dns.RR) *Result {
	res := &Result{Zone: zone, Key: keyName}
	for _, op := range ops {
		switch op.Action {
		case ddns.AddRR:
			res.Added = append(res.Added, op.RR.String())
		case ddns.DelRR:
			res.Removed = append(res.Removed, op.RR.String())
		case ddns.DelRRset:
			h := op.RR.Header()
			for _, rr := range live {
				if strings.EqualFold(rr.Header().Name, h.Name) && rr.Header().Rrtype == h.Rrtype {
					res.Removed = append(res.Removed, rr.String())
				}
			}
		case ddns.DelName:
			h := op.RR.Header()
			for _, rr := range live {
				if strings.EqualFold(rr.Header().Name, h.Name) {
					res.Removed = append(res.Removed, rr.String())
				}
			}
		}
	}
	return res
}
