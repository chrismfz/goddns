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

	if e.Snap != nil && len(live) > 0 {
		var serial uint32
		if soa := named.SOAOf(live); soa != nil {
			serial = soa.Serial
		}
		if id, err := e.Snap.SnapshotPut(zone, serial, named.Canonical(live), e.Keep); err == nil {
			res.Snapshot = id
		}
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
	live, _, _ := named.TransferAuto(zone, server, inv.AXFRKeys(z, key.Name)) // best-effort
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
		return nil, nil, fmt.Errorf("no goddns TSIG key is granted update on %q (zone grants: %s)",
			zone, strings.Join(z.UpdateKeys, ", "))
	}
	apex := dns.Fqdn(zone)
	for _, op := range ops {
		if op.RR == nil {
			return nil, nil, fmt.Errorf("a record operation has no record")
		}
		n := dns.Fqdn(op.RR.Header().Name)
		if n != apex && !strings.HasSuffix(n, "."+apex) {
			return nil, nil, fmt.Errorf("record %q is not inside zone %q", strings.TrimSuffix(n, "."), zone)
		}
	}
	return z, key, nil
}

// keyFor returns the first key goddns holds that the zone grants update rights.
func (e *Editor) keyFor(z *named.Zone) *tsig.Key {
	for i := range e.Keys {
		kn := strings.TrimSuffix(e.Keys[i].Name, ".")
		for _, gk := range z.UpdateKeys {
			if gk == kn {
				return &e.Keys[i]
			}
		}
	}
	return nil
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
