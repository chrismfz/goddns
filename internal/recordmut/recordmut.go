// Package recordmut is the Phase 2A record-mutation pipeline: it edits records
// in a DYNAMIC BIND zone via signed RFC2136 UPDATEs (ddns.Mutator), enforcing
// the roadmap invariant — goddns never touches a static/panel-managed zone, and
// never converts a zone. Every change snapshots the zone first (Phase 1) so it
// is reversible, and reports a diff of what it removed/added.
package recordmut

import (
	"fmt"
	"sort"
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

// prepare reads the inventory, validates the zone, validates the ops, and
// transfers the live zone — the full path Preview/Apply share.
func (e *Editor) prepare(zone string, ops []ddns.Op) (*named.Zone, *tsig.Key, []dns.RR, error) {
	inv, z, key, live, err := e.transfer(zone)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := e.validateOps(inv, zone, ops); err != nil {
		return nil, nil, nil, err
	}
	return z, key, live, nil
}

// transfer does everything that does NOT depend on the specific ops: read
// named.conf, check the zone is editable (exists, dynamic, grants a held key),
// and AXFR the live zone. RestorePlan needs the live zone BEFORE it can compute
// the restore delta, so this step stands on its own.
func (e *Editor) transfer(zone string) (*named.Inventory, *named.Zone, *tsig.Key, []dns.RR, error) {
	nc := e.NamedConf
	if nc == "" {
		nc = "/etc/named.conf"
	}
	data, err := named.CheckConf(nc)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read named.conf: %w", err)
	}
	inv := named.Parse(data)
	z, key, err := e.validateZone(inv, zone)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	server := e.DNSServer
	if server == "" {
		server = "127.0.0.1:53"
	}
	// AXFR is required: it's both the snapshot (restore point) and the basis of
	// the diff. If the zone can't be transferred, don't proceed on a blind diff.
	live, _, err := named.TransferAuto(zone, server, inv.AXFRKeys(z, key.Name))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("can't transfer %q to snapshot/diff it (%w) — "+
			"record editing needs the zone transferable: allow-transfer { localhost; } or a key", zone, err)
	}
	return inv, z, key, live, nil
}

// validate enforces the full invariant: the zone must exist, be dynamic, grant
// a key goddns holds, and every op's name must lie inside the zone. It composes
// the zone-level and op-level checks; both are also used on their own.
func (e *Editor) validate(inv *named.Inventory, zone string, ops []ddns.Op) (*named.Zone, *tsig.Key, error) {
	z, key, err := e.validateZone(inv, zone)
	if err != nil {
		return nil, nil, err
	}
	if err := e.validateOps(inv, zone, ops); err != nil {
		return nil, nil, err
	}
	return z, key, nil
}

// validateZone checks the zone is one goddns may edit: it exists, is dynamic
// (the invariant — goddns never converts a static/panel zone), and grants a
// TSIG key goddns actually holds.
func (e *Editor) validateZone(inv *named.Inventory, zone string) (*named.Zone, *tsig.Key, error) {
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
	return z, key, nil
}

// validateOps checks every op refers to a record that belongs to THIS zone as
// its most-specific enclosing zone — so a record for a delegated child is never
// sent to the parent.
func (e *Editor) validateOps(inv *named.Inventory, zone string, ops []ddns.Op) error {
	if len(ops) == 0 {
		return fmt.Errorf("no record operations given")
	}
	target := dns.CanonicalName(zone)
	for _, op := range ops {
		if op.RR == nil {
			return fmt.Errorf("a record operation has no record")
		}
		owner := mostSpecificZone(inv, op.RR.Header().Name)
		name := strings.TrimSuffix(dns.CanonicalName(op.RR.Header().Name), ".")
		if owner == "" {
			return fmt.Errorf("record %q is not inside any zone served here", name)
		}
		if owner != target {
			return fmt.Errorf("record %q belongs to the more specific zone %q — target that zone",
				name, strings.TrimSuffix(owner, "."))
		}
	}
	return nil
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
			// RFC2136 delete-exact-RR matches name+type+rdata (TTL ignored) and
			// is a no-op if absent — so only report it removed if it's actually
			// in the live zone (otherwise the diff would imply a change there
			// won't be).
			want := rrKey(op.RR)
			for _, rr := range live {
				if rrKey(rr) == want {
					res.Removed = append(res.Removed, rr.String())
					break
				}
			}
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

// rrKey identifies a record by name+type+rdata (case-insensitive name, TTL
// ignored) — the fields RFC2136 delete-exact-RR actually matches on.
func rrKey(rr dns.RR) string {
	h := rr.Header()
	rdata := strings.TrimPrefix(rr.String(), h.String())
	return strings.ToLower(strings.TrimSuffix(h.Name, ".")) + " " + dns.TypeToString[h.Rrtype] + " " + rdata
}

// RestorePlan computes the change that makes the live zone match a snapshot
// (Phase-1 canonical content) again — the Phase-1↔2 link. It is NOT a serial
// rollback: it computes a FORWARD delta (records the snapshot had but live lost
// → AddRR; records live gained since → DelRR) and returns it as ops, plus a
// preview Result. Feeding those ops to Apply runs them as one signed UPDATE
// that snapshots-before, so the restore is itself undoable. SOA and DNSSEC
// records are left untouched — BIND owns those and keeps the zone moving
// forward (new serial, fresh signatures). ops is empty when live already
// matches the snapshot (nothing to do).
func (e *Editor) RestorePlan(zone, snapContent string) ([]ddns.Op, *Result, error) {
	inv, _, key, live, err := e.transfer(zone)
	if err != nil {
		return nil, nil, err
	}
	want, err := parseRecords(snapContent)
	if err != nil {
		return nil, nil, err
	}
	// A snapshot is a full AXFR: it also carries any delegated child's apex NS
	// and in-bailiwick glue, which belong to the CHILD zone. Restore only the
	// records this zone is authoritative for, on both sides of the diff — so
	// child/glue is left untouched rather than aborting the whole restore, and
	// a child's record is never sent to the parent.
	target := dns.CanonicalName(zone)
	want = ownedBy(inv, target, want)
	live = ownedBy(inv, target, live)
	// Guard against a corrupt/empty snapshot: with no restorable records, the
	// delta would delete every live record (apex NS included) and empty the
	// zone. A real Phase-1 snapshot always has the apex NS, so this only fires
	// on a bad snapshot.
	if !hasRestorable(want) {
		return nil, nil, fmt.Errorf("snapshot has no restorable records for %q — refusing to empty the zone", zone)
	}
	ops := restoreOps(want, live)
	if len(ops) == 0 {
		return nil, &Result{Zone: zone, Key: key.Name}, nil
	}
	// The delta is derived from in-zone live + snapshot records, so every op is
	// in-zone by construction; validate anyway as a belt-and-braces guard.
	if err := e.validateOps(inv, zone, ops); err != nil {
		return nil, nil, err
	}
	return ops, buildResult(zone, key.Name, ops, live), nil
}

// ownedBy keeps only the records whose most-specific enclosing zone is target —
// i.e. the records THIS zone is authoritative for, excluding any delegated
// child's data that a full AXFR happens to include.
func ownedBy(inv *named.Inventory, target string, rrs []dns.RR) []dns.RR {
	out := rrs[:0:0]
	for _, rr := range rrs {
		if mostSpecificZone(inv, rr.Header().Name) == target {
			out = append(out, rr)
		}
	}
	return out
}

// hasRestorable reports whether any record is operator data (not BIND-managed
// SOA/DNSSEC) — the records a restore would actually re-create.
func hasRestorable(rrs []dns.RR) bool {
	for _, rr := range rrs {
		if !managed(rr) {
			return true
		}
	}
	return false
}

// restoreOps computes the delta that turns live into want, ignoring
// BIND-managed records (SOA + DNSSEC). Records in want but not live become
// AddRR; records in live but not want become DelRR. Matching is by rrKey
// (name+type+rdata, TTL-insensitive), so a TTL-only difference is not restored.
// Deletes are ordered before adds, each group sorted for a stable preview.
func restoreOps(want, live []dns.RR) []ddns.Op {
	wantSet := make(map[string]dns.RR, len(want))
	for _, rr := range want {
		if managed(rr) {
			continue
		}
		wantSet[rrKey(rr)] = rr
	}
	liveSet := make(map[string]dns.RR, len(live))
	for _, rr := range live {
		if managed(rr) {
			continue
		}
		liveSet[rrKey(rr)] = rr
	}
	var add, del []ddns.Op
	for k, rr := range wantSet {
		if _, ok := liveSet[k]; !ok {
			add = append(add, ddns.Op{Action: ddns.AddRR, RR: rr})
		}
	}
	for k, rr := range liveSet {
		if _, ok := wantSet[k]; !ok {
			del = append(del, ddns.Op{Action: ddns.DelRR, RR: rr})
		}
	}
	sortOps(add)
	sortOps(del)
	return append(del, add...)
}

// sortOps orders ops by their record's zone-file text, for deterministic
// previews and tests.
func sortOps(ops []ddns.Op) {
	sort.Slice(ops, func(i, j int) bool { return ops[i].RR.String() < ops[j].RR.String() })
}

// parseRecords turns a Phase-1 canonical snapshot (one record per line, in
// zone-file form) back into records.
func parseRecords(content string) ([]dns.RR, error) {
	var out []dns.RR
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rr, err := dns.NewRR(line)
		if err != nil {
			return nil, fmt.Errorf("snapshot has an unparseable record %q: %w", line, err)
		}
		if rr != nil {
			out = append(out, rr)
		}
	}
	return out, nil
}

// managed reports whether a record is owned by BIND rather than the operator:
// the SOA (its serial only moves forward) and the DNSSEC chain (RRSIG/NSEC*/
// DNSKEY/CDS/CDNSKEY, generated and rotated by inline-signing). These are
// excluded from a restore — replaying an old SOA would break secondaries and
// replaying stale signatures would break validation.
func managed(rr dns.RR) bool {
	switch rr.Header().Rrtype {
	case dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3,
		dns.TypeNSEC3PARAM, dns.TypeDNSKEY, dns.TypeCDS, dns.TypeCDNSKEY:
		return true
	}
	return false
}
