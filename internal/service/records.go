package service

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/filezone"
	"github.com/chrismfz/goddns/internal/store"
	"github.com/chrismfz/goddns/internal/zoned"
)

// Record edit actions.
const (
	ActionAdd = "add"
	ActionDel = "del"
)

// RecordResult is what a record edit did (apply) or would do (preview).
type RecordResult struct {
	Zone           string
	Added, Removed []string // zone-file form

	Static bool // edited in place (file-as-truth) rather than over RFC2136

	// Dynamic path.
	Key      string // TSIG key that signed the UPDATE
	Snapshot int64  // pre-change snapshot id (0 if none)

	// Static path.
	Serial uint32 // the new SOA serial
	Backup string // pre-edit file backup (empty on preview)
	Via    string // "zoned" (root helper) or "direct"
}

// EditRecord adds or deletes one record (line is zone-file syntax). apply=false
// previews the diff and changes nothing; apply=true writes and audits.
//
// Routing follows ownership, matching what Zone reports: an enabled static
// MASTER zone is edited in place (via the zoned root helper when zoned_socket
// is set, else directly); everything else, including a dynamic zone mistakenly
// listed in editable_zones, is RFC2136 — which itself refuses static/panel
// zones and snapshots before writing. CanEdit re-reads the live dynamic flag,
// so routing can't disagree with the display.
func (s *Service) EditRecord(a Actor, zone, action, line string, apply bool) (*RecordResult, error) {
	zone = strings.TrimSpace(zone)
	line = strings.TrimSpace(line)
	if zone == "" || line == "" || (action != ActionAdd && action != ActionDel) {
		return nil, missing("missing fields")
	}
	if err := s.authZone(a, zone); err != nil {
		return nil, err
	}
	cfg := s.cfg()
	rr, err := ParseRR(line, zone)
	if err != nil {
		return nil, err
	}
	// A granted user's record must belong to THIS zone, not a more specific
	// one served here: a grant on a.com is not one on sub.a.com, and the
	// static path's own check is only "is a subdomain". Admins keep the
	// parent-side delegation records (NS/DS at a child apex, glue below it),
	// which live in the parent zone by definition; the RFC2136 path applies
	// its own rule to them as before.
	if a.Role != RoleAdmin {
		inv, err := s.inventory(cfg)
		if err != nil {
			return nil, err // can't prove the owner zone: fail closed
		}
		if owner := ownerZone(inv, rr.Header().Name); owner != NormZone(zone) {
			if owner == "" {
				return nil, invalid("record %q is not inside any zone served here", rr.Header().Name)
			}
			return nil, invalid("record %q belongs to the more specific zone %q — ask for that zone", rr.Header().Name, owner)
		}
	}
	fed := s.fileEditor(cfg)
	if EditsInPlace(fed, zone) {
		return s.editStatic(a, cfg, fed, zone, action, line, rr, apply)
	}

	ops := []ddns.Op{{Action: opFor(action), RR: rr}}
	ed := s.recordEditor(cfg)
	if !apply {
		res, err := ed.Preview(zone, ops)
		if err != nil {
			return nil, err
		}
		return &RecordResult{Zone: zone, Added: res.Added, Removed: res.Removed, Key: res.Key}, nil
	}
	res, err := ed.Apply(zone, ops)
	if err != nil {
		return nil, err
	}
	s.Audit(a, "record-%s zone=%s rr=%q key=%s snapshot=%d", action, zone, line, res.Key, res.Snapshot)
	return &RecordResult{Zone: zone, Added: res.Added, Removed: res.Removed, Key: res.Key, Snapshot: res.Snapshot}, nil
}

func opFor(action string) ddns.Action {
	if action == ActionDel {
		return ddns.DelRR
	}
	return ddns.AddRR
}

// editStatic previews or applies one static-zone record edit, through the
// zoned root helper when a socket is configured (so the daemon never writes
// /var/named) or filezone directly.
func (s *Service) editStatic(a Actor, cfg *config.Config, fed *filezone.Editor, zone, action, line string, rr dns.RR, apply bool) (*RecordResult, error) {
	out := &RecordResult{Zone: zone, Static: true, Via: "direct"}
	if cfg.ZonedSocket != "" {
		out.Via = "zoned"
		resp, err := zoned.Call(cfg.ZonedSocket, zoned.Request{Zone: zone, Action: action, RR: line, Apply: apply})
		if err != nil {
			return nil, err
		}
		out.Added, out.Removed, out.Serial, out.Backup = resp.Added, resp.Removed, resp.Serial, resp.Backup
	} else {
		ops := []ddns.Op{{Action: opFor(action), RR: rr}}
		var res *filezone.Result
		var err error
		if apply {
			res, err = fed.Apply(zone, ops)
		} else {
			res, err = fed.Preview(zone, ops)
		}
		if err != nil {
			return nil, err
		}
		out.Added, out.Removed, out.Serial, out.Backup = res.Added, res.Removed, res.Serial, res.Backup
	}
	if apply {
		s.Audit(a, "record-%s zone=%s rr=%q serial=%d backup=%s via=%s", action, zone, line, out.Serial, out.Backup, out.Via)
	}
	return out, nil
}

// RestoreResult is what rolling a zone back to a snapshot did or would do.
type RestoreResult struct {
	Zone           string
	Snapshot       store.Snapshot // the snapshot restored to
	Added, Removed []string
	Key            string
	PreSnapshot    int64 // snapshot taken before the restore (apply only)
}

// Restore rolls a dynamic zone back to snapshot id. apply=false previews the
// forward delta (what the restore would add/remove); apply=true applies it as
// one signed UPDATE, itself snapshotted-before so a restore is undoable.
func (s *Service) Restore(a Actor, zone string, id int64, apply bool) (*RestoreResult, error) {
	zone = strings.TrimSpace(zone)
	if err := s.authZone(a, zone); err != nil {
		return nil, err
	}
	if zone == "" || id <= 0 {
		return nil, missing("missing fields")
	}
	snap, ok, err := s.store.SnapshotByID(id)
	if err != nil {
		return nil, fmt.Errorf("read snapshot #%d: %v", id, err)
	}
	if !ok || !strings.EqualFold(strings.TrimSuffix(snap.Zone, "."), strings.TrimSuffix(zone, ".")) {
		return nil, invalid("no snapshot #%d for zone %q", id, zone)
	}
	ed := s.recordEditor(s.cfg())
	ops, res, err := ed.RestorePlan(zone, snap.Content)
	if err != nil {
		return nil, err
	}
	if len(ops) == 0 {
		return nil, invalid("%s already matches snapshot #%d — nothing to restore", zone, id)
	}
	out := &RestoreResult{Zone: zone, Snapshot: snap, Added: res.Added, Removed: res.Removed, Key: res.Key}
	if !apply {
		return out, nil
	}
	res, err = ed.Apply(zone, ops)
	if err != nil {
		return nil, err
	}
	out.Added, out.Removed, out.Key, out.PreSnapshot = res.Added, res.Removed, res.Key, res.Snapshot
	s.Audit(a, "record-restore zone=%s snapshot=%d key=%s pre-snapshot=%d", zone, id, res.Key, res.Snapshot)
	return out, nil
}
