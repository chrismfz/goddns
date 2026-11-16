package service

import (
	"strings"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/zoned"
	"github.com/chrismfz/goddns/internal/zonemgr"
)

// ZoneChange is what creating or deleting a zone does (apply) or would do.
type ZoneChange struct {
	Zone    string
	File    string
	Stanza  string // the managed-include stanza added / removed
	Content string // the new zone file (create)
	MovedTo string // where a deleted zone's file went (delete, applied)

	// Create: the zone served here that contains the new one, the parent's
	// records the new zone will shadow (BIND answers from the most specific
	// zone), and whether the parent delegates it (NS at the new name).
	Parent        string
	ShadowChecked bool // the parent could be read; Shadowed/Delegated are only meaningful when true
	Shadowed      []string
	Delegated     bool
	AssignedTo    string
	Warning       string // the zone was created, but something after it failed (e.g. the assignment)
}

// ZoneManager is the production zone creator/deleter for cfg (tests swap
// Service.ZoneMgr).
func ZoneManager(cfg *config.Config) *zonemgr.Manager { return zonemgr.ForConfig(cfg) }

func (s *Service) zoneManager(cfg *config.Config) *zonemgr.Manager {
	if s.ZoneMgr != nil {
		return s.ZoneMgr(cfg)
	}
	return ZoneManager(cfg)
}

// zoneOp runs a create/delete through the zoned root helper when one is
// configured (the daemon can't write named's files or run rndc), else
// directly (the CLI as root, or a daemon given the rights).
func (s *Service) zoneOp(cfg *config.Config, action, zone string, ns []string, apply bool) (*zonemgr.Plan, error) {
	if cfg.ZonedSocket != "" && s.ZoneMgr == nil {
		resp, err := zoned.Call(cfg.ZonedSocket, zoned.Request{Zone: zone, Action: action, NS: ns, Apply: apply})
		if err != nil {
			if resp != nil && resp.Refused {
				return nil, invalid("%s", resp.Error)
			}
			return nil, err
		}
		return &zonemgr.Plan{Zone: zonemgr.NormName(zone), File: resp.File, Stanza: resp.Stanza,
			Content: resp.Content, Parent: resp.Parent, MovedTo: resp.MovedTo}, nil
	}
	m := s.zoneManager(cfg)
	var p *zonemgr.Plan
	var err error
	switch {
	case action == "zone-create" && apply:
		p, err = m.Create(zonemgr.CreateRequest{Zone: zone, NS: ns})
	case action == "zone-create":
		p, err = m.PlanCreate(zonemgr.CreateRequest{Zone: zone, NS: ns})
	case apply:
		p, err = m.Delete(zone)
	default:
		p, err = m.PlanDelete(zone)
	}
	return p, asInvalid(err)
}

// ZoneCreate makes a new static master zone goddns manages (admin only):
// its stanza goes into the managed include, its file into managed_zone_dir.
// ns defaults to zone_ns. assignTo, if set, grants it to that user-role
// login once it exists. apply=false previews, incl. what it would shadow.
func (s *Service) ZoneCreate(a Actor, zone string, ns []string, assignTo string, apply bool) (*ZoneChange, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	cfg := s.cfg()
	zone = NormZone(zone)
	if zone == "" {
		return nil, missing("a zone name is required")
	}
	if len(ns) == 0 {
		ns = cfg.ZoneNS
	}
	if len(ns) == 0 {
		return nil, invalid("no nameservers: give at least one, or set zone_ns in goddns.conf")
	}
	assignTo = strings.TrimSpace(assignTo)
	if assignTo != "" {
		if _, err := s.dbUser(assignTo); err != nil {
			return nil, err
		}
	}
	p, err := s.zoneOp(cfg, "zone-create", zone, ns, apply)
	if err != nil {
		return nil, err
	}
	out := &ZoneChange{Zone: p.Zone, File: p.File, Stanza: p.Stanza, Content: p.Content, Parent: p.Parent}
	if !apply {
		if p.Parent != "" { // the preview's job; the apply already saw it
			out.Shadowed, out.Delegated, out.ShadowChecked = s.shadowedBy(cfg, p.Parent, p.Zone)
		}
		return out, nil
	}
	s.Audit(a, "zone-create zone=%s file=%s parent=%s", p.Zone, p.File, p.Parent)
	// A zone of this name may have existed before (removed by hand from the
	// include, grants left behind): a new zone starts with no grants.
	if err := s.store.GrantsDelZone(p.Zone); err != nil {
		out.Warning = "created, but clearing old grants on it failed: " + err.Error()
	}
	if assignTo != "" {
		if err := s.store.GrantAdd(assignTo, p.Zone); err != nil {
			out.Warning = "created, but assigning it to " + assignTo + " failed: " + err.Error() + " — grant it from the users page"
		} else {
			s.Audit(a, "grant-add user=%s zone=%s", assignTo, p.Zone)
			out.AssignedTo = assignTo
		}
	}
	return out, nil
}

// ZoneDelete removes a zone goddns manages (admin only) — only one in the
// managed include; a zone defined elsewhere is refused. Its grants go with
// it; its file is moved aside, never deleted.
func (s *Service) ZoneDelete(a Actor, zone string, apply bool) (*ZoneChange, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	zone = NormZone(zone)
	if zone == "" {
		return nil, missing("a zone name is required")
	}
	p, err := s.zoneOp(s.cfg(), "zone-delete", zone, nil, apply)
	if err != nil {
		return nil, err
	}
	out := &ZoneChange{Zone: p.Zone, File: p.File, Stanza: p.Stanza, MovedTo: p.MovedTo}
	if !apply {
		return out, nil
	}
	s.Audit(a, "zone-delete zone=%s file=%s moved_to=%s", p.Zone, p.File, p.MovedTo)
	if err := s.store.GrantsDelZone(p.Zone); err != nil {
		return out, err
	}
	return out, nil
}

// shadowedBy lists the parent's records at or below child (they stop being
// answered once child exists), capped at 50, and whether the parent already
// delegates child (NS records at child's name). checked is false when the
// parent couldn't be read — then nothing can be said either way.
func (s *Service) shadowedBy(cfg *config.Config, parent, child string) (shadowed []string, delegated, checked bool) {
	inv, err := s.inventory(cfg)
	if err != nil {
		return nil, false, false
	}
	records, _, err := named.TransferAuto(parent, server(cfg), inv.AXFRKeys(inv.ZoneByName(parent), cfg.TSIGName))
	if err != nil {
		return nil, false, false
	}
	var out []string
	c := dns.Fqdn(child)
	for _, rr := range records {
		h := rr.Header()
		if !dns.IsSubDomain(c, h.Name) {
			continue
		}
		if h.Rrtype == dns.TypeNS && strings.EqualFold(h.Name, c) {
			delegated = true
			continue // the delegation itself is wanted, not shadowed
		}
		if len(out) < 50 {
			out = append(out, rr.String())
		}
	}
	return out, delegated, true
}

// asInvalid turns a zonemgr refusal (a bad name, an existing zone, the
// include not referenced, a zone it doesn't manage) into a caller mistake;
// real I/O failures stay as they are.
func asInvalid(err error) error {
	if zonemgr.IsRefused(err) {
		return invalid("%s", err.Error())
	}
	return err
}
