package service

import (
	"errors"
	"sort"
	"strings"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/store"
)

// Zone grants: a "user"-role login manages exactly the zones granted to it —
// each grant is one zone, never its subzones (a more specific zone served
// here is its own grant). An admin reaches every zone without grants.

// NormZone is the canonical spelling of a zone name in grants and checks:
// lowercase, no surrounding space, no trailing dot.
func NormZone(z string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".") }

// QualifyName resolves a hostname typed for zone into a FQDN:
//
//	"" or "@"            → the zone apex
//	"name."              → as written (absolute)
//	"x.zone" or "zone"   → absolute: it already ends in the zone (typing the
//	                       full name without the trailing dot must not become
//	                       x.zone.zone, which nobody ever means)
//	anything else        → relative to the zone ("test" → test.zone.)
//
// The UI's DDNS form and the CLI's name arguments share it.
func QualifyName(name, zone string) string {
	name = strings.TrimSpace(name)
	zone = NormZone(zone)
	switch {
	case name == "" || name == "@":
		return dns.Fqdn(zone)
	case strings.HasSuffix(name, "."):
		return name
	}
	l := strings.ToLower(name)
	if l == zone || strings.HasSuffix(l, "."+zone) {
		return dns.Fqdn(name)
	}
	return dns.Fqdn(name + "." + zone)
}

// NormalizeRRLine applies QualifyName's "already ends in the zone" rule to
// the owner (first field) of a zone-file record line: a full name typed
// without the trailing dot gets one, instead of zone-file semantics turning
// test.ddns.example into test.ddns.example.ddns.example. Everything else in
// the line keeps zone-file meaning (relative names, "@", absolute names).
func NormalizeRRLine(line, zone string) string {
	line = strings.TrimSpace(line)
	i := strings.IndexAny(line, " \t")
	if i <= 0 {
		return line
	}
	owner := line[:i]
	if owner == "@" || strings.HasSuffix(owner, ".") {
		return line
	}
	l, z := strings.ToLower(owner), NormZone(zone)
	if l == z || strings.HasSuffix(l, "."+z) {
		return owner + "." + line[i:]
	}
	return line
}

// grantSet returns the zones granted to a user-role actor.
func (s *Service) grantSet(a Actor) (map[string]bool, error) {
	zs, err := s.store.GrantsFor(a.User)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(zs))
	for _, z := range zs {
		m[NormZone(z)] = true
	}
	return m, nil
}

// authZone allows an admin everything and a user only a granted zone. Any
// other role, or an empty one, is refused.
func (s *Service) authZone(a Actor, zone string) error {
	switch a.Role {
	case RoleAdmin:
		return nil
	case RoleUser:
		g, err := s.grantSet(a)
		if err != nil {
			return err
		}
		if g[NormZone(zone)] {
			return nil
		}
	}
	return ErrForbidden
}

// ownerZone returns the most specific zone served here that contains name
// ("" if none), the rule RFC2136 edits already follow: a record belongs to
// the deepest zone above it, so an edit through a parent zone can't write
// into a child zone's namespace.
func ownerZone(inv *named.Inventory, name string) string {
	name = dns.CanonicalName(name)
	best := ""
	for _, z := range inv.UserZones() {
		zn := dns.CanonicalName(z.Name)
		if dns.IsSubDomain(zn, name) && len(zn) > len(best) {
			best = zn
		}
	}
	return NormZone(best)
}

// Grant gives a database user one zone. The zone must be a zone named.conf
// serves (not a built-in): a typo, or "arpa", must not become a grant.
func (s *Service) Grant(a Actor, user, zone string) error {
	if err := s.requireAdmin(a); err != nil {
		return err
	}
	zone = NormZone(zone)
	if user == "" || zone == "" {
		return missing("user and zone are required")
	}
	u, err := s.dbUser(user)
	if err != nil {
		return err
	}
	inv, err := s.inventory(s.cfg())
	if err != nil {
		return err
	}
	found := false
	for _, z := range inv.UserZones() {
		if NormZone(z.Name) == zone {
			found = true
			break
		}
	}
	if !found {
		return invalid("zone %q is not served by this BIND (see the zones page)", zone)
	}
	if err := s.store.GrantAdd(u.Name, zone); err != nil {
		return err
	}
	s.Audit(a, "grant-add user=%s zone=%s", u.Name, zone)
	return nil
}

// Revoke removes one grant. It works for any name, so a grant can be
// cleaned up even after the zone left named.conf.
func (s *Service) Revoke(a Actor, user, zone string) error {
	if err := s.requireAdmin(a); err != nil {
		return err
	}
	zone = NormZone(zone)
	if user == "" || zone == "" {
		return missing("user and zone are required")
	}
	if err := s.store.GrantDel(user, zone); err != nil {
		if errors.Is(err, store.ErrNoGrant) {
			return invalid("%s has no grant for %s", user, zone)
		}
		return err
	}
	s.Audit(a, "grant-del user=%s zone=%s", user, zone)
	return nil
}

// MyZones returns the zones the actor can manage by grant (an admin gets an
// empty list: they manage everything through the zones page).
func (s *Service) MyZones(a Actor) ([]string, error) {
	if a.Role != RoleUser {
		if a.Role == RoleAdmin {
			return nil, nil
		}
		return nil, ErrForbidden
	}
	zs, err := s.store.GrantsFor(a.User)
	sort.Strings(zs)
	return zs, err
}
