package service

import (
	"strings"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/store"
)

// DefaultDDNSTTL is the TTL a new DDNS record gets when none is given.
const DefaultDDNSTTL = 60

// DDNSList returns every DDNS record (token → hostname binding).
// DDNSList returns every DDNS record (token → hostname binding); a user-role
// actor gets only the records it created, in zones it still holds. A user
// never sees or touches an admin's records, even in a granted zone (they may
// serve the admin's own infrastructure).
func (s *Service) DDNSList(a Actor) ([]store.Record, error) {
	switch a.Role {
	case RoleAdmin:
		return s.store.List()
	case RoleUser:
		g, err := s.grantSet(a)
		if err != nil {
			return nil, err
		}
		all, err := s.store.List()
		if err != nil {
			return nil, err
		}
		var out []store.Record
		for _, r := range all {
			if r.Owner == a.User && g[NormZone(r.Zone)] {
				out = append(out, r)
			}
		}
		return out, nil
	}
	return nil, ErrForbidden
}

// ddnsRecord loads a record the actor may touch. A user gets ErrForbidden
// for a record outside its zones and for one that doesn't exist alike, so
// it can't probe which hostnames other people hold.
func (s *Service) ddnsRecord(a Actor, fqdn string) (store.Record, error) {
	rec, err := s.store.Get(strings.TrimSpace(fqdn))
	if err != nil {
		if a.Role != RoleAdmin {
			return store.Record{}, ErrForbidden
		}
		return store.Record{}, err
	}
	if err := s.authZone(a, rec.Zone); err != nil {
		return store.Record{}, err
	}
	if a.Role != RoleAdmin && rec.Owner != a.User {
		return store.Record{}, ErrForbidden
	}
	return rec, nil
}

// DDNSGet returns one DDNS record by hostname.
func (s *Service) DDNSGet(a Actor, fqdn string) (store.Record, error) {
	return s.ddnsRecord(a, fqdn)
}

// DDNSAdd creates a DDNS record and returns it with its bearer token — the
// only time the token exists in clear (the store keeps its hash).
//
// The hostname must be inside the zone (an out-of-zone token could never
// update anything). For a user-role actor the zone must be granted and the
// hostname must belong to it, not to a more specific zone served here.
func (s *Service) DDNSAdd(a Actor, fqdn, zone string, ttl int) (store.Record, string, error) {
	fqdn, zone = strings.TrimSpace(fqdn), strings.TrimSpace(zone)
	if fqdn == "" || zone == "" {
		return store.Record{}, "", missing("fqdn and zone are required")
	}
	if err := s.authZone(a, zone); err != nil {
		return store.Record{}, "", err
	}
	if ttl <= 0 {
		ttl = DefaultDDNSTTL
	}
	if _, ok := dns.IsDomainName(fqdn); !ok || !dns.IsSubDomain(dns.CanonicalName(zone), dns.CanonicalName(fqdn)) {
		return store.Record{}, "", invalid("%s is not a name inside zone %s", fqdn, zone)
	}
	if a.Role != RoleAdmin {
		inv, err := s.inventory(s.cfg())
		if err != nil {
			return store.Record{}, "", err
		}
		if owner := ownerZone(inv, fqdn); owner != NormZone(zone) {
			return store.Record{}, "", invalid("%s belongs to zone %q, not %s", fqdn, owner, NormZone(zone))
		}
	}
	// A user's record is owned by it: the token then works only while the
	// user is enabled and holds the zone (store.Lookup decides at use).
	owner := ""
	if a.Role != RoleAdmin {
		owner = a.User
	}
	rec, tok, err := s.store.AddFor(owner, fqdn, zone, uint32(ttl))
	if err != nil {
		return store.Record{}, "", err
	}
	s.Audit(a, "ddns-add fqdn=%s zone=%s ttl=%d", rec.FQDN, rec.Zone, rec.TTL)
	return rec, tok, nil
}

// DDNSRotate replaces a record's token; the old one stops working at once.
func (s *Service) DDNSRotate(a Actor, fqdn string) (store.Record, string, error) {
	if _, err := s.ddnsRecord(a, fqdn); err != nil {
		return store.Record{}, "", err
	}
	rec, tok, err := s.store.Rotate(strings.TrimSpace(fqdn))
	if err != nil {
		return store.Record{}, "", err
	}
	s.Audit(a, "ddns-rotate fqdn=%s", rec.FQDN)
	return rec, tok, nil
}

// DDNSDel removes a record (its token stops working at once).
func (s *Service) DDNSDel(a Actor, fqdn string) error {
	if _, err := s.ddnsRecord(a, fqdn); err != nil {
		return err
	}
	fqdn = strings.TrimSpace(fqdn)
	if err := s.store.Del(fqdn); err != nil {
		return err
	}
	s.Audit(a, "ddns-del fqdn=%s", store.FQDN(fqdn))
	return nil
}

// TrafficMonthly returns per-month proxy traffic totals (last n months).
func (s *Service) TrafficMonthly(a Actor, n int) ([]store.TrafficRow, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	return s.store.TrafficMonthly(n)
}

// TrafficDaily returns per-day proxy traffic rows (last n days).
func (s *Service) TrafficDaily(a Actor, n int) ([]store.TrafficRow, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	return s.store.TrafficDaily(n)
}
