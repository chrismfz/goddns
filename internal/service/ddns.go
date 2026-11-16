package service

import (
	"strings"

	"github.com/chrismfz/goddns/internal/store"
)

// DefaultDDNSTTL is the TTL a new DDNS record gets when none is given.
const DefaultDDNSTTL = 60

// DDNSList returns every DDNS record (token → hostname binding).
func (s *Service) DDNSList(a Actor) ([]store.Record, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	return s.store.List()
}

// DDNSGet returns one DDNS record by hostname.
func (s *Service) DDNSGet(a Actor, fqdn string) (store.Record, error) {
	if err := s.requireAdmin(a); err != nil {
		return store.Record{}, err
	}
	return s.store.Get(strings.TrimSpace(fqdn))
}

// DDNSAdd creates a DDNS record and returns it with its bearer token — the
// only time the token exists in clear (the store keeps its hash).
func (s *Service) DDNSAdd(a Actor, fqdn, zone string, ttl int) (store.Record, string, error) {
	if err := s.requireAdmin(a); err != nil {
		return store.Record{}, "", err
	}
	fqdn, zone = strings.TrimSpace(fqdn), strings.TrimSpace(zone)
	if ttl <= 0 {
		ttl = DefaultDDNSTTL
	}
	if fqdn == "" || zone == "" {
		return store.Record{}, "", missing("fqdn and zone are required")
	}
	rec, tok, err := s.store.Add(fqdn, zone, uint32(ttl))
	if err != nil {
		return store.Record{}, "", err
	}
	s.Audit(a, "ddns-add fqdn=%s zone=%s ttl=%d", rec.FQDN, rec.Zone, rec.TTL)
	return rec, tok, nil
}

// DDNSRotate replaces a record's token; the old one stops working at once.
func (s *Service) DDNSRotate(a Actor, fqdn string) (store.Record, string, error) {
	if err := s.requireAdmin(a); err != nil {
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
	if err := s.requireAdmin(a); err != nil {
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
