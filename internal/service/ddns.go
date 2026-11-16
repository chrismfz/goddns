package service

import (
	"strings"

	"github.com/chrismfz/goddns/internal/store"
)

// DefaultDDNSTTL is the TTL a new DDNS record gets when none is given.
const DefaultDDNSTTL = 60

// DDNSList returns every DDNS record (token → hostname binding).
func (s *Service) DDNSList() ([]store.Record, error) { return s.store.List() }

// DDNSGet returns one DDNS record by hostname.
func (s *Service) DDNSGet(fqdn string) (store.Record, error) {
	return s.store.Get(strings.TrimSpace(fqdn))
}

// DDNSAdd creates a DDNS record and returns it with its bearer token — the
// only time the token exists in clear (the store keeps its hash).
func (s *Service) DDNSAdd(a Actor, fqdn, zone string, ttl int) (store.Record, string, error) {
	fqdn, zone = strings.TrimSpace(fqdn), strings.TrimSpace(zone)
	if ttl <= 0 {
		ttl = DefaultDDNSTTL
	}
	if fqdn == "" || zone == "" {
		return store.Record{}, "", invalid("fqdn and zone are required")
	}
	rec, tok, err := s.store.Add(fqdn, zone, uint32(ttl))
	if err != nil {
		return store.Record{}, "", err
	}
	s.audit(a, "ddns-add fqdn=%s zone=%s ttl=%d", rec.FQDN, rec.Zone, rec.TTL)
	return rec, tok, nil
}

// DDNSRotate replaces a record's token; the old one stops working at once.
func (s *Service) DDNSRotate(a Actor, fqdn string) (store.Record, string, error) {
	rec, tok, err := s.store.Rotate(strings.TrimSpace(fqdn))
	if err != nil {
		return store.Record{}, "", err
	}
	s.audit(a, "ddns-rotate fqdn=%s", rec.FQDN)
	return rec, tok, nil
}

// DDNSDel removes a record (its token stops working at once).
func (s *Service) DDNSDel(a Actor, fqdn string) error {
	fqdn = strings.TrimSpace(fqdn)
	if err := s.store.Del(fqdn); err != nil {
		return err
	}
	s.audit(a, "ddns-del fqdn=%s", store.FQDN(fqdn))
	return nil
}

// TrafficMonthly returns per-month proxy traffic totals (last n months).
func (s *Service) TrafficMonthly(n int) ([]store.TrafficRow, error) { return s.store.TrafficMonthly(n) }

// TrafficDaily returns per-day proxy traffic rows (last n days).
func (s *Service) TrafficDaily(n int) ([]store.TrafficRow, error) { return s.store.TrafficDaily(n) }
