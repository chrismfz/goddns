package named

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var errUnreachable = errors.New("unreachable")

// NSCheck is the live result of probing one apex nameserver for the zone's
// SOA (Tier 2): which serial it serves, whether it answered authoritatively,
// and whether it was reachable at all.
type NSCheck struct {
	Name   string   // nameserver hostname
	Addrs  []string // addresses considered (glue or resolved)
	Serial uint32   // SOA serial it served (0 = none obtained)
	AA     bool     // answered authoritatively (AA bit)
	OK     bool     // reachable, authoritative, SOA present
	Note   string   // short status / error when not OK
}

// apexNS returns the NS targets defined AT the zone apex. Delegations to
// sub-names (e.g. _acme-challenge, ddns, rbl) are ignored — we only want the
// servers authoritative for THIS zone.
func apexNS(zone string, rrs []dns.RR) []string {
	apex := dns.Fqdn(zone)
	var out []string
	seen := map[string]bool{}
	for _, rr := range rrs {
		if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Header().Name, apex) {
			t := strings.TrimSuffix(strings.ToLower(ns.Ns), ".")
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// addressIndex maps owner name (lowercased, no trailing dot) to its A/AAAA
// addresses found in the transferred records (the in-zone glue).
func addressIndex(rrs []dns.RR) map[string][]string {
	m := map[string][]string{}
	add := func(name, ip string) {
		n := strings.TrimSuffix(strings.ToLower(name), ".")
		m[n] = append(m[n], ip)
	}
	for _, rr := range rrs {
		switch r := rr.(type) {
		case *dns.A:
			add(r.Header().Name, r.A.String())
		case *dns.AAAA:
			add(r.Header().Name, r.AAAA.String())
		}
	}
	return m
}

// CheckDelegation runs the offline (Tier 1) SOA-vs-NS consistency checks from
// the transferred records — no network. It verifies the SOA primary (MNAME)
// is among the apex NS, and that each in-zone NS has address (glue) records.
func CheckDelegation(zone string, rrs []dns.RR) []Finding {
	apex := strings.TrimSuffix(dns.Fqdn(zone), ".")
	ns := apexNS(zone, rrs)
	if len(ns) == 0 {
		return []Finding{{Error, apex, "no NS records at the zone apex"}}
	}
	addrs := addressIndex(rrs)
	var f []Finding

	if soa := SOAOf(rrs); soa != nil {
		mname := strings.TrimSuffix(strings.ToLower(soa.Ns), ".")
		inSet := false
		for _, n := range ns {
			if n == mname {
				inSet = true
				break
			}
		}
		if inSet {
			f = append(f, Finding{OK, apex, "SOA primary " + mname + " is listed in the NS set"})
		} else {
			f = append(f, Finding{Info, apex,
				"SOA primary (MNAME) " + mname + " is not in the NS set — normal for a hidden primary, otherwise check for a typo"})
		}
	}

	apexSuffix := "." + apex
	for _, n := range ns {
		inZone := n == apex || strings.HasSuffix(n, apexSuffix)
		if inZone && len(addrs[n]) == 0 {
			f = append(f, Finding{Warn, apex,
				"nameserver " + n + " has no A/AAAA in the zone (in-zone NS needs glue)"})
		}
	}
	return f
}

// CheckNameservers runs the live (Tier 2) probe: for each apex nameserver it
// finds an address (in-zone glue first, otherwise resolves via resolver) and
// queries that server DIRECTLY, non-recursively, for the zone SOA — reporting
// which serial each one actually serves. This is what surfaces a secondary
// stuck on an old serial (the classic propagation foot-gun). Read-only.
func CheckNameservers(zone string, rrs []dns.RR, resolver string) []NSCheck {
	idx := addressIndex(rrs)
	names := apexNS(zone, rrs)
	// Probe nameservers concurrently so the wall clock is ~the slowest single
	// server, not the sum — a request can't be made to hang for K×timeout by
	// several slow/blackholing nameservers.
	out := make([]NSCheck, len(names))
	var wg sync.WaitGroup
	for i, nsName := range names {
		wg.Add(1)
		go func(i int, nsName string) {
			defer wg.Done()
			out[i] = probeNS(zone, nsName, idx[nsName], resolver)
		}(i, nsName)
	}
	wg.Wait()
	return out
}

// probeNS resolves one nameserver (in-zone glue first, else via resolver) and
// queries it for the zone SOA. At most a few addresses are tried so a server
// with many dead addresses can't burn the whole budget.
func probeNS(zone, nsName string, glue []string, resolver string) NSCheck {
	c := NSCheck{Name: nsName}
	addrs := glue
	if len(addrs) == 0 && resolver != "" {
		addrs = resolveHost(nsName, resolver)
	}
	c.Addrs = addrs
	if len(addrs) == 0 {
		c.Note = "no address (couldn't resolve)"
		return c
	}
	if len(addrs) > 3 {
		addrs = addrs[:3]
	}
	for _, a := range addrs {
		serial, aa, err := probeSOA(zone, a)
		if err != nil {
			c.Note = "unreachable"
			continue
		}
		c.Serial, c.AA = serial, aa
		switch {
		case !aa:
			c.Note = "not authoritative (lame delegation?)"
		case serial == 0:
			c.Note = "no SOA in answer"
		default:
			c.OK = true
			c.Note = ""
		}
		break
	}
	return c
}

// SerialStatus summarizes a zone's nameserver serial agreement.
type SerialStatus int

const (
	SerialNoNS        SerialStatus = iota // no apex NS reachable to check
	SerialAgree                           // all reachable NS serve the same serial
	SerialMismatch                        // nameservers disagree (a secondary is behind)
	SerialUnreachable                     // NS exist but none answered authoritatively
)

// ZoneNS fetches a zone's apex NS records plus any in-zone glue (A/AAAA in the
// additional/authority sections) from server via a single non-recursive query.
// This is far cheaper than an AXFR when only the delegation set is needed, and
// — unlike AXFR — it doesn't depend on allow-transfer. Read-only.
func ZoneNS(zone, server string) []dns.RR {
	c := &dns.Client{Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeNS)
	m.RecursionDesired = false
	resp, _, err := c.Exchange(m, withPort(server))
	if err != nil || resp == nil {
		return nil
	}
	if resp.Truncated { // NS sets + glue can exceed a UDP datagram
		c.Net = "tcp"
		if r2, _, e := c.Exchange(m, withPort(server)); e == nil && r2 != nil {
			resp = r2
		}
	}
	rrs := append([]dns.RR{}, resp.Answer...)
	rrs = append(rrs, resp.Ns...)    // some servers put apex NS here
	rrs = append(rrs, resp.Extra...) // glue addresses (OPT is ignored downstream)
	return rrs
}

// ZoneSerialCheck fetches a zone's apex nameservers from server (a cheap NS
// query, no AXFR) and probes each one directly for the SOA serial it serves,
// returning an agreement verdict and the agreed serial. Read-only.
func ZoneSerialCheck(zone, server string) (SerialStatus, uint32) {
	checks := CheckNameservers(zone, ZoneNS(zone, server), server)
	if len(checks) == 0 {
		return SerialNoNS, 0
	}
	agree, seen := SerialsAgree(checks)
	switch {
	case len(seen) == 0:
		return SerialUnreachable, 0
	case agree && len(seen) == 1:
		for s := range seen {
			return SerialAgree, s
		}
	}
	return SerialMismatch, 0
}

// SerialsAgree reports whether all reachable, authoritative nameservers serve
// the same SOA serial, and returns the distinct serials seen (serial -> count).
// Note: with zero reachable nameservers it returns true with an empty map;
// callers should treat len(seen)==0 as "nobody answered", not as agreement.
func SerialsAgree(checks []NSCheck) (bool, map[uint32]int) {
	seen := map[uint32]int{}
	for _, c := range checks {
		if c.OK {
			seen[c.Serial]++
		}
	}
	return len(seen) <= 1, seen
}

// resolveHost recursively resolves a hostname's A/AAAA via resolver (used only
// for out-of-zone nameservers that have no glue in the zone).
func resolveHost(name, resolver string) []string {
	c := &dns.Client{Timeout: 2 * time.Second}
	var addrs []string
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qt)
		m.RecursionDesired = true
		resp, _, err := c.Exchange(m, withPort(resolver))
		if err != nil || resp == nil {
			continue
		}
		for _, rr := range resp.Answer {
			switch r := rr.(type) {
			case *dns.A:
				addrs = append(addrs, r.A.String())
			case *dns.AAAA:
				addrs = append(addrs, r.AAAA.String())
			}
		}
	}
	return addrs
}

// probeSOA queries addr directly (non-recursive) for the zone SOA and returns
// the serial and whether the answer was authoritative.
func probeSOA(zone, addr string) (uint32, bool, error) {
	c := &dns.Client{Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.RecursionDesired = false
	resp, _, err := c.Exchange(m, withPort(addr))
	if err != nil || resp == nil {
		return 0, false, errUnreachable
	}
	// A truncated UDP answer (e.g. a DNSSEC-signed SOA) would otherwise look
	// like "no SOA" — retry over TCP so a healthy signed secondary isn't
	// falsely reported as a mismatch.
	if resp.Truncated {
		c.Net = "tcp"
		if r2, _, err2 := c.Exchange(m, withPort(addr)); err2 == nil && r2 != nil {
			resp = r2
		}
	}
	var serial uint32
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			serial = soa.Serial
		}
	}
	return serial, resp.Authoritative, nil
}
