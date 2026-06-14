package named

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// TSIGKey is a key usable for an authenticated zone transfer. Secret == ""
// means an unauthenticated transfer (allowed when allow-transfer permits the
// peer, e.g. localhost).
type TSIGKey struct {
	Name   string // key name (trailing dot optional)
	Algo   string // named.conf algorithm name, e.g. hmac-sha256
	Secret string // base64
}

// algoToDNS maps a named.conf algorithm name to the miekg/dns constant. Kept
// local so the named package stays self-contained (it mirrors ddns.AlgoToDNS).
func algoToDNS(a string) string {
	switch strings.ToLower(strings.TrimSuffix(a, ".")) {
	case "hmac-sha512":
		return dns.HmacSHA512
	case "hmac-sha1":
		return dns.HmacSHA1
	case "hmac-md5":
		return dns.HmacMD5
	default: // hmac-sha256 and unknown both default to the modern algorithm
		return dns.HmacSHA256
	}
}

// withPort returns server with :53 appended if it has no port.
func withPort(server string) string {
	if _, _, err := net.SplitHostPort(server); err != nil {
		return net.JoinHostPort(server, "53")
	}
	return server
}

// Transfer performs an AXFR of zone from server and returns all records. When
// key is non-nil and has a secret, the request is TSIG-signed. This is a
// read-only query: it never changes anything on the server. The records are
// the LIVE contents as the server serves them — for a dynamic zone that means
// journal-merged data, not the (possibly stale) on-disk zone file.
// maxRecords caps how many RRs a single transfer will buffer. It's a memory
// guard for the per-request admin handler against a pathological/hostile
// primary; it sits far above any realistic hand-run zone.
const maxRecords = 1_000_000

func Transfer(zone, server string, key *TSIGKey) ([]dns.RR, error) {
	zone = dns.Fqdn(zone)
	if len(zone) > 255 {
		return nil, fmt.Errorf("axfr: zone name too long (%d > 255 octets)", len(zone))
	}
	server = withPort(server)

	m := new(dns.Msg)
	m.SetAxfr(zone)

	t := &dns.Transfer{DialTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second}
	if key != nil && key.Secret != "" {
		name := dns.Fqdn(key.Name)
		t.TsigSecret = map[string]string{name: key.Secret}
		m.SetTsig(name, algoToDNS(key.Algo), 300, time.Now().Unix())
	}

	env, err := t.In(m, server)
	if err != nil {
		return nil, fmt.Errorf("axfr %s from %s: %w", zone, server, err)
	}
	var rrs []dns.RR
	for e := range env {
		if e.Error != nil {
			return nil, fmt.Errorf("axfr %s from %s: %w", zone, server, e.Error)
		}
		rrs = append(rrs, e.RR...)
		if len(rrs) > maxRecords {
			return nil, fmt.Errorf("axfr %s from %s: zone exceeds %d records — refusing to buffer", zone, server, maxRecords)
		}
	}
	if len(rrs) == 0 {
		return nil, fmt.Errorf("axfr %s from %s: empty transfer", zone, server)
	}
	// AXFR frames the zone as SOA ... SOA: the closing SOA repeats the opening
	// one only to mark the end. Drop that trailing duplicate so callers (and a
	// -export dump) see the SOA exactly once.
	if len(rrs) >= 2 {
		if _, first := rrs[0].(*dns.SOA); first {
			if _, last := rrs[len(rrs)-1].(*dns.SOA); last {
				rrs = rrs[:len(rrs)-1]
			}
		}
	}
	return rrs, nil
}

// TransferAuto tries an unauthenticated AXFR first (covers allow-transfer
// { localhost; }, the common case for a local goddns), then falls back to each
// candidate key in turn. It returns the records from the first method that
// works, or the original (unauthenticated) error — which is the most useful
// one to show ("REFUSED" → tell the operator to allow-transfer).
func TransferAuto(zone, server string, keys []TSIGKey) ([]dns.RR, error) {
	rrs, firstErr := Transfer(zone, server, nil)
	if firstErr == nil {
		return rrs, nil
	}
	// Only fall back to keys if the server ANSWERED and refused (REFUSED/
	// NOTAUTH come back as an xfr rcode). A dial/timeout error means we never
	// reached BIND, so authenticating won't help — fail fast instead of
	// fanning out one connection per key. Bound the whole fallback by a wall
	// clock so a slow server can't stack (K+1) full timeouts on one request.
	if !serverRefused(firstErr) {
		return nil, firstErr
	}
	deadline := time.Now().Add(20 * time.Second)
	for i := range keys {
		if time.Now().After(deadline) {
			break
		}
		if rrs, err := Transfer(zone, server, &keys[i]); err == nil {
			return rrs, nil
		}
	}
	return nil, firstErr
}

// serverRefused reports whether err is a transfer the server actively rejected
// (an rcode), as opposed to a connection/timeout failure where it never got to
// answer. miekg/dns reports the former as "bad xfr rcode: N".
func serverRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "rcode")
}

// AXFRKeys builds the candidate keys to try for transferring z, most likely
// first: goddns's own key, then keys granted update rights on the zone, then
// every other key defined in named.conf. Secrets come from the parsed config
// (named-checkconf -p exposes them), so authenticated AXFR works even when
// allow-transfer is locked to a specific key.
func (inv *Inventory) AXFRKeys(z *Zone, goddnsName string) []TSIGKey {
	goddnsName = strings.TrimSuffix(goddnsName, ".")
	var out []TSIGKey
	seen := map[string]bool{}
	add := func(name string) {
		name = strings.TrimSuffix(name, ".")
		if name == "" || seen[name] {
			return
		}
		for _, k := range inv.Keys {
			if k.Name == name {
				seen[name] = true
				out = append(out, TSIGKey{Name: k.Name, Algo: k.Algorithm, Secret: k.Secret})
				return
			}
		}
	}
	add(goddnsName)
	if z != nil {
		for _, k := range z.UpdateKeys {
			add(k)
		}
	}
	for _, k := range inv.Keys {
		add(k.Name)
	}
	return out
}

// ZoneByName returns the user zone with the given name (trailing dot ignored),
// or nil. View-split configs may define the name more than once; the first
// match wins (the detail view is per-name, not per-view, in v1).
func (inv *Inventory) ZoneByName(name string) *Zone {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for i := range inv.Zones {
		if strings.ToLower(inv.Zones[i].Name) == name {
			return &inv.Zones[i]
		}
	}
	return nil
}

// RR is a flattened record for display: owner name, TTL, type and the rdata
// (everything after the header), ready for a table or a zone-file dump.
type RR struct {
	Name string
	TTL  uint32
	Type string
	Data string
}

// Rows flattens records for display. Call SortZone first for a stable,
// human-friendly order.
func Rows(rrs []dns.RR) []RR {
	out := make([]RR, 0, len(rrs))
	for _, rr := range rrs {
		h := rr.Header()
		out = append(out, RR{
			Name: h.Name,
			TTL:  h.Ttl,
			Type: dns.TypeToString[h.Rrtype],
			Data: strings.TrimPrefix(rr.String(), h.String()),
		})
	}
	return out
}

// SOAOf returns the zone's SOA record, or nil if the transfer had none.
func SOAOf(rrs []dns.RR) *dns.SOA {
	for _, rr := range rrs {
		if s, ok := rr.(*dns.SOA); ok {
			return s
		}
	}
	return nil
}

// Signed reports whether the transfer carries DNSSEC material and how many
// such records there are (RRSIG/DNSKEY/NSEC/NSEC3/NSEC3PARAM/CDS/CDNSKEY). For
// a signed zone these are normally generated and rotated by BIND itself
// (inline-signing / auto-dnssec); they expire, so restoring them by hand from
// an AXFR dump is usually wrong — the export header warns about this.
func Signed(rrs []dns.RR) (bool, int) {
	n := 0
	for _, rr := range rrs {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC, dns.TypeNSEC3,
			dns.TypeNSEC3PARAM, dns.TypeCDS, dns.TypeCDNSKEY:
			n++
		}
	}
	return n > 0, n
}

// SortZone orders records the way an operator reads a zone file: apex first,
// then subdomains in hierarchical order; within a name SOA, then NS, then MX,
// then the rest by type and rdata.
func SortZone(rrs []dns.RR) {
	rank := func(rr dns.RR) int {
		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			return 0
		case dns.TypeNS:
			return 1
		case dns.TypeMX:
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(rrs, func(i, j int) bool {
		ni, nj := rrs[i].Header().Name, rrs[j].Header().Name
		if !sameName(ni, nj) {
			return lessName(ni, nj)
		}
		if ri, rj := rank(rrs[i]), rank(rrs[j]); ri != rj {
			return ri < rj
		}
		return rrs[i].String() < rrs[j].String()
	})
}

func sameName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// lessName compares names by reversed labels, so the apex sorts before its
// children and siblings group together (gr < com, then myip.gr before
// www.myip.gr, etc.).
func lessName(a, b string) bool {
	ra, rb := reverseLabels(a), reverseLabels(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if ra[i] != rb[i] {
			return ra[i] < rb[i]
		}
	}
	return len(ra) < len(rb)
}

func reverseLabels(name string) []string {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels
}
