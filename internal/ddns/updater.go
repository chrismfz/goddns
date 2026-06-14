// Package ddns performs the actual DNS record writes. v1 ships a single
// backend (RFC 2136 / TSIG dynamic update against BIND); the Backend
// interface is the seam where cPanel/DirectAdmin/Virtualmin backends plug
// in later (see BACKLOG.md).
package ddns

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Backend replaces the A or AAAA RRset of fqdn (chosen by the IP family) with
// a single record pointing at ip — the narrow DDNS hot path. The general write
// seam is Mutator (see mutate.go); RFC2136 implements both.
type Backend interface {
	Update(fqdn, zone string, ip net.IP, ttl uint32) error
}

// RFC2136 sends TSIG-signed dynamic updates to a DNS server.
type RFC2136 struct {
	server  string
	keyName string
	algo    string // dns.HmacSHA256 etc.
	secret  string // base64
}

// AlgoToDNS maps a named.conf algorithm name to the miekg/dns constant.
func AlgoToDNS(a string) (string, error) {
	switch strings.ToLower(strings.TrimSuffix(a, ".")) {
	case "hmac-sha256", "":
		return dns.HmacSHA256, nil
	case "hmac-sha512":
		return dns.HmacSHA512, nil
	case "hmac-sha1":
		return dns.HmacSHA1, nil
	case "hmac-md5":
		return dns.HmacMD5, nil
	default:
		return "", fmt.Errorf("unsupported TSIG algorithm %q", a)
	}
}

func NewRFC2136(server, keyName, algo, secret string) (*RFC2136, error) {
	if secret == "" {
		return nil, fmt.Errorf("TSIG secret not set (config tsig_secret or env GODDNS_TSIG_SECRET)")
	}
	a, err := AlgoToDNS(algo)
	if err != nil {
		return nil, err
	}
	return &RFC2136{
		server:  server,
		keyName: dns.Fqdn(keyName),
		algo:    a,
		secret:  secret,
	}, nil
}

// Update replaces the A or AAAA RRset for fqdn with a single record pointing
// at ip — a thin caller of Apply. It removes BOTH address families at the name
// first, so a client flipping IPv4<->IPv6 never leaves the other family's stale
// record answering alongside the new one.
func (u *RFC2136) Update(fqdn, zone string, ip net.IP, ttl uint32) error {
	name := dns.Fqdn(fqdn)
	hdr := dns.RR_Header{Name: name, Class: dns.ClassINET, Ttl: ttl}
	var add dns.RR
	if v4 := ip.To4(); v4 != nil {
		hdr.Rrtype = dns.TypeA
		add = &dns.A{Hdr: hdr, A: v4}
	} else {
		hdr.Rrtype = dns.TypeAAAA
		add = &dns.AAAA{Hdr: hdr, AAAA: ip.To16()}
	}
	return u.Apply(zone, []Op{
		{Action: DelRRset, RR: &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET}}},
		{Action: DelRRset, RR: &dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET}}},
		{Action: AddRR, RR: add},
	})
}
