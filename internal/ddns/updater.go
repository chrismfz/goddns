// Package ddns performs the actual DNS record writes. v1 ships a single
// backend (RFC 2136 / TSIG dynamic update against BIND); the Backend
// interface is the seam where cPanel/DirectAdmin/Virtualmin backends plug
// in later (see BACKLOG.md).
package ddns

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Backend replaces the A or AAAA RRset of fqdn (chosen by the IP family)
// with a single record pointing at ip.
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
// at ip, inside zone, using a signed RFC 2136 UPDATE.
func (u *RFC2136) Update(fqdn, zone string, ip net.IP, ttl uint32) error {
	rrType := dns.TypeA
	if ip.To4() == nil {
		rrType = dns.TypeAAAA
	}

	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))

	// Remove any existing RRset of this exact type at this name, then add ours.
	m.RemoveRRset([]dns.RR{&dns.A{Hdr: dns.RR_Header{
		Name: dns.Fqdn(fqdn), Rrtype: rrType, Class: dns.ClassINET}}})

	hdr := dns.RR_Header{Name: dns.Fqdn(fqdn), Rrtype: rrType, Class: dns.ClassINET, Ttl: ttl}
	if rrType == dns.TypeA {
		m.Insert([]dns.RR{&dns.A{Hdr: hdr, A: ip.To4()}})
	} else {
		m.Insert([]dns.RR{&dns.AAAA{Hdr: hdr, AAAA: ip.To16()}})
	}

	m.SetTsig(u.keyName, u.algo, 300, time.Now().Unix())

	c := &dns.Client{
		TsigSecret: map[string]string{u.keyName: u.secret},
		Timeout:    5 * time.Second,
	}
	resp, _, err := c.Exchange(m, u.server)
	if err != nil {
		return fmt.Errorf("dns exchange: %w", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("dns update rejected: %s", dns.RcodeToString[resp.Rcode])
	}
	return nil
}
