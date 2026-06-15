package ddns

import (
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

const (
	testKeyName = "ddns-update."
	testSecret  = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ=" // any base64
)

// testDNSServer runs an in-process authoritative server that accepts
// TSIG-signed UPDATEs and records what it was asked to do — a stand-in for
// BIND so the full miekg/dns exchange (incl. TSIG validation) is exercised.
type testDNSServer struct {
	mu      sync.Mutex
	updates []*dns.Msg
	badTSIG bool
}

func (h *testDNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if r.Opcode != dns.OpcodeUpdate {
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}
	if tsig := r.IsTsig(); tsig != nil && w.TsigStatus() == nil {
		h.mu.Lock()
		h.updates = append(h.updates, r.Copy())
		h.mu.Unlock()
		m.SetTsig(testKeyName, dns.HmacSHA256, 300,
			int64(r.Extra[len(r.Extra)-1].(*dns.TSIG).TimeSigned))
	} else {
		h.badTSIG = true
		m.Rcode = dns.RcodeNotAuth
	}
	w.WriteMsg(m)
}

func startTestServer(t *testing.T) (addr string, h *testDNSServer) {
	t.Helper()
	h = &testDNSServer{}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler:    h,
		TsigSecret: map[string]string{testKeyName: testSecret},
		// default accept func rejects UPDATE opcodes with NOTIMP
		MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept },
	}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String(), h
}

func TestUpdateEndToEnd(t *testing.T) {
	addr, h := startTestServer(t)

	u, err := NewRFC2136(addr, testKeyName, "hmac-sha256", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Update("home.myip.gr", "myip.gr", net.ParseIP("203.0.113.10"), 60); err != nil {
		t.Fatalf("update: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.badTSIG {
		t.Fatal("server saw a bad/missing TSIG")
	}
	if len(h.updates) != 1 {
		t.Fatalf("got %d updates, want 1", len(h.updates))
	}
	msg := h.updates[0]
	if zone := msg.Question[0].Name; zone != "myip.gr." {
		t.Fatalf("update zone: %q", zone)
	}
	// Ns section carries the update RRs: an RRset delete + our A insert.
	var inserted *dns.A
	for _, rr := range msg.Ns {
		if a, ok := rr.(*dns.A); ok && a.Hdr.Class == dns.ClassINET {
			inserted = a
		}
	}
	if inserted == nil {
		t.Fatalf("no A insert found in %v", msg.Ns)
	}
	if inserted.Hdr.Name != "home.myip.gr." || !inserted.A.Equal(net.ParseIP("203.0.113.10")) || inserted.Hdr.Ttl != 60 {
		t.Fatalf("inserted RR wrong: %v", inserted)
	}
}

func TestUpdateAAAA(t *testing.T) {
	addr, h := startTestServer(t)
	u, err := NewRFC2136(addr, testKeyName, "hmac-sha256", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Update("home.myip.gr", "myip.gr", net.ParseIP("2001:db8::1"), 60); err != nil {
		t.Fatalf("update: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	found := false
	for _, rr := range h.updates[0].Ns {
		if aaaa, ok := rr.(*dns.AAAA); ok && aaaa.AAAA.Equal(net.ParseIP("2001:db8::1")) {
			found = true
		}
	}
	if !found {
		t.Fatal("AAAA insert not found")
	}
}

func TestApplyOps(t *testing.T) {
	addr, h := startTestServer(t)
	u, err := NewRFC2136(addr, testKeyName, "hmac-sha256", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	add, _ := dns.NewRR("www.myip.gr. 60 IN A 203.0.113.5")
	ops := []Op{
		{Action: AddRR, RR: add},
		{Action: DelRRset, RR: &dns.TXT{Hdr: dns.RR_Header{Name: "old.myip.gr.", Rrtype: dns.TypeTXT, Class: dns.ClassINET}}},
		{Action: DelName, RR: &dns.A{Hdr: dns.RR_Header{Name: "gone.myip.gr.", Class: dns.ClassINET}}},
	}
	if err := u.Apply("myip.gr", ops); err != nil {
		t.Fatalf("apply: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.badTSIG {
		t.Fatal("server saw a bad/missing TSIG")
	}
	if len(h.updates) != 1 {
		t.Fatalf("got %d updates, want 1", len(h.updates))
	}
	var inserted *dns.A
	for _, rr := range h.updates[0].Ns {
		if a, ok := rr.(*dns.A); ok && a.Hdr.Class == dns.ClassINET {
			inserted = a
		}
	}
	if inserted == nil || inserted.Hdr.Name != "www.myip.gr." || !inserted.A.Equal(net.ParseIP("203.0.113.5")) {
		t.Fatalf("AddRR not applied: %v", h.updates[0].Ns)
	}
}

// RFC2136 must satisfy both the narrow Backend and the general Mutator.
var _ Backend = (*RFC2136)(nil)
var _ Mutator = (*RFC2136)(nil)

func TestVerifyKey(t *testing.T) {
	// A server that answers SOA queries and TSIG-signs the response only when
	// the request's TSIG verified — i.e. it has the key (like real named).
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		TsigSecret: map[string]string{testKeyName: testSecret},
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			soa, _ := dns.NewRR("myip.gr. 60 IN SOA ns.myip.gr. h.myip.gr. 1 3600 600 1209600 60")
			m.Answer = append(m.Answer, soa)
			if r.IsTsig() != nil && w.TsigStatus() == nil {
				m.SetTsig(testKeyName, dns.HmacSHA256, 300,
					int64(r.Extra[len(r.Extra)-1].(*dns.TSIG).TimeSigned))
			}
			w.WriteMsg(m)
		}),
	}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	addr := pc.LocalAddr().String()

	u, _ := NewRFC2136(addr, testKeyName, "hmac-sha256", testSecret)
	if err := u.Verify("myip.gr"); err != nil {
		t.Fatalf("verify with correct secret should pass: %v", err)
	}
	bad, _ := NewRFC2136(addr, testKeyName, "hmac-sha256",
		"d3Jvbmctc2VjcmV0LXdyb25nLXNlY3JldC13cm9uZyE=")
	if err := bad.Verify("myip.gr"); err == nil {
		t.Fatal("verify with wrong secret must fail (unsigned/unverified response)")
	}
}

func TestWrongSecretRejected(t *testing.T) {
	addr, _ := startTestServer(t)
	u, err := NewRFC2136(addr, testKeyName, "hmac-sha256",
		"d3Jvbmctc2VjcmV0LXdyb25nLXNlY3JldC13cm9uZyE=")
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Update("home.myip.gr", "myip.gr", net.ParseIP("203.0.113.10"), 60); err == nil {
		t.Fatal("update with wrong TSIG secret succeeded")
	}
}

func TestNewRequiresSecret(t *testing.T) {
	if _, err := NewRFC2136("127.0.0.1:53", testKeyName, "hmac-sha256", ""); err == nil {
		t.Fatal("empty secret accepted")
	}
	if _, err := NewRFC2136("127.0.0.1:53", testKeyName, "hmac-bogus", testSecret); err == nil {
		t.Fatal("bogus algo accepted")
	}
}
