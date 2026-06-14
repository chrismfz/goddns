package named

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const (
	axfrKeyName = "ddns-update."
	axfrSecret  = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ=" // any base64
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR %q: %v", s, err)
	}
	return rr
}

// AXFR must begin and end with the SOA so the client knows the stream is done.
func sampleZone(t *testing.T) []dns.RR {
	soa := mustRR(t, "myip.gr. 3600 IN SOA ns1.myip.gr. host.myip.gr. 2026061401 3600 600 1209600 60")
	return []dns.RR{
		soa,
		mustRR(t, "myip.gr. 3600 IN NS ns1.myip.gr."),
		mustRR(t, "myip.gr. 3600 IN MX 10 mail.myip.gr."),
		mustRR(t, "www.myip.gr. 60 IN A 203.0.113.10"),
		mustRR(t, "ns1.myip.gr. 3600 IN A 203.0.113.1"),
		soa,
	}
}

type axfrHandler struct {
	records     []dns.RR
	requireTSIG bool
}

func (h *axfrHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 || r.Question[0].Qtype != dns.TypeAXFR {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}
	if h.requireTSIG && (r.IsTsig() == nil || w.TsigStatus() != nil) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}
	tr := &dns.Transfer{}
	if h.requireTSIG {
		tr.TsigSecret = map[string]string{axfrKeyName: axfrSecret}
	}
	ch := make(chan *dns.Envelope, 1)
	ch <- &dns.Envelope{RR: h.records}
	close(ch)
	tr.Out(w, r, ch)
}

func startAXFRServer(t *testing.T, h *axfrHandler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Handler: h}
	if h.requireTSIG {
		srv.TsigSecret = map[string]string{axfrKeyName: axfrSecret}
	}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return ln.Addr().String()
}

func TestTransferUnauthenticated(t *testing.T) {
	addr := startAXFRServer(t, &axfrHandler{records: sampleZone(t)})
	rrs, err := Transfer("myip.gr", addr, nil)
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if len(rrs) != 5 {
		t.Fatalf("got %d records, want 5", len(rrs))
	}
	if soa := SOAOf(rrs); soa == nil || soa.Serial != 2026061401 {
		t.Fatalf("SOA serial wrong: %v", soa)
	}
}

func TestTransferTSIG(t *testing.T) {
	addr := startAXFRServer(t, &axfrHandler{records: sampleZone(t), requireTSIG: true})

	// Unauthenticated must be refused.
	if _, err := Transfer("myip.gr", addr, nil); err == nil {
		t.Fatal("unauthenticated transfer accepted by TSIG-required server")
	}
	// With the right key it works.
	key := &TSIGKey{Name: axfrKeyName, Algo: "hmac-sha256", Secret: axfrSecret}
	rrs, err := Transfer("myip.gr", addr, key)
	if err != nil {
		t.Fatalf("tsig transfer: %v", err)
	}
	if len(rrs) != 5 {
		t.Fatalf("got %d records, want 5", len(rrs))
	}
}

func TestTransferAutoFallsBackToKey(t *testing.T) {
	addr := startAXFRServer(t, &axfrHandler{records: sampleZone(t), requireTSIG: true})
	keys := []TSIGKey{{Name: axfrKeyName, Algo: "hmac-sha256", Secret: axfrSecret}}
	rrs, err := TransferAuto("myip.gr", addr, keys)
	if err != nil {
		t.Fatalf("auto transfer: %v", err)
	}
	if len(rrs) != 5 {
		t.Fatalf("got %d records, want 5", len(rrs))
	}
}

func TestTransferDropsTrailingSOA(t *testing.T) {
	addr := startAXFRServer(t, &axfrHandler{records: sampleZone(t)})
	rrs, err := Transfer("myip.gr", addr, nil)
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	soas := 0
	for _, rr := range rrs {
		if _, ok := rr.(*dns.SOA); ok {
			soas++
		}
	}
	if soas != 1 {
		t.Fatalf("got %d SOA records, want exactly 1 (trailing duplicate must be dropped)", soas)
	}
}

func TestServerRefused(t *testing.T) {
	// An rcode-bearing error = the server answered and refused -> try keys.
	if !serverRefused(errString("axfr myip.gr. from 127.0.0.1:53: dns: bad xfr rcode: 5")) {
		t.Fatal("REFUSED rcode not recognised as a refusal")
	}
	// A dial failure = never reached the server -> don't fan out over keys.
	if serverRefused(errString("axfr myip.gr. from 127.0.0.1:53: dial tcp 127.0.0.1:53: connect: connection refused")) {
		t.Fatal("dial error misclassified as a refusal")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestSortZoneOrder(t *testing.T) {
	rrs := sampleZone(t)[:5] // drop the trailing SOA so each name is unique
	SortZone(rrs)
	rows := Rows(rrs)
	// Apex first (SOA, NS, MX), then children in hierarchical order.
	wantTypes := []string{"SOA", "NS", "MX", "A", "A"}
	wantNames := []string{"myip.gr.", "myip.gr.", "myip.gr.", "ns1.myip.gr.", "www.myip.gr."}
	for i := range wantTypes {
		if rows[i].Type != wantTypes[i] || rows[i].Name != wantNames[i] {
			t.Fatalf("row %d = %s %s, want %s %s", i, rows[i].Name, rows[i].Type, wantNames[i], wantTypes[i])
		}
	}
}

func TestSigned(t *testing.T) {
	if s, n := Signed(sampleZone(t)); s || n != 0 {
		t.Fatalf("unsigned zone reported signed=%v count=%d", s, n)
	}
	signed := append(sampleZone(t)[:5],
		mustRR(t, "myip.gr. 3600 IN DNSKEY 257 3 13 AwEAAa=="),
		mustRR(t, "www.myip.gr. 60 IN RRSIG A 13 3 60 20260701000000 20260601000000 1234 myip.gr. abcd=="),
	)
	if s, n := Signed(signed); !s || n != 2 {
		t.Fatalf("signed zone reported signed=%v count=%d, want true/2", s, n)
	}
}

func TestZoneByName(t *testing.T) {
	inv := &Inventory{Zones: []Zone{{Name: "myip.gr"}, {Name: "ddns.myip.gr"}}}
	if z := inv.ZoneByName("MyIP.gr."); z == nil || z.Name != "myip.gr" {
		t.Fatalf("ZoneByName lookup failed: %v", z)
	}
	if z := inv.ZoneByName("nope.gr"); z != nil {
		t.Fatal("ZoneByName matched a non-existent zone")
	}
}

func TestAXFRKeysOrder(t *testing.T) {
	inv := &Inventory{Keys: []Key{
		{Name: "acme-key", Algorithm: "hmac-sha256", Secret: "a"},
		{Name: "ddns-update", Algorithm: "hmac-sha256", Secret: "b"},
		{Name: "other", Algorithm: "hmac-sha256", Secret: "c"},
	}}
	z := &Zone{Name: "myip.gr", UpdateKeys: []string{"acme-key"}}
	keys := inv.AXFRKeys(z, "ddns-update.")
	got := make([]string, len(keys))
	for i, k := range keys {
		got[i] = k.Name
	}
	// goddns key first, then the zone's granted key, then the rest; no dupes.
	want := []string{"ddns-update", "acme-key", "other"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("AXFRKeys order = %v, want %v", got, want)
	}
}
