package recordmut

import (
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/tsig"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR %q: %v", s, err)
	}
	return rr
}

func testEditor() *Editor {
	return &Editor{
		Keys: []tsig.Key{{Name: "ddns-update", Algo: "hmac-sha256", Secret: "x"}},
	}
}

func inv() *named.Inventory {
	return &named.Inventory{Zones: []named.Zone{
		{Name: "ddns.myip.gr", Type: "master", Dynamic: true, UpdateKeys: []string{"ddns-update"}},
		{Name: "myip.gr", Type: "master", Dynamic: false},
		{Name: "acme.myip.gr", Type: "master", Dynamic: true, UpdateKeys: []string{"acme-key"}},
	}}
}

func TestValidateDynamicAndKey(t *testing.T) {
	e := testEditor()
	op := []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "host.ddns.myip.gr. 60 IN A 1.2.3.4")}}

	// dynamic zone granting our key -> ok
	if _, k, err := e.validate(inv(), "ddns.myip.gr", op); err != nil || k.Name != "ddns-update" {
		t.Fatalf("expected ok with ddns-update key: %v / %+v", err, k)
	}

	// static zone -> refused (the invariant)
	if _, _, err := e.validate(inv(), "myip.gr", []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "x.myip.gr. 60 IN A 1.1.1.1")}}); err == nil || !strings.Contains(err.Error(), "only edits dynamic") {
		t.Errorf("static zone should be refused, got %v", err)
	}

	// dynamic zone granting a key we don't hold -> refused
	if _, _, err := e.validate(inv(), "acme.myip.gr", []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "x.acme.myip.gr. 60 IN TXT \"a\"")}}); err == nil || !strings.Contains(err.Error(), "no goddns TSIG key") {
		t.Errorf("ungranted key should be refused, got %v", err)
	}

	// op name outside the zone -> refused
	out := []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "evil.example. 60 IN A 6.6.6.6")}}
	if _, _, err := e.validate(inv(), "ddns.myip.gr", out); err == nil || !strings.Contains(err.Error(), "not inside") {
		t.Errorf("out-of-zone record should be refused, got %v", err)
	}

	// uppercase name in the zone is accepted (DNS names are case-insensitive)
	up := []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "HOST.DDNS.MYIP.GR. 60 IN A 1.2.3.4")}}
	if _, _, err := e.validate(inv(), "ddns.myip.gr", up); err != nil {
		t.Errorf("uppercase in-zone name should pass: %v", err)
	}
}

func TestDelegatedChildRefused(t *testing.T) {
	e := testEditor()
	in := &named.Inventory{Zones: []named.Zone{
		{Name: "myip.gr", Type: "master", Dynamic: true, UpdateKeys: []string{"ddns-update"}},
		{Name: "ddns.myip.gr", Type: "master", Dynamic: true, UpdateKeys: []string{"ddns-update"}},
	}}
	op := []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "host.ddns.myip.gr. 60 IN A 1.2.3.4")}}
	// targeting the PARENT for a record that belongs to the delegated child -> refused
	if _, _, err := e.validate(in, "myip.gr", op); err == nil || !strings.Contains(err.Error(), "more specific") {
		t.Errorf("parent-target for a child record should be refused, got %v", err)
	}
	// targeting the CHILD correctly -> ok
	if _, _, err := e.validate(in, "ddns.myip.gr", op); err != nil {
		t.Errorf("child-target should pass: %v", err)
	}
}

func TestEmptySecretKeyUnusable(t *testing.T) {
	e := &Editor{Keys: []tsig.Key{{Name: "ddns-update", Algo: "hmac-sha256", Secret: ""}}}
	op := []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "host.ddns.myip.gr. 60 IN A 1.2.3.4")}}
	if _, _, err := e.validate(inv(), "ddns.myip.gr", op); err == nil || !strings.Contains(err.Error(), "no goddns TSIG key") {
		t.Errorf("a key with an empty secret must not be usable, got %v", err)
	}
}

func TestBuildResult(t *testing.T) {
	live := []dns.RR{
		mustRR(t, "host.ddns.myip.gr. 60 IN A 1.1.1.1"),
		mustRR(t, "host.ddns.myip.gr. 60 IN A 2.2.2.2"),
		mustRR(t, "other.ddns.myip.gr. 60 IN A 9.9.9.9"),
	}
	ops := []ddns.Op{
		{Action: ddns.AddRR, RR: mustRR(t, "new.ddns.myip.gr. 60 IN A 3.3.3.3")},
		{Action: ddns.DelRRset, RR: &dns.A{Hdr: dns.RR_Header{Name: "host.ddns.myip.gr.", Rrtype: dns.TypeA, Class: dns.ClassINET}}},
	}
	res := buildResult("ddns.myip.gr", "ddns-update", ops, live)

	if len(res.Added) != 1 || !strings.Contains(res.Added[0], "new.ddns.myip.gr.") {
		t.Fatalf("added = %v", res.Added)
	}
	// the DelRRset must resolve to BOTH host A records, and not touch other.
	if len(res.Removed) != 2 {
		t.Fatalf("removed = %v, want the two host A records", res.Removed)
	}
	for _, r := range res.Removed {
		if !strings.Contains(r, "host.ddns.myip.gr.") {
			t.Fatalf("removed the wrong record: %s", r)
		}
	}
}
