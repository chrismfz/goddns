package named

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func healthZone(t *testing.T, mname string, nsGlue bool) []dns.RR {
	rrs := []dns.RR{
		mustRR(t, "myip.gr. 3600 IN SOA "+mname+" admin.myip.gr. 2026061410 3600 600 1209600 300"),
		mustRR(t, "myip.gr. 3600 IN NS ns1.myip.gr."),
		mustRR(t, "myip.gr. 3600 IN NS ns2.myip.gr."),
		// a delegation NS at a sub-name must NOT be treated as an apex NS:
		mustRR(t, "ddns.myip.gr. 3600 IN NS sdns.myip.gr."),
	}
	if nsGlue {
		rrs = append(rrs,
			mustRR(t, "ns1.myip.gr. 600 IN A 84.54.49.6"),
			mustRR(t, "ns2.myip.gr. 600 IN A 45.76.129.127"),
		)
	}
	return rrs
}

func TestApexNSIgnoresSubDelegations(t *testing.T) {
	ns := apexNS("myip.gr", healthZone(t, "ns1.myip.gr.", true))
	if len(ns) != 2 || ns[0] != "ns1.myip.gr" || ns[1] != "ns2.myip.gr" {
		t.Fatalf("apexNS = %v, want [ns1.myip.gr ns2.myip.gr] (sub-delegation excluded)", ns)
	}
}

func TestCheckDelegationMNAMEAndGlue(t *testing.T) {
	// MNAME in NS set + glue present -> an OK finding, no warnings.
	for _, f := range CheckDelegation("myip.gr", healthZone(t, "ns1.myip.gr.", true)) {
		if f.Severity == Warn || f.Severity == Error {
			t.Fatalf("unexpected finding: %v", f)
		}
	}

	// MNAME NOT in NS set -> an Info (hidden primary), and missing glue -> Warn.
	var sawInfo, sawGlueWarn bool
	for _, f := range CheckDelegation("myip.gr", healthZone(t, "sdns.myip.gr.", false)) {
		if f.Severity == Info {
			sawInfo = true
		}
		if f.Severity == Warn {
			sawGlueWarn = true
		}
	}
	if !sawInfo {
		t.Error("expected Info for hidden-primary MNAME not in NS set")
	}
	if !sawGlueWarn {
		t.Error("expected Warn for in-zone NS missing glue")
	}
}

func TestSerialsAgree(t *testing.T) {
	agree, seen := SerialsAgree([]NSCheck{
		{OK: true, Serial: 10}, {OK: true, Serial: 10}, {OK: false, Serial: 7},
	})
	if !agree || len(seen) != 1 || seen[10] != 2 {
		t.Fatalf("agree=%v seen=%v, want agree on 10 (unreachable ignored)", agree, seen)
	}
	agree, _ = SerialsAgree([]NSCheck{{OK: true, Serial: 10}, {OK: true, Serial: 7}})
	if agree {
		t.Fatal("expected disagreement when serials differ")
	}
}

// soaServer answers SOA queries with a fixed serial, authoritatively.
type soaServer struct{ serial uint32 }

func (s *soaServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeSOA {
		soa, _ := dns.NewRR("myip.gr. 300 IN SOA ns1.myip.gr. admin.myip.gr. 2026061410 3600 600 1209600 300")
		soa.(*dns.SOA).Serial = s.serial
		m.Answer = append(m.Answer, soa)
	}
	w.WriteMsg(m)
}

func startSOAServer(t *testing.T, serial uint32) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: &soaServer{serial: serial}}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

type nsServer struct{ answer, extra []dns.RR }

func (s *nsServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeNS {
		m.Answer = s.answer
		m.Extra = s.extra
	}
	w.WriteMsg(m)
}

func TestZoneNS(t *testing.T) {
	answer := []dns.RR{
		mustRR(t, "myip.gr. 3600 IN NS ns1.myip.gr."),
		mustRR(t, "myip.gr. 3600 IN NS ns2.myip.gr."),
	}
	extra := []dns.RR{
		mustRR(t, "ns1.myip.gr. 600 IN A 84.54.49.6"),
		mustRR(t, "ns2.myip.gr. 600 IN A 45.76.129.127"),
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: &nsServer{answer, extra}}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })

	rrs := ZoneNS("myip.gr", pc.LocalAddr().String())
	if ns := apexNS("myip.gr", rrs); len(ns) != 2 || ns[0] != "ns1.myip.gr" || ns[1] != "ns2.myip.gr" {
		t.Fatalf("apexNS from ZoneNS = %v, want [ns1.myip.gr ns2.myip.gr]", ns)
	}
	if idx := addressIndex(rrs); len(idx["ns1.myip.gr"]) != 1 || idx["ns1.myip.gr"][0] != "84.54.49.6" {
		t.Fatalf("glue not captured from additional section: %v", idx)
	}
}

func TestProbeSOA(t *testing.T) {
	addr := startSOAServer(t, 2026061410)
	serial, aa, err := probeSOA("myip.gr", addr)
	if err != nil || !aa || serial != 2026061410 {
		t.Fatalf("probeSOA = (%d, %v, %v), want (2026061410, true, nil)", serial, aa, err)
	}
	if _, _, err := probeSOA("myip.gr", "127.0.0.1:1"); err == nil {
		t.Fatal("expected error probing a dead port")
	}
}
