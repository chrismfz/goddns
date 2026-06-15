package filezone

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// rndcReload reloads a single zone via rndc (per-zone blast radius). It is the
// production default for Editor.Reload.
func rndcReload(zone string) error {
	bin, err := exec.LookPath("rndc")
	if err != nil {
		return errRndcMissing
	}
	if out, err := exec.Command(bin, "reload", zone).CombinedOutput(); err != nil {
		return fmt.Errorf("rndc reload %s: %v (%s)", zone, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// verifySerial queries the local named for the zone's SOA and confirms the
// served serial is at least wantSerial — the post-reload semantic check
// (extended to the apex NS set in a later stage). Uses >= so an inline-signed
// zone (named keeps its own signed serial) doesn't false-fail.
func verifySerial(server, zone string, wantSerial uint32) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	c := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		return fmt.Errorf("SOA query: %w", err)
	}
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			if soa.Serial < wantSerial {
				return fmt.Errorf("served serial %d < expected %d (reload didn't take?)", soa.Serial, wantSerial)
			}
			return nil
		}
	}
	return fmt.Errorf("no SOA in the response for %s", zone)
}
