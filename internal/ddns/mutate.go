package ddns

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Action is one record-level operation in a Mutator.Apply batch.
type Action int

const (
	AddRR    Action = iota // add this exact record
	DelRR                  // delete this exact record (name + type + rdata)
	DelRRset               // delete the whole RRset at the record's name + type
	DelName                // delete every record at the record's name
)

// Op is one operation against a zone. For DelRRset only the RR's name and type
// are significant; for DelName only its name.
type Op struct {
	Action Action
	RR     dns.RR
}

// Mutator applies a batch of record operations to a zone atomically. The
// RFC2136 backend does it as one TSIG-signed UPDATE; a future cPanel/
// DirectAdmin/Virtualmin backend does the equivalent through the panel's API,
// honouring the "never touch the zone file/journal" invariant. This is the
// general write seam behind Phase 2 record CRUD and rollback.
type Mutator interface {
	Apply(zone string, ops []Op) error
}

// Apply executes ops against zone in a single TSIG-signed RFC 2136 UPDATE, so
// the whole batch lands atomically (BIND applies an UPDATE all-or-nothing).
func (u *RFC2136) Apply(zone string, ops []Op) error {
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	for i, op := range ops {
		if op.RR == nil {
			return fmt.Errorf("ddns: op %d has a nil RR", i)
		}
		switch op.Action {
		case AddRR:
			m.Insert([]dns.RR{op.RR})
		case DelRR:
			m.Remove([]dns.RR{op.RR})
		case DelRRset:
			m.RemoveRRset([]dns.RR{op.RR})
		case DelName:
			m.RemoveName([]dns.RR{op.RR})
		default:
			return fmt.Errorf("ddns: unknown mutation action %d", op.Action)
		}
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

// Verify probes whether the server accepts this key, by sending a TSIG-signed
// SOA query for name (a zone the server is authoritative for) and requiring the
// response to be TSIG-signed AND verified with our secret. A bare nil error is
// NOT enough: miekg/dns only verifies a response that actually carries a TSIG,
// so an unsigned REFUSED/NOTAUTH (server doesn't have the key) must fail here.
func (u *RFC2136) Verify(name string) error {
	c := &dns.Client{
		TsigSecret: map[string]string{u.keyName: u.secret},
		Timeout:    4 * time.Second,
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeSOA)
	m.SetTsig(u.keyName, u.algo, 300, time.Now().Unix())
	resp, _, err := c.Exchange(m, u.server)
	if err != nil {
		return err // network error, or TSIG verification failed (BADKEY/BADSIG)
	}
	if resp == nil || resp.IsTsig() == nil {
		return fmt.Errorf("response not TSIG-signed — server may not have key %q", u.keyName)
	}
	return nil
}
