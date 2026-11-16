package service

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/history"
	"github.com/chrismfz/goddns/internal/named"
)

// KeyInfo is a TSIG key as the inventory reports it. The secret is never
// carried out of the service.
type KeyInfo struct{ Name, Algorithm string }

// ZoneList is the BIND inventory as the zones page shows it.
type ZoneList struct {
	Directory string
	Zones     []named.Zone // user zones (built-in empty zones left out)
	Builtin   int          // how many built-in zones were left out
	Keys      []KeyInfo
	Findings  []named.Finding // TSIG / grant health for goddns's own key
}

// Inventory reads named.conf through `named-checkconf -p` (every include
// inlined by BIND's own parser).
func (s *Service) Inventory(a Actor) (*named.Inventory, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	return inventory(s.cfg())
}

// inventory reads named.conf as cfg names it. Calls that use the config for
// more than this take ONE snapshot and pass it down, so a hot-reload mid-call
// can't mix two configs.
func inventory(cfg *config.Config) (*named.Inventory, error) {
	nc := cfg.NamedConf
	if nc == "" {
		nc = "/etc/named.conf" // config.Load sets it; this covers a bare Config
	}
	data, err := named.CheckConf(nc)
	if err != nil {
		return nil, err
	}
	return named.Parse(data), nil
}

// server is where AXFR / SOA probes go (config.Load defaults it).
func server(cfg *config.Config) string {
	if cfg.DNSServer != "" {
		return cfg.DNSServer
	}
	return "127.0.0.1:53"
}

// Zones lists the zones BIND serves plus the TSIG health findings.
func (s *Service) Zones(a Actor) (*ZoneList, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	cfg := s.cfg()
	inv, err := inventory(cfg)
	if err != nil {
		return nil, err
	}
	zl := &ZoneList{Directory: inv.Directory, Zones: inv.UserZones()}
	zl.Builtin = len(inv.Zones) - len(zl.Zones)
	for _, k := range inv.Keys {
		zl.Keys = append(zl.Keys, KeyInfo{Name: k.Name, Algorithm: k.Algorithm})
	}
	zl.Findings = inv.Check(cfg.TSIGName, cfg.TSIGSecret)
	return zl, nil
}

// nsCheckConcurrency bounds how many zones are probed at once by NSVerdicts.
const nsCheckConcurrency = 8

// NSVerdict is the live NS-serial agreement of one zone. Status is empty for a
// zone with no apex NS set to compare (hint/slave/forward).
type NSVerdict struct {
	Status string
	Serial uint32
}

// NSVerdicts probes every zone's nameservers for serial agreement (a cheap NS
// query + a few SOA probes each, no AXFR), with a small concurrency cap so a
// host with many zones can't be made to open a flood of sockets from one call.
// The result is index-aligned with zones.
func (s *Service) NSVerdicts(a Actor, zones []named.Zone) ([]NSVerdict, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	srv := server(s.cfg())
	out := make([]NSVerdict, len(zones))
	sem := make(chan struct{}, nsCheckConcurrency)
	var wg sync.WaitGroup
	for i := range zones {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = nsVerdict(zones[i], srv)
		}(i)
	}
	wg.Wait()
	return out, nil
}

// NS verdict statuses.
const (
	NSAgree       = "agree"
	NSMismatch    = "mismatch"
	NSUnreachable = "unreachable"
	NSNone        = "no-ns"
)

func nsVerdict(z named.Zone, server string) NSVerdict {
	switch z.Kind() {
	case "static file", "dynamic":
	default:
		return NSVerdict{}
	}
	switch st, serial := named.ZoneSerialCheck(z.Name, server); st {
	case named.SerialAgree:
		return NSVerdict{Status: NSAgree, Serial: serial}
	case named.SerialMismatch:
		return NSVerdict{Status: NSMismatch}
	case named.SerialUnreachable:
		return NSVerdict{Status: NSUnreachable}
	default:
		return NSVerdict{Status: NSNone}
	}
}

// ZoneView is one zone's live content plus its checks.
type ZoneView struct {
	Name     string
	Conf     *named.Zone // nil when named.conf doesn't define it (or can't be read)
	Records  []dns.RR    // the live zone (AXFR, journal-merged), sorted
	Auth     string      // how the transfer was authenticated
	Editable bool        // goddns can edit it (dynamic + held key, or enabled static)
	FileEdit bool        // ...and it is a static zone edited in place

	Delegation []named.Finding // offline SOA-vs-NS checks

	// Live per-nameserver probe, only when asked for (N DNS queries).
	Checked bool
	NS      []named.NSCheck
	Agree   bool // every nameserver answered with the same serial
	NoAuth  bool // no nameserver answered authoritatively
}

// Zone pulls the LIVE records from BIND via AXFR so the caller sees exactly
// what the server answers, including anything written dynamically. Read-only.
// liveNS adds the per-nameserver SOA probe.
func (s *Service) Zone(a Actor, name string, liveNS bool) (*ZoneView, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	cfg := s.cfg()
	srv := server(cfg)

	// named.conf is best-effort: it supplies the dynamic flag and the TSIG
	// keys to authenticate the transfer. Without it we still try unauthenticated.
	inv := &named.Inventory{}
	if i, err := inventory(cfg); err == nil {
		inv = i
	}
	z := inv.ZoneByName(name)

	records, auth, err := named.TransferAuto(name, srv, inv.AXFRKeys(z, cfg.TSIGName))
	if err != nil {
		return nil, err
	}
	named.SortZone(records)

	v := &ZoneView{Name: name, Conf: z, Records: records, Auth: auth}
	if z != nil {
		fed := s.fileEditor(cfg)
		v.FileEdit = fed.CanEdit(z)
		v.Editable = s.recordEditor(cfg).CanEdit(z) || v.FileEdit
	}
	v.Delegation = named.CheckDelegation(name, records)
	if liveNS {
		v.Checked = true
		v.NS = named.CheckNameservers(name, records, srv)
		agree, seen := named.SerialsAgree(v.NS)
		v.Agree = agree && len(seen) == 1
		v.NoAuth = len(seen) == 0
	}
	return v, nil
}

// canEditDynamic reports whether goddns may write the named zone over RFC2136
// (dynamic + a held key). Best-effort: unreadable named.conf ⇒ false.
func (s *Service) canEditDynamic(cfg *config.Config, name string) bool {
	inv, err := inventory(cfg)
	if err != nil {
		return false
	}
	return s.recordEditor(cfg).CanEdit(inv.ZoneByName(name))
}

// SnapshotInfo is one stored snapshot, without its content.
type SnapshotInfo struct {
	ID      int64
	Serial  uint32
	TakenAt time.Time
}

// ZoneHistory is a zone's stored snapshots plus the diff of the latest change.
type ZoneHistory struct {
	Name       string
	Snapshots  []SnapshotInfo // newest first
	Restorable bool           // a snapshot can be restored (dynamic + held key)

	HasDiff        bool
	FromSerial     uint32
	ToSerial       uint32
	Added, Removed []string // SOA serial noise filtered out
}

// History returns the snapshot list (up to 200) and the diff of the most
// recent change. Snapshots are captured by the serve poller.
func (s *Service) History(a Actor, name string) (*ZoneHistory, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	snaps, err := s.store.SnapshotList(name, 200)
	if err != nil {
		return nil, err
	}
	h := &ZoneHistory{Name: name, Restorable: s.canEditDynamic(s.cfg(), name)}
	for _, sn := range snaps {
		h.Snapshots = append(h.Snapshots, SnapshotInfo{ID: sn.ID, Serial: sn.Serial, TakenAt: sn.TakenAt})
	}
	if len(snaps) >= 2 {
		newer, okN, errN := s.store.SnapshotByID(snaps[0].ID)
		older, okO, errO := s.store.SnapshotByID(snaps[1].ID)
		if errN == nil && errO == nil && okN && okO {
			added, removed := history.Diff(older.Content, newer.Content)
			h.Added = history.DropSOA(added)
			h.Removed = history.DropSOA(removed)
			h.FromSerial, h.ToSerial = older.Serial, newer.Serial
			h.HasDiff = true
		}
	}
	return h, nil
}

// NormalizeZone trims whitespace and a trailing dot.
func NormalizeZone(name string) string {
	return strings.TrimSuffix(strings.TrimSpace(name), ".")
}
