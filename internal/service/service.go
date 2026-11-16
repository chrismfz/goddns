// Package service is goddns's single funnel for everything an operator can do:
// read the BIND inventory and zones, edit records (dynamic via RFC2136, enabled
// static zones in place), restore snapshots, manage DDNS tokens and proxy.d/
// vhosts. The admin UI is one front-end over it; the machine API and the CLI
// are meant to be others, so the rules (routing by zone ownership, the
// console-port collision check, audit lines, reload-after-write) live here
// ONCE instead of being re-derived per surface.
//
// It is transport-agnostic: no HTTP, no templates, no sessions. Callers own
// authentication and presentation; every mutating call takes the Actor it
// audits as. Authorization (who may touch which zone) is the next layer and
// will be enforced here too, so no front-end can forget it.
package service

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/filezone"
	"github.com/chrismfz/goddns/internal/recordmut"
	"github.com/chrismfz/goddns/internal/store"
	"github.com/chrismfz/goddns/internal/tsig"
	"github.com/chrismfz/goddns/internal/vhostmut"
)

// Store is the slice of the SQLite store the service needs.
type Store interface {
	List() ([]store.Record, error)
	Add(name, zone string, ttl uint32) (store.Record, string, error)
	Del(name string) error
	Rotate(name string) (store.Record, string, error)
	Get(name string) (store.Record, error)
	TrafficMonthly(months int) ([]store.TrafficRow, error)
	TrafficDaily(days int) ([]store.TrafficRow, error)
	SnapshotList(zone string, limit int) ([]store.Snapshot, error)
	SnapshotByID(id int64) (store.Snapshot, bool, error)
	SnapshotPut(zone string, serial uint32, content string, keep int) (int64, error)
}

// Actor is who performs a mutating call, for the audit line.
type Actor struct {
	User string
	Peer string // client address, "?" when unknown
}

// Service is the operation layer. Construct with New; the zero value of the
// optional fields means "feature off".
type Service struct {
	cfg   func() *config.Config // live config (hot-reloaded)
	store Store

	// ConfPath locates goddns.conf (and so proxy.d/); empty ⇒ vhost editing off.
	ConfPath string
	// Reload, if set, is called after a successful vhost write so the change
	// applies now instead of on the next config poll.
	Reload func()
	// FileEd overrides the static-zone editor builder (tests inject stubs);
	// nil ⇒ FileEditor.
	FileEd func(*config.Config) *filezone.Editor
	// Logf is where audit lines go; nil ⇒ log.Printf.
	Logf func(format string, a ...any)
}

func New(cfg func() *config.Config, st Store) *Service {
	return &Service{cfg: cfg, store: st}
}

// InvalidError marks a request the caller got wrong (missing or malformed
// input, a snapshot/vhost that isn't there, a conflicting setting), as opposed
// to an operation that failed. Front-ends map it to "400"-class. Missing is
// set when a required field was absent.
type InvalidError struct {
	Msg     string
	Missing bool
}

func (e *InvalidError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &InvalidError{Msg: fmt.Sprintf(format, a...)} }

func missing(msg string) error { return &InvalidError{Msg: msg, Missing: true} }

// IsInvalid reports whether err is (or wraps) an InvalidError.
func IsInvalid(err error) bool {
	var ie *InvalidError
	return errors.As(err, &ie)
}

// IsMissing reports whether err is an InvalidError for an absent required field.
func IsMissing(err error) bool {
	var ie *InvalidError
	return errors.As(err, &ie) && ie.Missing
}

// Audit writes one admin-audit line. The format is relied on by operators'
// log searches, so it stays exactly what the admin UI always wrote, and it is
// defined only here: front-ends audit their own events (login) through it too.
func (s *Service) Audit(a Actor, format string, args ...any) {
	logf := s.Logf
	if logf == nil {
		logf = log.Printf
	}
	logf("admin-audit user=%s peer=%s "+format, append([]any{a.User, a.Peer}, args...)...)
}

// EditorKeys returns goddns's keyring (from tsig_keys_file) or the single key.
func EditorKeys(cfg *config.Config) []tsig.Key {
	if ks := cfg.TSIGKeys(); len(ks) > 0 {
		return ks
	}
	return []tsig.Key{{Name: strings.TrimSuffix(cfg.TSIGName, "."), Algo: cfg.TSIGAlgo, Secret: cfg.TSIGSecret}}
}

// RecordEditor builds the RFC2136 (dynamic-zone) editor from cfg, wired to
// snap for snapshot-before-write. The named.conf / DNS server defaults come
// from config.Load (and the editors' own fallbacks), not from here.
func RecordEditor(cfg *config.Config, snap recordmut.Snapshotter) *recordmut.Editor {
	return &recordmut.Editor{NamedConf: cfg.NamedConf, DNSServer: cfg.DNSServer, Keys: EditorKeys(cfg), Snap: snap, Keep: cfg.HistoryKeep}
}

// FileEditor builds the file-as-truth editor for enabled static zones.
func FileEditor(cfg *config.Config) *filezone.Editor {
	return &filezone.Editor{NamedConf: cfg.NamedConf, DNSServer: cfg.DNSServer, Editable: cfg.EditableZones, Keep: cfg.HistoryKeep}
}

// EditsInPlace is THE routing rule for a record edit: true when zone is an
// enabled static master (edited in its file), false for everything else,
// including a dynamic zone mistakenly listed in editable_zones (RFC2136).
// CanEdit re-reads the live dynamic flag, so routing can't disagree with what
// Zone reports. Every surface (service, CLI) routes through this.
func EditsInPlace(fed *filezone.Editor, zone string) bool {
	return fed.CanEdit(fed.Lookup(zone))
}

// ParseRR parses one record in zone-file syntax with the zone as $ORIGIN, so a
// relative owner ("www", "@") qualifies against the zone on every path.
func ParseRR(line, zone string) (dns.RR, error) {
	rr, err := filezone.ParseRR(line, zone)
	if err != nil {
		return nil, invalid("parse record %q: %v", line, err)
	}
	return rr, nil
}

func (s *Service) recordEditor(cfg *config.Config) *recordmut.Editor {
	return RecordEditor(cfg, s.store)
}

func (s *Service) fileEditor(cfg *config.Config) *filezone.Editor {
	if s.FileEd != nil {
		return s.FileEd(cfg)
	}
	return FileEditor(cfg)
}

func (s *Service) vhostEditor() *vhostmut.Editor { return &vhostmut.Editor{ConfPath: s.ConfPath} }
