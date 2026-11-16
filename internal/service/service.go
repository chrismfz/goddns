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

// Config returns the live config.
func (s *Service) Config() *config.Config { return s.cfg() }

// InvalidError marks a request the caller got wrong (missing/malformed input),
// as opposed to an operation that failed. Front-ends map it to "400".
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &InvalidError{Msg: fmt.Sprintf(format, a...)} }

// IsInvalid reports whether err is (or wraps) an InvalidError.
func IsInvalid(err error) bool {
	var ie *InvalidError
	return errors.As(err, &ie)
}

// audit writes one admin-audit line. The format is relied on by operators'
// log searches, so it stays exactly what the admin UI always wrote.
func (s *Service) audit(a Actor, format string, args ...any) {
	logf := s.Logf
	if logf == nil {
		logf = log.Printf
	}
	logf("admin-audit user=%s peer=%s "+format, append([]any{a.User, a.Peer}, args...)...)
}

func namedConf(cfg *config.Config) string {
	if cfg.NamedConf != "" {
		return cfg.NamedConf
	}
	return "/etc/named.conf"
}

func dnsServer(cfg *config.Config) string {
	if cfg.DNSServer != "" {
		return cfg.DNSServer
	}
	return "127.0.0.1:53"
}

// EditorKeys returns goddns's keyring (from tsig_keys_file) or the single key.
func EditorKeys(cfg *config.Config) []tsig.Key {
	if ks := cfg.TSIGKeys(); len(ks) > 0 {
		return ks
	}
	return []tsig.Key{{Name: strings.TrimSuffix(cfg.TSIGName, "."), Algo: cfg.TSIGAlgo, Secret: cfg.TSIGSecret}}
}

// RecordEditor builds the RFC2136 (dynamic-zone) editor from cfg, wired to
// snap for snapshot-before-write (nil ⇒ no snapshots).
func RecordEditor(cfg *config.Config, snap recordmut.Snapshotter) *recordmut.Editor {
	ed := &recordmut.Editor{NamedConf: namedConf(cfg), DNSServer: dnsServer(cfg), Keys: EditorKeys(cfg), Keep: cfg.HistoryKeep}
	if snap != nil {
		ed.Snap = snap
	}
	return ed
}

// FileEditor builds the file-as-truth editor for enabled static zones.
func FileEditor(cfg *config.Config) *filezone.Editor {
	return &filezone.Editor{NamedConf: namedConf(cfg), DNSServer: dnsServer(cfg), Editable: cfg.EditableZones, Keep: cfg.HistoryKeep}
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
