// Package filezone is the Phase-4 Stage-1 apply path for "file-as-truth" static
// zone editing. It edits a static master zone's file in place via the Stage-0
// surgical engine (internal/zonefile), under an advisory lock with a
// byte-compare so it coexists with hand-editing, validated by named-checkzone,
// backed up before the write, written atomically, reloaded per-zone, and
// verified — the pipeline the design (docs/PHASE4.md §2) calls for.
//
// It refuses anything outside its remit: a zone not in named.conf, a dynamic
// zone (that's RFC2136 / recordmut), a slave, a zone not on the operator's
// editable allowlist, a symlinked file, or a file that looks panel-managed.
package filezone

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/zonefile"
)

// Editor edits enabled static master zones in place.
type Editor struct {
	NamedConf string   // path to named.conf (default /etc/named.conf)
	DNSServer string   // for the post-reload verify (default 127.0.0.1:53)
	Editable  []string // the operator's allowlist of editable static zones
	LockDir   string   // advisory zone locks live here (default /var/lib/goddns/zonelocks)
	BackupDir string   // raw pre-edit file backups (default /var/lib/goddns/zonebackups)
	Keep      int      // backups retained per zone (default 50)

	// Injectable for testing; nil ⇒ the production defaults below.
	Inv         func() (*named.Inventory, error)        // default: named.CheckConf + Parse
	CheckZone   func(zone string, content []byte) error // default: zonefile.CheckZone (named-checkzone)
	Reload      func(zone string) error                 // default: rndc reload <zone>
	Verify      func(zone string, wantSerial uint32) error
	beforeWrite func() // test hook: runs after checkzone, before the nano-guard re-read
}

// Result describes a (previewed or applied) edit.
type Result struct {
	Zone, File string
	Backup     string   // path of the pre-edit backup (empty on preview)
	Serial     uint32   // the new SOA serial
	Added      []string // records added (zone-file form)
	Removed    []string // records removed
}

func (e *Editor) namedConf() string {
	if e.NamedConf != "" {
		return e.NamedConf
	}
	return "/etc/named.conf"
}

func (e *Editor) server() string {
	if e.DNSServer != "" {
		return e.DNSServer
	}
	return "127.0.0.1:53"
}

func (e *Editor) keep() int {
	if e.Keep > 0 {
		return e.Keep
	}
	return 50
}

// Editable reports whether the zone is on the operator's allowlist.
func (e *Editor) editable(zone string) bool {
	z := norm(zone)
	for _, x := range e.Editable {
		if norm(x) == z {
			return true
		}
	}
	return false
}

func norm(z string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".") }

// CanEdit reports whether goddns may file-edit this zone (static master, on the
// allowlist) — for showing edit controls. It does not read the file.
func (e *Editor) CanEdit(z *named.Zone) bool {
	return z != nil && (z.Type == "master" || z.Type == "primary") && !z.Dynamic && e.editable(z.Name)
}

// inventory returns the parsed named.conf inventory (injectable for tests).
func (e *Editor) inventory() (*named.Inventory, error) {
	if e.Inv != nil {
		return e.Inv()
	}
	data, err := named.CheckConf(e.namedConf())
	if err != nil {
		return nil, fmt.Errorf("read named.conf: %w", err)
	}
	return named.Parse(data), nil
}

// resolve validates the zone is one goddns may file-edit and returns it.
func (e *Editor) resolve(zone string) (*named.Zone, error) {
	inv, err := e.inventory()
	if err != nil {
		return nil, err
	}
	z := inv.ZoneByName(zone)
	if z == nil {
		return nil, fmt.Errorf("zone %q is not in named.conf", zone)
	}
	if z.Type != "master" && z.Type != "primary" {
		return nil, fmt.Errorf("zone %q is a %s — goddns only file-edits static master zones", zone, z.Kind())
	}
	if z.Dynamic {
		return nil, fmt.Errorf("zone %q is dynamic — edit it with `goddns record` (RFC2136), not file editing", zone)
	}
	if !e.editable(zone) {
		return nil, fmt.Errorf("zone %q is not enabled for editing — run `goddns zone enable %s` and add it to editable_zones", zone, zone)
	}
	if z.Path == "" {
		return nil, fmt.Errorf("zone %q has no resolvable file path in named.conf", zone)
	}
	// Refuse a symlinked zone file (defeats a path pivot).
	if fi, err := os.Lstat(z.Path); err != nil {
		return nil, fmt.Errorf("stat %s: %w", z.Path, err)
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("zone file %s is a symlink — refusing to edit", z.Path)
	}
	if p := panelPath(z.Path); p != "" {
		return nil, fmt.Errorf("zone file %s is under a panel tree (%s) — goddns won't edit a panel's zone", z.Path, p)
	}
	return z, nil
}

// PreflightEnable validates that a static zone is safe to add to editable_zones
// (static master, not dynamic, file present and not a symlink, not
// panel-managed, and parseable). It does NOT check the allowlist — the caller is
// about to add the zone to it. Returns the zone file path. Run by the root CLI.
func PreflightEnable(namedConf, zone string) (string, error) {
	// Reuse resolve by pretending the zone is already enabled (resolve's only
	// allowlist use is the membership gate, which doesn't apply pre-enable).
	e := &Editor{NamedConf: namedConf, Editable: []string{zone}}
	z, err := e.resolve(zone)
	if err != nil {
		return "", err
	}
	orig, err := readNoFollow(z.Path)
	if err != nil {
		return "", err
	}
	if m := panelMarker(orig); m != "" {
		return "", fmt.Errorf("%s looks panel-managed (%s)", z.Path, m)
	}
	if _, err := zonefile.Parse(orig, zone); err != nil {
		return "", fmt.Errorf("zone file doesn't parse: %w", err)
	}
	return z.Path, nil
}

// Preview validates and computes the diff without writing.
func (e *Editor) Preview(zone string, ops []ddns.Op) (*Result, error) {
	z, err := e.resolve(zone)
	if err != nil {
		return nil, err
	}
	orig, err := readNoFollow(z.Path)
	if err != nil {
		return nil, err
	}
	if m := panelMarker(orig); m != "" {
		return nil, fmt.Errorf("%s looks panel-managed (%s) — goddns won't edit a panel's zone", z.Path, m)
	}
	newBytes, err := e.compute(zone, orig, ops)
	if err != nil {
		return nil, err
	}
	res := diff(zone, z.Path, orig, newBytes)
	return res, nil
}

// Apply runs the full locked pipeline and writes the change.
func (e *Editor) Apply(zone string, ops []ddns.Op) (*Result, error) {
	z, err := e.resolve(zone)
	if err != nil {
		return nil, err
	}

	unlock, err := e.lock(zone)
	if err != nil {
		return nil, err
	}
	defer unlock()

	orig, err := readNoFollow(z.Path)
	if err != nil {
		return nil, err
	}
	if m := panelMarker(orig); m != "" {
		return nil, fmt.Errorf("%s looks panel-managed (%s) — goddns won't edit a panel's zone", z.Path, m)
	}

	newBytes, err := e.compute(zone, orig, ops)
	if err != nil {
		return nil, err
	}
	return e.commit(z, zone, orig, newBytes)
}

// ReadRaw returns the zone's current file bytes (the export source / raw-edit
// base). Validates the zone is editable, but takes no lock.
func (e *Editor) ReadRaw(zone string) ([]byte, error) {
	z, err := e.resolve(zone)
	if err != nil {
		return nil, err
	}
	return readNoFollow(z.Path)
}

// ReplaceRaw replaces the whole zone file with newBytes (raw / webmin-style
// mode). base is the content the caller last read — the concurrent-edit guard
// refuses if the file moved since (pass nil only for an intentional overwrite).
// CLI-only: the daemon never calls this, because a whole-file replace can
// rewrite an entire zone past checkzone (design S2).
func (e *Editor) ReplaceRaw(zone string, newBytes, base []byte) (*Result, error) {
	z, err := e.resolve(zone)
	if err != nil {
		return nil, err
	}
	unlock, err := e.lock(zone)
	if err != nil {
		return nil, err
	}
	defer unlock()

	cur, err := readNoFollow(z.Path)
	if err != nil {
		return nil, err
	}
	if m := panelMarker(cur); m != "" {
		return nil, fmt.Errorf("%s looks panel-managed (%s) — goddns won't edit a panel's zone", z.Path, m)
	}
	if base != nil && !bytes.Equal(cur, base) {
		return nil, fmt.Errorf("zone %q changed under you (a concurrent edit) — reload and reapply", zone)
	}
	normalized, err := normalizeRawSerial(zone, cur, newBytes)
	if err != nil {
		return nil, err
	}
	return e.commit(z, zone, cur, normalized)
}

// PreviewRaw checkzones a proposed whole-file replacement and returns the
// record-level diff plus the current bytes (the base to pass to ReplaceRaw).
// Writes nothing. The serial is normalized to stay monotonic vs the live zone.
func (e *Editor) PreviewRaw(zone string, newBytes []byte) (*Result, []byte, error) {
	z, err := e.resolve(zone)
	if err != nil {
		return nil, nil, err
	}
	cur, err := readNoFollow(z.Path)
	if err != nil {
		return nil, nil, err
	}
	if m := panelMarker(cur); m != "" {
		return nil, nil, fmt.Errorf("%s looks panel-managed (%s) — goddns won't edit a panel's zone", z.Path, m)
	}
	newBytes, err = normalizeRawSerial(zone, cur, newBytes)
	if err != nil {
		return nil, nil, err
	}
	check := e.CheckZone
	if check == nil {
		check = zonefile.CheckZone
	}
	if err := check(zone, newBytes); err != nil {
		return nil, nil, fmt.Errorf("checkzone: %w", err)
	}
	return diff(zone, z.Path, cur, newBytes), cur, nil
}

// normalizeRawSerial keeps a raw replacement's SOA serial monotonic vs the live
// zone. Surgically-locatable content is rewritten above the current serial. When
// goddns can't auto-bump (e.g. $GENERATE), it REFUSES if the operator's serial
// doesn't already exceed the current one — never silently regressing secondaries.
func normalizeRawSerial(zone string, cur, newBytes []byte) ([]byte, error) {
	floor, _ := currentSerial(cur, zone) // 0 if the current file can't be read
	if f, err := zonefile.Parse(newBytes, zone); err == nil && f.Surgical() {
		if b, err := f.SerialFloor(floor); err == nil {
			return b, nil
		}
	}
	newSerial, ok := currentSerial(newBytes, zone)
	if !ok || newSerial <= floor {
		return nil, fmt.Errorf("raw content goddns can't auto-bump (e.g. $GENERATE) has SOA serial %d, not above the current %d — set a higher serial in the file", newSerial, floor)
	}
	return newBytes, nil
}

// currentSerial reads a zone's SOA serial, tolerant of non-surgical content
// (implied owners, $GENERATE with a normal SOA at the top): it returns the first
// SOA found even if a later directive stops the parse.
func currentSerial(content []byte, zone string) (uint32, bool) {
	zp := dns.NewZoneParser(bytes.NewReader(content), dns.Fqdn(zone), "")
	zp.SetIncludeAllowed(false)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial, true
		}
	}
	return 0, false
}

// commit is the shared write tail: checkzone the new bytes (HARD GATE), re-read
// under the lock and refuse if the file moved since `expected` (nano guard),
// back up the previous bytes, write atomically, reload (restoring on failure),
// and verify. The caller holds the lock and supplies `expected` = the bytes it
// based newBytes on.
func (e *Editor) commit(z *named.Zone, zone string, expected, newBytes []byte) (*Result, error) {
	check := e.CheckZone
	if check == nil {
		check = zonefile.CheckZone
	}
	if err := check(zone, newBytes); err != nil {
		return nil, fmt.Errorf("checkzone: %w", err)
	}

	if e.beforeWrite != nil {
		e.beforeWrite()
	}
	cur, err := readNoFollow(z.Path)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cur, expected) {
		return nil, fmt.Errorf("zone %q changed under you (a concurrent edit) — reload and reapply", zone)
	}

	backup, err := e.backup(zone, expected)
	if err != nil {
		return nil, fmt.Errorf("refusing to write without a backup: %w", err)
	}

	if err := writePreserving(z.Path, newBytes); err != nil {
		return nil, fmt.Errorf("write %s: %w", z.Path, err)
	}

	res := diff(zone, z.Path, expected, newBytes)
	res.Backup = backup

	reload := e.Reload
	if reload == nil {
		reload = rndcReload
	}
	if err := reload(zone); err != nil {
		if rerr := writePreserving(z.Path, expected); rerr != nil {
			return res, fmt.Errorf("reload failed (%w) AND restoring the previous file failed (%v) — recover manually from backup %s", err, rerr, backup)
		}
		return res, fmt.Errorf("reload failed (%w) — restored the previous zone file (backup at %s)", err, backup)
	}

	if e.Verify != nil {
		if err := e.Verify(zone, res.Serial); err != nil {
			return res, fmt.Errorf("zone written & reloaded, but verify failed: %w", err)
		}
	} else if err := verifySerial(e.server(), zone, res.Serial); err != nil {
		return res, fmt.Errorf("zone written & reloaded, but verify failed: %w", err)
	}
	return res, nil
}

// compute runs the Stage-0 surgical edit and returns the new bytes (UnsafeError
// ⇒ the caller should use raw mode).
func (e *Editor) compute(zone string, orig []byte, ops []ddns.Op) ([]byte, error) {
	f, err := zonefile.Parse(orig, zone)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", zone, err)
	}
	newBytes, err := f.Edit(ops)
	if err != nil {
		return nil, err // includes *zonefile.UnsafeError
	}
	return newBytes, nil
}

func (e *Editor) lockDir() string {
	if e.LockDir != "" {
		return e.LockDir
	}
	return "/var/lib/goddns/zonelocks"
}

// lock takes an advisory flock on a per-zone lockfile (decoupled from the zone
// file's inode, so the atomic rename can't drop the lock). Held across the
// read-modify-write.
func (e *Editor) lock(zone string) (func(), error) {
	if err := os.MkdirAll(e.lockDir(), 0o750); err != nil {
		return nil, err
	}
	lp := filepath.Join(e.lockDir(), norm(zone)+".lock")
	fd, err := os.OpenFile(lp, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_EX); err != nil {
		fd.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(fd.Fd()), syscall.LOCK_UN)
		fd.Close()
	}, nil
}

func (e *Editor) backupDir() string {
	if e.BackupDir != "" {
		return e.BackupDir
	}
	return "/var/lib/goddns/zonebackups"
}

// backup writes the raw pre-edit bytes and prunes to Keep most recent.
func (e *Editor) backup(zone string, content []byte) (string, error) {
	dir := filepath.Join(e.backupDir(), norm(zone))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("%d.zone", time.Now().UnixNano()))
	if err := os.WriteFile(path, content, 0o640); err != nil {
		return "", err
	}
	pruneBackups(dir, e.keep())
	return path, nil
}

func pruneBackups(dir string, keep int) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, en := range ents {
		if strings.HasSuffix(en.Name(), ".zone") {
			names = append(names, en.Name())
		}
	}
	sort.Strings(names) // unixnano prefix ⇒ chronological
	for i := 0; i < len(names)-keep; i++ {
		_ = os.Remove(filepath.Join(dir, names[i]))
	}
}

// readNoFollow reads a file, refusing to follow a final-component symlink.
func readNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// writePreserving writes content to path atomically (temp + rename + fsync),
// preserving the original file's mode and owner so named keeps reading it. It
// re-checks the target is not a symlink (Lstat) inside the locked window, and
// fails closed if it can't preserve a different owner (so a non-root run never
// silently re-homes a named-owned zone to the CLI user).
func writePreserving(path string, content []byte) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s became a symlink — refusing to write", path)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".goddns-zone-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if err := tmp.Chown(int(st.Uid), int(st.Gid)); err != nil && int(st.Uid) != os.Geteuid() {
			tmp.Close()
			return fmt.Errorf("can't preserve the zone file's owner (uid %d) — run as root: %w", st.Uid, err)
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

var panelNames = []string{"cpanel", "directadmin", "virtualmin", "plesk", "ispconfig"}

// panelMarker returns a recognizable control-panel signature found anywhere in
// the zone file (best-effort), or "" — goddns refuses to edit a panel's zone.
// The operator's allowlist is the PRIMARY guard; this is the secondary,
// fail-on-detection one (panel zones often carry no marker, so a clean result
// is not proof a zone is unmanaged).
func panelMarker(content []byte) string {
	low := strings.ToLower(string(content))
	for _, m := range panelNames {
		if strings.Contains(low, m) {
			return m
		}
	}
	return ""
}

// panelPath returns a panel signature in the zone file's PATH (a file under a
// known panel control tree), or "". Best-effort: cPanel/DirectAdmin keep zones
// in the shared /var/named, so this only catches panels with distinct trees.
func panelPath(path string) string {
	low := strings.ToLower(path)
	for _, p := range []string{"/var/cpanel/", "/usr/local/directadmin/", "/usr/local/psa/", "/etc/virtualmin", "/var/lib/virtualmin"} {
		if strings.Contains(low, p) {
			return p
		}
	}
	return ""
}

// diff builds the record-level added/removed (formatting/serial noise dropped)
// plus the new serial.
func diff(zone, file string, orig, newBytes []byte) *Result {
	res := &Result{Zone: norm(zone), File: file}
	if f, err := zonefile.Parse(newBytes, zone); err == nil {
		res.Serial = f.SOASerial()
	}
	oldSet := canonSet(parseRecords(orig, zone))
	newSet := canonSet(parseRecords(newBytes, zone))
	for k := range newSet {
		if _, ok := oldSet[k]; !ok {
			res.Added = append(res.Added, k)
		}
	}
	for k := range oldSet {
		if _, ok := newSet[k]; !ok {
			res.Removed = append(res.Removed, k)
		}
	}
	sort.Strings(res.Added)
	sort.Strings(res.Removed)
	return res
}

func parseRecords(data []byte, origin string) []dns.RR {
	zp := dns.NewZoneParser(bytes.NewReader(data), dns.Fqdn(origin), "")
	zp.SetIncludeAllowed(false)
	var out []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		out = append(out, rr)
	}
	return out
}

// canonSet maps each record's zone-file form, dropping the SOA (its serial
// always changes and would be diff noise) — classified by type, not by string.
func canonSet(rrs []dns.RR) map[string]bool {
	m := make(map[string]bool, len(rrs))
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeSOA {
			continue
		}
		m[rr.String()] = true
	}
	return m
}

var errRndcMissing = errors.New("rndc not found in PATH")
