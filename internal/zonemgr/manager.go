package zonemgr

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/zonefile"
)

// RefusedError is a request zonemgr won't carry out as asked (a bad name,
// a zone that exists, a file in the way, the include not referenced, a zone
// it doesn't manage) — the caller's to fix, as opposed to an I/O failure.
type RefusedError struct{ Msg string }

func (e *RefusedError) Error() string { return e.Msg }

func refused(format string, a ...any) error { return &RefusedError{Msg: fmt.Sprintf(format, a...)} }

// IsRefused reports whether err is (or wraps) a RefusedError.
func IsRefused(err error) bool {
	var r *RefusedError
	return errors.As(err, &r)
}

// Manager creates and deletes managed zones. The zero value of each seam is
// the production behaviour; tests inject their own.
type Manager struct {
	NamedConf string // the root named.conf (to confirm the include is referenced)
	Include   string // the managed include file
	ZoneDir   string // where new zone files go
	LockDir   string // advisory lock lives here (default /var/lib/goddns/zonelocks)

	Inv        func() (*named.Inventory, error)        // default: named-checkconf -p + Parse
	CheckZone  func(zone string, content []byte) error // default: named-checkzone
	CheckConf  func() error                            // default: named-checkconf <NamedConf>
	Reconfig   func() error                            // default: rndc reconfig
	Verify     func(zone string) error                 // default: SOA query to DNSServer
	DNSServer  string                                  // for the default Verify (default 127.0.0.1:53)
	Hostmaster string                                  // default SOA contact when a request gives none (zone_hostmaster)
	Now        func() time.Time
}

// CreateRequest is a new zone. NS are the apex nameservers (at least one);
// Hostmaster defaults to hostmaster.<zone>.
type CreateRequest struct {
	Zone       string
	NS         []string
	Hostmaster string
	TTL        uint32 // default 3600
}

// Plan is what a create or delete does (or did).
type Plan struct {
	Zone    string
	File    string // zone file
	Stanza  string // the include stanza added or removed
	Content string // the new zone file (create)
	Parent  string // the zone served here that contains this one ("" if none)
	MovedTo string // where a deleted zone's file was moved (delete, applied)
}

// zoneNameRe: lowercase labels of letters, digits, '-' and '_' (for
// _acme-challenge style names), at least two labels, nothing that could
// escape the zone directory or the quoted stanza.
// hostRe is a host name for NS / hostmaster: the same strict labels (no
// spaces, quotes, ';' or newlines — they would be zone-file text).
var hostRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$`)

var zoneNameRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$`)

// NormName lowercases and strips a trailing dot.
func NormName(z string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".") }

func (m *Manager) inventory() (*named.Inventory, error) {
	if m.Inv != nil {
		return m.Inv()
	}
	nc := m.NamedConf
	if nc == "" {
		nc = "/etc/named.conf"
	}
	data, err := named.CheckConf(nc)
	if err != nil {
		return nil, err
	}
	return named.Parse(data), nil
}

func (m *Manager) checkZone(zone string, content []byte) error {
	if m.CheckZone != nil {
		return m.CheckZone(zone, content)
	}
	return zonefile.CheckZone(zone, content)
}

func (m *Manager) checkConf() error {
	if m.CheckConf != nil {
		return m.CheckConf()
	}
	_, err := named.CheckConf(m.NamedConf)
	return err
}

func (m *Manager) reconfig() error {
	if m.Reconfig != nil {
		return m.Reconfig()
	}
	bin, err := exec.LookPath("rndc")
	if err != nil {
		return fmt.Errorf("rndc not found: %w", err)
	}
	if out, err := exec.Command(bin, "reconfig").CombinedOutput(); err != nil {
		return fmt.Errorf("rndc reconfig: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) lock() (func(), error) {
	dir := m.LockDir
	if dir == "" {
		dir = "/var/lib/goddns/zonelocks"
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "managed-include.lock"), os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func (m *Manager) ready() error {
	if m.Include == "" || m.ZoneDir == "" {
		return refused("managed_include and managed_zone_dir must be set to create or delete zones")
	}
	ok, err := IncludeReferenced(m.NamedConf, m.Include)
	if err != nil {
		return fmt.Errorf("read %s: %w", m.NamedConf, err)
	}
	if !ok {
		return refused("%s doesn't include the managed include yet — run `goddns zone init`, then add this line once:\n    include %q;", m.NamedConf, m.Include)
	}
	return nil
}

// parentOf is the most specific zone served here that strictly contains z.
func parentOf(inv *named.Inventory, z string) string {
	best := ""
	for _, uz := range inv.UserZones() {
		n := NormName(uz.Name)
		if n != z && dns.IsSubDomain(dns.Fqdn(n), dns.Fqdn(z)) && len(n) > len(best) {
			best = n
		}
	}
	return best
}

// render is a minimal valid zone: a one-line SOA (so goddns's surgical
// editor can edit it later) and the apex NS set.
func render(req CreateRequest, z string, serial uint32, day time.Time) (string, error) {
	if len(req.NS) == 0 {
		return "", refused("at least one nameserver is required")
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = 3600
	}
	hm := strings.TrimSpace(req.Hostmaster)
	if hm == "" {
		hm = "hostmaster." + z
	}
	hm = strings.ToLower(strings.ReplaceAll(strings.TrimSuffix(hm, "."), "@", "."))
	if !hostRe.MatchString(hm) {
		return "", refused("hostmaster %q is not a valid name", req.Hostmaster)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "; %s — created by goddns %s. Edit freely (vi/nano or goddns); keep the SOA on one line.\n",
		z, day.Format("2006-01-02"))
	fmt.Fprintf(&b, "$TTL %d\n", ttl)
	ns0 := ""
	var nsLines []string
	for _, ns := range req.NS {
		ns = NormName(ns)
		if !hostRe.MatchString(ns) {
			return "", refused("nameserver %q is not a valid host name", ns)
		}
		if ns0 == "" {
			ns0 = ns
		}
		nsLines = append(nsLines, fmt.Sprintf("@\tIN\tNS\t%s.\n", ns))
	}
	fmt.Fprintf(&b, "@\tIN\tSOA\t%s. %s. %d 3600 900 1209600 300\n", ns0, hm, serial)
	for _, l := range nsLines {
		b.WriteString(l)
	}
	return b.String(), nil
}

func (m *Manager) zoneFile(z string) string { return filepath.Join(m.ZoneDir, z+".hosts") }

func stanzaFor(z, file string) string {
	return fmt.Sprintf("zone %q { type master; file %q; };", z, file)
}

// PlanCreate validates a new zone and returns what Create would write.
func (m *Manager) PlanCreate(req CreateRequest) (*Plan, error) {
	z := NormName(req.Zone)
	if !zoneNameRe.MatchString(z) || len(z) > 253 {
		return nil, refused("%q is not a valid zone name", req.Zone)
	}
	if err := m.ready(); err != nil {
		return nil, err
	}
	inv, err := m.inventory()
	if err != nil {
		return nil, err
	}
	for _, uz := range inv.Zones { // every view, built-ins included
		if uz.View != "" {
			// BIND forbids top-level zones once views are used, so a managed
			// stanza would fail named-checkconf every time
			return nil, refused("this BIND config uses views; goddns can't create zones in it (managed zones are top-level)")
		}
	}
	for _, uz := range inv.Zones {
		if NormName(uz.Name) == z {
			return nil, refused("zone %s already exists in the BIND configuration", z)
		}
	}
	file := m.zoneFile(z)
	if _, err := os.Lstat(file); err == nil {
		return nil, refused("%s already exists — refusing to overwrite it (move it aside or reuse it by hand)", file)
	}
	// YYYYMMDD01, the usual date-based serial (the "01" is literal: in a Go
	// layout "01" would be the month again)
	day := m.now().UTC()
	serial := uint32(day.Year()*1000000+int(day.Month())*10000+day.Day()*100) + 1
	if strings.TrimSpace(req.Hostmaster) == "" {
		req.Hostmaster = m.Hostmaster
	}
	content, err := render(req, z, serial, day)
	if err != nil {
		return nil, err
	}
	if err := m.checkZone(z, []byte(content)); err != nil {
		return nil, err
	}
	return &Plan{Zone: z, File: file, Stanza: stanzaFor(z, file), Content: content, Parent: parentOf(inv, z)}, nil
}

// Create writes the zone file and its stanza, checks the whole config and
// reconfigures BIND. Any failure before BIND is told puts everything back.
func (m *Manager) Create(req CreateRequest) (*Plan, error) {
	unlock, err := m.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	p, err := m.PlanCreate(req)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(m.ZoneDir, 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p.File, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(p.Content); err != nil {
		f.Close()
		os.Remove(p.File)
		return nil, err
	}
	f.Close()
	matchGroup(p.File, m.ZoneDir) // named reads it through the directory's group

	old, existed, err := readMaybe(m.Include)
	if err != nil {
		os.Remove(p.File)
		return nil, err
	}
	next := old
	if !existed {
		next = includeHeader
	}
	if next != "" && !strings.HasSuffix(next, "\n") {
		next += "\n"
	}
	next += p.Stanza + "\n"
	restore := func() {
		if existed {
			_ = atomicWrite(m.Include, old)
		} else {
			_ = os.Remove(m.Include)
		}
		_ = os.Remove(p.File)
	}
	if err := atomicWrite(m.Include, next); err != nil {
		restore()
		return nil, err
	}
	if err := m.checkConf(); err != nil {
		restore()
		return nil, fmt.Errorf("named-checkconf rejected the change (rolled back): %w", err)
	}
	if err := m.reconfig(); err != nil {
		restore()
		_ = m.reconfig() // best effort: BIND back on the restored config
		return nil, fmt.Errorf("rolled back: %w", err)
	}
	// named-checkconf doesn't load zone data: confirm named now SERVES the
	// zone (a file it can't read — permissions, SELinux — passes every check
	// and only shows up as SERVFAIL).
	if err := m.verify(p.Zone); err != nil {
		restore()
		_ = m.reconfig()
		return nil, fmt.Errorf("named did not load %s after reconfig (rolled back): %v — check named's log; the zone file (%s) must be readable by named (permissions, SELinux label)", p.Zone, err, p.File)
	}
	return p, nil
}

func (m *Manager) verify(zone string) error {
	if m.Verify != nil {
		return m.Verify(zone)
	}
	srv := m.DNSServer
	if srv == "" {
		srv = "127.0.0.1:53"
	}
	var last error
	for i := 0; i < 6; i++ { // reconfig loads zones asynchronously
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
		c := &dns.Client{Timeout: 2 * time.Second}
		resp, _, err := c.Exchange(m, srv)
		switch {
		case err != nil:
			last = err
		case resp.Rcode == dns.RcodeSuccess && resp.Authoritative:
			for _, rr := range resp.Answer {
				if _, ok := rr.(*dns.SOA); ok {
					return nil
				}
			}
			last = errors.New("no SOA in the answer")
		default:
			last = fmt.Errorf("answered %s (authoritative=%v)", dns.RcodeToString[resp.Rcode], resp.Authoritative)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return last
}

// PlanDelete finds a managed zone and returns what Delete would remove. A
// zone defined anywhere but the managed include is refused: it is the
// operator's or a panel's.
func (m *Manager) PlanDelete(zone string) (*Plan, error) {
	z := NormName(zone)
	if err := m.ready(); err != nil {
		return nil, err
	}
	src, _, err := readMaybe(m.Include)
	if err != nil {
		return nil, err
	}
	st, err := ParseInclude(src)
	if err != nil {
		return nil, err
	}
	for _, s := range st {
		if s.Name == z {
			file := s.File
			if file != "" && !filepath.IsAbs(file) {
				if inv, err := m.inventory(); err == nil && inv.Directory != "" {
					file = filepath.Join(inv.Directory, file)
				}
			}
			return &Plan{Zone: z, File: file, Stanza: strings.TrimSpace(src[s.Start:s.End])}, nil
		}
	}
	if inv, err := m.inventory(); err == nil && inv.ZoneByName(z) != nil {
		return nil, refused("zone %s is not in %s (it is defined elsewhere in the BIND config) — goddns only deletes zones it manages; remove it by hand", z, m.Include)
	}
	return nil, refused("no zone %s in %s", z, m.Include)
}

// Delete removes the zone's stanza, checks the config, reconfigures BIND and
// only then moves the zone file aside (<file>.deleted-<UTC time>).
func (m *Manager) Delete(zone string) (*Plan, error) {
	unlock, err := m.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	p, err := m.PlanDelete(zone)
	if err != nil {
		return nil, err
	}
	old, _, err := readMaybe(m.Include)
	if err != nil {
		return nil, err
	}
	st, err := ParseInclude(old)
	if err != nil {
		return nil, err
	}
	next := old
	for _, s := range st {
		if s.Name == p.Zone {
			end := s.End
			if end < len(old) && old[end] == '\n' {
				end++
			}
			next = old[:s.Start] + old[end:]
			break
		}
	}
	if err := atomicWrite(m.Include, next); err != nil {
		return nil, err
	}
	if err := m.checkConf(); err != nil {
		_ = atomicWrite(m.Include, old)
		return nil, fmt.Errorf("named-checkconf rejected the change (rolled back): %w", err)
	}
	if err := m.reconfig(); err != nil {
		_ = atomicWrite(m.Include, old)
		_ = m.reconfig()
		return nil, fmt.Errorf("rolled back: %w", err)
	}
	if p.File != "" && !m.inZoneDir(p.File) {
		// a hand-edited stanza can name any path: goddns moves aside only
		// files in its own zone directory
		p.MovedTo = ""
		p.File += " (left in place: outside managed_zone_dir)"
	} else if p.File != "" {
		if _, err := os.Lstat(p.File); err == nil {
			to := p.File + ".deleted-" + m.now().UTC().Format("20060102-150405")
			if err := os.Rename(p.File, to); err == nil {
				p.MovedTo = to
			}
		}
	}
	return p, nil
}

// inZoneDir reports whether path resolves to a file directly inside
// ZoneDir (symlinks resolved on the directory side).
func (m *Manager) inZoneDir(path string) bool {
	dir, err := filepath.EvalSymlinks(m.ZoneDir)
	if err != nil {
		dir = filepath.Clean(m.ZoneDir)
	}
	pdir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return false
	}
	return pdir == dir && filepath.Base(path) != "." && filepath.Base(path) != ".."
}

func readMaybe(path string) (string, bool, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(b), true, nil
}

// atomicWrite replaces path with data (temp + fsync + rename), keeping the
// existing file's mode and group, or 0640 with the directory's group.
func atomicWrite(path, data string) error {
	mode := os.FileMode(0o640)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(tmp.Name(), int(st.Uid), int(st.Gid))
		}
	} else {
		matchGroup(tmp.Name(), filepath.Dir(path))
	}
	return os.Rename(tmp.Name(), path)
}

// matchGroup gives path the group of dir (best effort; needs root): named
// reads zone files and the include through that group.
func matchGroup(path, dir string) {
	if fi, err := os.Stat(dir); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(path, -1, int(st.Gid))
		}
	}
}

const includeHeader = "// goddns-managed zones — a plain named.conf fragment. goddns adds and removes\n" +
	"// stanzas here; you may edit it by hand too (named-checkconf before reloading).\n"

// Init creates the managed include, empty, if it doesn't exist yet: BIND
// refuses an `include` of a missing file (named-checkconf, a reload or a
// restart all fail), so it must exist BEFORE named.conf references it.
// Returns whether it created the file.
func (m *Manager) Init() (bool, error) {
	if m.Include == "" {
		return false, refused("managed_include is not set")
	}
	if _, err := os.Lstat(m.Include); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(m.Include), 0o750); err != nil {
		return false, err
	}
	return true, atomicWrite(m.Include, includeHeader)
}

// ForConfig builds the production Manager from goddns's config.
func ForConfig(cfg *config.Config) *Manager {
	return &Manager{NamedConf: cfg.NamedConf, Include: cfg.ManagedInclude, ZoneDir: cfg.ManagedZoneDir,
		DNSServer: cfg.DNSServer, Hostmaster: cfg.ZoneHostmaster}
}

// EditableZones is the static-zone edit allowlist: the operator's
// editable_zones plus every zone in the managed include (goddns created
// them for editing). An unreadable include adds nothing — never a reason to
// widen the list.
func EditableZones(configured []string, include string) []string {
	out := append([]string(nil), configured...)
	if z, err := ManagedZones(include); err == nil {
		out = append(out, z...)
	}
	return out
}
