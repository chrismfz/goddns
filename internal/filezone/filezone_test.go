package filezone

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/zonefile"
)

const zoneText = `$ORIGIN example.
$TTL 3600
; the apex
@	IN	SOA	ns.example. host.example. 2024010101 3600 600 1209600 60
@	IN	NS	ns.example.
www	IN	A	1.2.3.4		; the web
mail	IN	A	5.6.7.8
`

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil || rr == nil {
		t.Fatalf("NewRR %q: %v", s, err)
	}
	return rr
}

// testEditor writes the zone to a temp file and returns an Editor wired to it
// with stubbed reload/verify/checkzone (no live BIND needed).
func testEditor(t *testing.T, z named.Zone, editable ...string) (*Editor, string) {
	t.Helper()
	dir := t.TempDir()
	zonePath := filepath.Join(dir, "zone.db")
	if err := os.WriteFile(zonePath, []byte(zoneText), 0o640); err != nil {
		t.Fatal(err)
	}
	z.Path = zonePath
	inv := &named.Inventory{Zones: []named.Zone{z}}
	e := &Editor{
		Editable:  editable,
		LockDir:   filepath.Join(dir, "locks"),
		BackupDir: filepath.Join(dir, "backups"),
		Inv:       func() (*named.Inventory, error) { return inv, nil },
		CheckZone: func(string, []byte) error { return nil },
		Reload:    func(string) error { return nil },
		Verify:    func(string, uint32) error { return nil },
	}
	return e, zonePath
}

func staticZone() named.Zone {
	return named.Zone{Name: "example", Type: "master", Dynamic: false}
}

func TestApplyAddPreservesAndBumps(t *testing.T) {
	e, path := testEditor(t, staticZone(), "example")
	res, err := e.Apply("example", []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "new.example. 60 IN A 9.9.9.9")}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	out, _ := os.ReadFile(path)
	s := string(out)
	if !strings.Contains(s, "new.example.") || !strings.Contains(s, "9.9.9.9") {
		t.Fatalf("record not added:\n%s", s)
	}
	// hand formatting preserved
	if !strings.Contains(s, "www\tIN\tA\t1.2.3.4\t\t; the web") || !strings.Contains(s, "; the apex") {
		t.Fatalf("formatting/comments not preserved:\n%s", s)
	}
	// serial bumped
	if res.Serial <= 2024010101 {
		t.Fatalf("serial not bumped: %d", res.Serial)
	}
	if !strings.Contains(s, u32(res.Serial)) {
		t.Fatalf("new serial %d not in file", res.Serial)
	}
	// a backup of the pre-edit bytes exists and matches the original
	if res.Backup == "" {
		t.Fatal("no backup recorded")
	}
	if b, _ := os.ReadFile(res.Backup); string(b) != zoneText {
		t.Fatalf("backup isn't the pre-edit bytes:\n%s", b)
	}
	if len(res.Added) != 1 {
		t.Fatalf("diff Added = %v", res.Added)
	}
}

func TestRefuseDynamic(t *testing.T) {
	z := staticZone()
	z.Dynamic = true
	e, _ := testEditor(t, z, "example")
	if _, err := e.Apply("example", nil); err == nil || !strings.Contains(err.Error(), "dynamic") {
		t.Fatalf("a dynamic zone must be refused, got %v", err)
	}
}

func TestRefuseNotEnabled(t *testing.T) {
	e, _ := testEditor(t, staticZone()) // not in editable list
	if _, err := e.Apply("example", nil); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("a zone not on the allowlist must be refused, got %v", err)
	}
}

func TestRefuseSlave(t *testing.T) {
	z := staticZone()
	z.Type = "slave"
	e, _ := testEditor(t, z, "example")
	if _, err := e.Apply("example", nil); err == nil || !strings.Contains(err.Error(), "only file-edits static master") {
		t.Fatalf("a slave zone must be refused, got %v", err)
	}
}

func TestRefuseSymlink(t *testing.T) {
	e, path := testEditor(t, staticZone(), "example")
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	// point the inventory at the symlink
	e.Inv = func() (*named.Inventory, error) {
		return &named.Inventory{Zones: []named.Zone{{Name: "example", Type: "master", Path: link}}}, nil
	}
	if _, err := e.Apply("example", nil); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked zone file must be refused, got %v", err)
	}
}

func TestRefusePanelMarker(t *testing.T) {
	e, path := testEditor(t, staticZone(), "example")
	os.WriteFile(path, []byte("; cPanel generated zone\n"+zoneText), 0o640)
	if _, err := e.Apply("example", nil); err == nil || !strings.Contains(err.Error(), "panel-managed") {
		t.Fatalf("a panel-marked zone must be refused, got %v", err)
	}
}

func TestNanoGuard(t *testing.T) {
	e, path := testEditor(t, staticZone(), "example")
	// simulate a concurrent hand-edit landing after we read & checkzone'd
	e.beforeWrite = func() { os.WriteFile(path, []byte(zoneText+"sneaky IN A 6.6.6.6\n"), 0o640) }
	_, err := e.Apply("example", []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "x.example. 60 IN A 1.1.1.1")}})
	if err == nil || !strings.Contains(err.Error(), "changed under you") {
		t.Fatalf("the nano guard should refuse a concurrent change, got %v", err)
	}
	// the concurrent edit is intact; goddns wrote nothing
	out, _ := os.ReadFile(path)
	if !strings.Contains(string(out), "sneaky") || strings.Contains(string(out), "x.example.") {
		t.Fatalf("goddns clobbered the concurrent edit:\n%s", out)
	}
}

func TestUnsafeFallsToRawError(t *testing.T) {
	e, path := testEditor(t, staticZone(), "example")
	// a zone with owner-name omission so the target's neighbour inherits
	os.WriteFile(path, []byte("$ORIGIN example.\n$TTL 60\n@ IN SOA ns. host. 1 2 3 4 5\n@ IN NS ns.\nhost IN A 1.1.1.1\n\tIN A 2.2.2.2\n"), 0o640)
	_, err := e.Apply("example", []ddns.Op{{Action: ddns.DelRR, RR: mustRR(t, "host.example. 0 IN A 1.1.1.1")}})
	var ue *zonefile.UnsafeError
	if !errors.As(err, &ue) {
		t.Fatalf("a surgically-unsafe edit should surface UnsafeError (raw mode), got %v", err)
	}
}

func TestPreviewDoesNotWrite(t *testing.T) {
	e, path := testEditor(t, staticZone(), "example")
	before, _ := os.ReadFile(path)
	res, err := e.Preview("example", []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "p.example. 60 IN A 1.1.1.1")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 1 || res.Backup != "" {
		t.Fatalf("preview should show 1 add and take no backup: %+v", res)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("preview must not write the file")
	}
}

func TestCheckzoneGateIntegration(t *testing.T) {
	e, _ := testEditor(t, staticZone(), "example")
	e.CheckZone = zonefile.CheckZone // the real one
	_, err := e.Apply("example", []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "ok.example. 60 IN A 1.1.1.1")}})
	if err != nil && strings.Contains(err.Error(), "not found") {
		t.Skip("named-checkzone not installed")
	}
	if err != nil {
		t.Fatalf("a valid edit should pass real checkzone: %v", err)
	}
}

func u32(n uint32) string {
	var b []byte
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
