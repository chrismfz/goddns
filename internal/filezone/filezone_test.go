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

func TestRefuseOutOfZoneRecord(t *testing.T) {
	e, path := testEditor(t, staticZone(), "example")
	// an out-of-zone owner must be refused (named-checkzone only WARNS on it, so
	// it would otherwise be appended and pollute the authoritative file)
	op := []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "evil.victim.com. 60 IN A 6.6.6.6")}}
	if _, err := e.Apply("example", op); err == nil || !strings.Contains(err.Error(), "not inside zone") {
		t.Fatalf("an out-of-zone record must be refused, got %v", err)
	}
	if out, _ := os.ReadFile(path); strings.Contains(string(out), "victim.com") {
		t.Fatal("the out-of-zone record must not be written")
	}
}

func TestRefuseInFileSignedZone(t *testing.T) {
	e, path := testEditor(t, staticZone(), "example")
	// a zone signed IN the file (a DNSSEC record present) must be refused — a
	// record edit + serial bump would invalidate the signatures.
	os.WriteFile(path, []byte(zoneText+"example. 3600 IN NSEC www.example. A NS SOA RRSIG NSEC\n"), 0o640)
	op := []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "new.example. 60 IN A 9.9.9.9")}}
	if _, err := e.Apply("example", op); err == nil || !strings.Contains(err.Error(), "signed in the file") {
		t.Fatalf("an in-file-signed zone must be refused, got %v", err)
	}
	// (an inline-signed zone has an UNSIGNED source — no DNSSEC records in the
	// file — so it passes; that's the plain-zone path, covered elsewhere.)
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

func TestDelRRsetQualifiedName(t *testing.T) {
	// The CLI qualifies short names to FQDN-under-zone; the engine matches the
	// parsed (fully-qualified) owner. A qualified name removes the RRset...
	e, path := testEditor(t, staticZone(), "example")
	qualified := []ddns.Op{{Action: ddns.DelRRset, RR: &dns.RFC3597{Hdr: dns.RR_Header{
		Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassINET}}}}
	res, err := e.Apply("example", qualified)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 1 {
		t.Fatalf("qualified delset should remove www A, Removed=%v", res.Removed)
	}
	if out, _ := os.ReadFile(path); strings.Contains(string(out), "www\tIN\tA") {
		t.Fatalf("www A not removed:\n%s", out)
	}

	// ...while a root-level "www." (the pre-qualify bug shape) is now refused as
	// out-of-zone rather than silently matching nothing.
	e2, path2 := testEditor(t, staticZone(), "example")
	rootlevel := []ddns.Op{{Action: ddns.DelRRset, RR: &dns.RFC3597{Hdr: dns.RR_Header{
		Name: "www.", Rrtype: dns.TypeA, Class: dns.ClassINET}}}}
	if _, err := e2.Apply("example", rootlevel); err == nil || !strings.Contains(err.Error(), "not inside zone") {
		t.Fatalf("a root-level www. must be refused as out-of-zone, got %v", err)
	}
	if out, _ := os.ReadFile(path2); !strings.Contains(string(out), "www\tIN\tA\t1.2.3.4") {
		t.Fatal("www A should be untouched")
	}
}

func TestReloadFailureRestores(t *testing.T) {
	e, path := testEditor(t, staticZone(), "example")
	e.Reload = func(string) error { return errors.New("rndc down") }
	_, err := e.Apply("example", []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "x.example. 60 IN A 1.1.1.1")}})
	if err == nil || !strings.Contains(err.Error(), "reload failed") {
		t.Fatalf("expected a reload-failed error, got %v", err)
	}
	// the previous file must be restored (named keeps serving the old zone)
	if out, _ := os.ReadFile(path); string(out) != zoneText {
		t.Fatalf("reload failure didn't restore the previous file:\n%s", out)
	}
}

func TestRawReplace(t *testing.T) {
	e, path := testEditor(t, staticZone(), "example")
	base := []byte(zoneText)
	newContent := []byte(zoneText + "extra\tIN\tA\t7.7.7.7\n")
	res, err := e.ReplaceRaw("example", newContent, base)
	if err != nil {
		t.Fatalf("ReplaceRaw: %v", err)
	}
	out, _ := os.ReadFile(path)
	if !strings.Contains(string(out), "extra\tIN\tA\t7.7.7.7") {
		t.Fatalf("raw replace didn't take:\n%s", out)
	}
	if res.Serial <= 2024010101 {
		t.Fatalf("serial not normalized: %d", res.Serial)
	}
	if res.Backup == "" {
		t.Fatal("no backup")
	}
}

func TestRawImportStaleSerialNormalized(t *testing.T) {
	e, path := testEditor(t, staticZone(), "example")
	// an imported file carrying a much older serial (5) must not regress the zone
	stale := []byte("$ORIGIN example.\n$TTL 3600\n@ IN SOA ns.example. host.example. 5 3600 600 1209600 60\n@ IN NS ns.example.\nimported IN A 8.8.8.8\n")
	res, _, err := e.PreviewRaw("example", stale)
	if err != nil {
		t.Fatal(err)
	}
	if res.Serial <= 2024010101 {
		t.Fatalf("stale import serial not floored above current: %d", res.Serial)
	}
	if _, err := e.ReplaceRaw("example", stale, nil); err != nil {
		t.Fatal(err)
	}
	if s := parseSerial(t, path); s <= 2024010101 {
		t.Fatalf("written serial regressed: %d", s)
	}
}

func TestRawGenerateSerialFloor(t *testing.T) {
	e, _ := testEditor(t, staticZone(), "example") // current serial 2024010101
	// $GENERATE content goddns can't auto-bump: a low serial must be REFUSED
	// (else it silently regresses secondaries).
	lo := []byte("$ORIGIN example.\n$TTL 60\n@ IN SOA ns.example. host.example. 5 3600 600 1209600 60\n@ IN NS ns.example.\n$GENERATE 1-3 host$ IN A 10.0.0.$\n")
	if _, _, err := e.PreviewRaw("example", lo); err == nil || !strings.Contains(err.Error(), "not above the current") {
		t.Fatalf("a $GENERATE import with a low serial must be refused, got %v", err)
	}
	// the operator can bump the SOA serial themselves (it's a normal record)
	hi := []byte("$ORIGIN example.\n$TTL 60\n@ IN SOA ns.example. host.example. 2030010100 3600 600 1209600 60\n@ IN NS ns.example.\n$GENERATE 1-3 host$ IN A 10.0.0.$\n")
	if _, _, err := e.PreviewRaw("example", hi); err != nil {
		t.Fatalf("a $GENERATE import with a high serial should be allowed: %v", err)
	}
}

func TestRawNanoGuard(t *testing.T) {
	e, path := testEditor(t, staticZone(), "example")
	staleBase := []byte("stale base that differs from the file")
	_, err := e.ReplaceRaw("example", []byte(zoneText+"x IN A 1.1.1.1\n"), staleBase)
	if err == nil || !strings.Contains(err.Error(), "changed under you") {
		t.Fatalf("a stale base must be refused, got %v", err)
	}
	if out, _ := os.ReadFile(path); string(out) != zoneText {
		t.Fatal("a refused raw replace must not write")
	}
}

func TestReadRaw(t *testing.T) {
	e, _ := testEditor(t, staticZone(), "example")
	data, err := e.ReadRaw("example")
	if err != nil || string(data) != zoneText {
		t.Fatalf("ReadRaw = %q, %v", data, err)
	}
	// refuses a non-enabled zone
	e2, _ := testEditor(t, staticZone())
	if _, err := e2.ReadRaw("example"); err == nil {
		t.Fatal("ReadRaw must refuse a non-enabled zone")
	}
}

func parseSerial(t *testing.T, path string) uint32 {
	t.Helper()
	b, _ := os.ReadFile(path)
	f, err := zonefile.Parse(b, "example.")
	if err != nil {
		t.Fatal(err)
	}
	return f.SOASerial()
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
