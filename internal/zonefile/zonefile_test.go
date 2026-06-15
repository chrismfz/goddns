package zonefile

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/ddns"
)

// a hand-crafted zone with the adversarial features the design must preserve:
// a multi-line parenthesised SOA with per-line `; comment`s, implied-owner
// records (leading whitespace inheriting @ / the line above), aligned columns,
// blank lines, and trailing comments.
const handZone = `$ORIGIN example.
$TTL 3600
; the apex
@	IN	SOA	ns1.example. host.example. (
			2024010101	; serial
			3600		; refresh
			600		; retry
			1209600		; expire
			60 )		; minimum
	IN	NS	ns1.example.
	IN	NS	ns2.example.

; hosts
www	IN	A	1.2.3.4		; the web
www	IN	AAAA	2001:db8::1
mail	3600 IN	A	5.6.7.8
host	IN	A	1.1.1.1
	IN	A	2.2.2.2		; inherits "host"
`

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil || rr == nil {
		t.Fatalf("NewRR %q: %v", s, err)
	}
	return rr
}

func parse(t *testing.T, z string) *File {
	t.Helper()
	f, err := Parse([]byte(z), "example.")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return f
}

// restoreSerial swaps the (new) serial back to the original so the rest of the
// file can be asserted byte-identical.
func restoreSerial(out string, oldSerial, newSerial uint32) string {
	return strings.Replace(out, u32(newSerial), u32(oldSerial), 1)
}
func u32(n uint32) string { return strconv.FormatUint(uint64(n), 10) }

func TestNoOpBumpsSerialAndPreservesEverything(t *testing.T) {
	f := parse(t, handZone)
	if !f.Surgical() {
		t.Fatalf("hand zone should be surgically editable, got: %s", f.Reason())
	}
	old := f.SOASerial()
	if old != 2024010101 {
		t.Fatalf("serial = %d, want 2024010101", old)
	}
	out, err := f.Edit(nil)
	if err != nil {
		t.Fatal(err)
	}
	gotNew := parse(t, string(out)).SOASerial()
	if gotNew <= old {
		t.Fatalf("serial didn't advance: %d -> %d", old, gotNew)
	}
	// everything except the serial must be byte-identical
	if restored := restoreSerial(string(out), old, gotNew); restored != handZone {
		t.Fatalf("non-serial bytes changed.\n--- got ---\n%s\n--- want ---\n%s", restored, handZone)
	}
}

func TestSerialCommentAndIndentPreserved(t *testing.T) {
	f := parse(t, handZone)
	out, _ := f.Edit(nil)
	if !strings.Contains(string(out), "; serial") {
		t.Fatal("the `; serial` comment was lost in the bump")
	}
	// the serial line keeps its leading tabs
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "; serial") {
			if !strings.HasPrefix(line, "\t\t\t") {
				t.Fatalf("serial line lost its indentation: %q", line)
			}
		}
	}
}

func TestAddRecordAppendsAndPreserves(t *testing.T) {
	f := parse(t, handZone)
	old := f.SOASerial()
	op := []ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "new.example. 60 IN A 9.9.9.9")}}
	out, err := f.Edit(op)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "new.example.") || !strings.Contains(s, "9.9.9.9") {
		t.Fatalf("added record missing:\n%s", s)
	}
	// original records still present, file still ends with a newline
	if !strings.Contains(s, "www\tIN\tA\t1.2.3.4") || !strings.HasSuffix(s, "\n") {
		t.Fatalf("original content/trailing newline not preserved:\n%s", s)
	}
	if parse(t, s).SOASerial() <= old {
		t.Fatal("serial not bumped on add")
	}
}

func TestDeleteExplicitSingleLine(t *testing.T) {
	f := parse(t, handZone)
	// www AAAA is explicit, single-line, and the record after it (mail) is explicit
	op := []ddns.Op{{Action: ddns.DelRR, RR: mustRR(t, "www.example. 0 IN AAAA 2001:db8::1")}}
	out, err := f.Edit(op)
	if err != nil {
		t.Fatalf("delete of a safe record should succeed: %v", err)
	}
	if strings.Contains(string(out), "2001:db8::1") {
		t.Fatalf("record not removed:\n%s", out)
	}
	// the neighbouring www A is untouched
	if !strings.Contains(string(out), "www\tIN\tA\t1.2.3.4") {
		t.Fatalf("neighbour record damaged:\n%s", out)
	}
}

func TestRefuseDeleteWhenNextInheritsOwner(t *testing.T) {
	f := parse(t, handZone)
	// "host IN A 1.1.1.1" is explicit, but the line below it ("  IN A 2.2.2.2")
	// inherits "host" — deleting the first would silently re-home the second.
	op := []ddns.Op{{Action: ddns.DelRR, RR: mustRR(t, "host.example. 0 IN A 1.1.1.1")}}
	_, err := f.Edit(op)
	var ue *UnsafeError
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), "inherits its owner") {
		t.Fatalf("expected an UnsafeError about owner inheritance, got %v", err)
	}
}

func TestRefuseDeleteImpliedOwnerRecord(t *testing.T) {
	f := parse(t, handZone)
	// the second NS ("  IN NS ns2") is implied-owner — not surgically editable
	op := []ddns.Op{{Action: ddns.DelRR, RR: mustRR(t, "example. 0 IN NS ns2.example.")}}
	_, err := f.Edit(op)
	var ue *UnsafeError
	if !errors.As(err, &ue) {
		t.Fatalf("expected an UnsafeError for an implied-owner target, got %v", err)
	}
}

func TestRefuseDeleteSOA(t *testing.T) {
	f := parse(t, handZone)
	op := []ddns.Op{{Action: ddns.DelName, RR: mustRR(t, "example. 0 IN SOA ns1.example. host.example. 1 2 3 4 5")}}
	_, err := f.Edit(op)
	if err == nil || !strings.Contains(err.Error(), "SOA") {
		t.Fatalf("deleting the apex (which includes the SOA) must be refused, got %v", err)
	}
}

func TestDelRRsetMissingIsNoOp(t *testing.T) {
	f := parse(t, handZone)
	op := []ddns.Op{{Action: ddns.DelRR, RR: mustRR(t, "absent.example. 0 IN A 8.8.8.8")}}
	out, err := f.Edit(op)
	if err != nil {
		t.Fatalf("deleting an absent record is a no-op, not an error: %v", err)
	}
	// only the serial changed
	old := f.SOASerial()
	if restoreSerial(string(out), old, parse(t, string(out)).SOASerial()) != handZone {
		t.Fatal("a no-op delete changed more than the serial")
	}
}

func TestRefuseDeleteWhenNextInheritsTTL(t *testing.T) {
	// No $TTL directive: "b" omits its TTL, inheriting "a"'s 300. Deleting "a"
	// would silently change b's effective TTL — must be refused.
	z := "$ORIGIN example.\n@ IN SOA ns.example. host.example. 100 3 4 5 6\n@ IN NS ns.example.\na 300 IN A 1.1.1.1\nb IN A 2.2.2.2\n"
	f := parse(t, z)
	if !f.Surgical() {
		t.Fatalf("zone should be surgical, got %q", f.Reason())
	}
	op := []ddns.Op{{Action: ddns.DelRR, RR: mustRR(t, "a.example. 0 IN A 1.1.1.1")}}
	_, err := f.Edit(op)
	var ue *UnsafeError
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), "inherits its TTL") {
		t.Fatalf("expected a TTL-inheritance UnsafeError, got %v", err)
	}
}

func TestDeleteSafeWithTTLDirective(t *testing.T) {
	// With $TTL present, an omitted TTL inherits from the directive, not the
	// neighbour — so the same delete is safe.
	z := "$ORIGIN example.\n$TTL 3600\n@ IN SOA ns.example. host.example. 100 3 4 5 6\n@ IN NS ns.example.\na 300 IN A 1.1.1.1\nb IN A 2.2.2.2\n"
	f := parse(t, z)
	op := []ddns.Op{{Action: ddns.DelRR, RR: mustRR(t, "a.example. 0 IN A 1.1.1.1")}}
	if _, err := f.Edit(op); err != nil {
		t.Fatalf("delete should be safe with $TTL present: %v", err)
	}
}

func TestTXTWithParensSemicolonsRoundTrips(t *testing.T) {
	z := "$ORIGIN example.\n$TTL 60\n@ IN SOA ns.example. host.example. 5 3 4 5 6\n@ IN NS ns.example.\ntxt IN TXT \"v=spf1 a:foo (bar) ; not a comment\"\n"
	f := parse(t, z)
	if !f.Surgical() {
		t.Fatalf("TXT-with-specials should be surgical, got %q", f.Reason())
	}
	out, err := f.Edit(nil)
	if err != nil {
		t.Fatal(err)
	}
	old := f.SOASerial()
	if restoreSerial(string(out), old, parse(t, string(out)).SOASerial()) != z {
		t.Fatalf("TXT with parens/semicolons not preserved byte-for-byte:\n%s", out)
	}
}

func TestCRLFPreserved(t *testing.T) {
	z := "$ORIGIN example.\r\n$TTL 60\r\n@ IN SOA ns.example. host.example. 7 3 4 5 6\r\n@ IN NS ns.example.\r\nw IN A 1.1.1.1\r\n"
	f := parse(t, z)
	out, err := f.Edit(nil)
	if err != nil {
		t.Fatal(err)
	}
	old := f.SOASerial()
	if restoreSerial(string(out), old, parse(t, string(out)).SOASerial()) != z {
		t.Fatalf("CRLF endings not preserved:\n%q", out)
	}
}

func TestNoTrailingNewlineAdd(t *testing.T) {
	z := "$ORIGIN example.\n$TTL 60\n@ IN SOA ns.example. host.example. 8 3 4 5 6\n@ IN NS ns.example." // no trailing \n
	f := parse(t, z)
	out, err := f.Edit([]ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "w.example. 60 IN A 1.1.1.1")}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "w.example.") {
		t.Fatalf("add to a newline-less file failed:\n%q", out)
	}
}

func TestDuplicateDeleteFirstOnly(t *testing.T) {
	z := "$ORIGIN example.\n$TTL 60\n@ IN SOA ns.example. host.example. 9 3 4 5 6\n@ IN NS ns.example.\nw IN A 1.1.1.1\nw IN A 1.1.1.1\n"
	f := parse(t, z)
	out, err := f.Edit([]ddns.Op{{Action: ddns.DelRR, RR: mustRR(t, "w.example. 0 IN A 1.1.1.1")}})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), "w\tIN\tA\t1.1.1.1") + strings.Count(string(out), "w IN A 1.1.1.1"); n != 1 {
		t.Fatalf("DelRR should remove exactly one of the duplicate lines, %d remain:\n%s", n, out)
	}
}

func TestRefuseGenerate(t *testing.T) {
	z := "$ORIGIN example.\n$TTL 60\n@ IN SOA ns. host. ( 1 2 3 4 5 )\n@ IN NS ns.\n$GENERATE 1-3 host$ IN A 10.0.0.$\n"
	f, err := Parse([]byte(z), "example.")
	if err != nil {
		t.Fatalf("Parse should not hard-error on $GENERATE: %v", err)
	}
	if f.Surgical() {
		t.Fatal("a $GENERATE zone must not be surgically editable")
	}
	if !strings.Contains(f.Reason(), "$GENERATE") {
		t.Fatalf("reason should name $GENERATE, got %q", f.Reason())
	}
	if _, err := f.Edit(nil); err == nil {
		t.Fatal("Edit on a raw-only file must return an error")
	}
}

func TestRefuseMidFileOrigin(t *testing.T) {
	z := "$ORIGIN a.example.\n$TTL 60\n@ IN SOA ns. host. ( 1 2 3 4 5 )\n@ IN NS ns.\n$ORIGIN b.example.\nx IN A 1.1.1.1\n"
	f := parse(t, z)
	if f.Surgical() || !strings.Contains(f.Reason(), "$ORIGIN") {
		t.Fatalf("a mid-file $ORIGIN must force raw mode, surgical=%v reason=%q", f.Surgical(), f.Reason())
	}
}

func TestSingleLineSOA(t *testing.T) {
	z := "$ORIGIN example.\n$TTL 60\n@ IN SOA ns.example. host.example. 2023123199 3600 600 1209600 60\n@ IN NS ns.example.\n"
	f := parse(t, z)
	if f.SOASerial() != 2023123199 {
		t.Fatalf("serial = %d, want 2023123199", f.SOASerial())
	}
	out, err := f.Edit([]ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "w.example. 60 IN A 1.1.1.1")}})
	if err != nil {
		t.Fatal(err)
	}
	if parse(t, string(out)).SOASerial() <= 2023123199 {
		t.Fatal("single-line SOA serial not bumped")
	}
}

func TestSerialFloor(t *testing.T) {
	f := parse(t, handZone) // serial 2024010101
	// floor 0 -> date-based bump above the current serial
	out, err := f.SerialFloor(0)
	if err != nil {
		t.Fatal(err)
	}
	if s := parse(t, string(out)).SOASerial(); s <= 2024010101 {
		t.Fatalf("SerialFloor(0) = %d, want a date bump above the current", s)
	}
	// a high floor wins
	out2, _ := parse(t, handZone).SerialFloor(4000000000)
	if s := parse(t, string(out2)).SOASerial(); s != 4000000001 {
		t.Fatalf("SerialFloor(4e9) = %d, want 4000000001", s)
	}
	// the rest of the file is byte-identical except the serial
	old := uint32(2024010101)
	if restoreSerial(string(out2), old, 4000000001) != handZone {
		t.Fatalf("SerialFloor changed more than the serial:\n%s", out2)
	}
}

func TestNextSerial(t *testing.T) {
	// from an old serial -> jumps to today's YYYYMMDD00
	if got := nextSerial(1); got < 2026061500 {
		t.Fatalf("nextSerial(1) = %d, want >= today's date base", got)
	}
	// from a serial already past today -> just +1
	huge := uint32(4000000000)
	if got := nextSerial(huge); got != huge+1 {
		t.Fatalf("nextSerial(%d) = %d, want %d", huge, got, huge+1)
	}
}

func TestCheckZoneIntegration(t *testing.T) {
	// A real named-checkzone run if it's installed; otherwise skip (CI has none).
	f := parse(t, handZone)
	out, err := f.Edit([]ddns.Op{{Action: ddns.AddRR, RR: mustRR(t, "ok.example. 60 IN A 1.2.3.4")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckZone("example.", out); err != nil {
		if errors.Is(err, ErrCheckzoneMissing) {
			t.Skip("named-checkzone not installed")
		}
		t.Fatalf("checkzone rejected a valid edit: %v", err)
	}
	// a deliberately broken zone must be rejected
	bad := []byte("$ORIGIN example.\n@ IN SOA ns. host. 1 2 3 4 5\n@ IN A not-an-ip\n")
	if err := CheckZone("example.", bad); err == nil || errors.Is(err, ErrCheckzoneMissing) {
		if errors.Is(err, ErrCheckzoneMissing) {
			t.Skip("named-checkzone not installed")
		}
		t.Fatal("checkzone should have rejected a malformed zone")
	}
}
