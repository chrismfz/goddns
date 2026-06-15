// Package zonefile is the Phase-4 Stage-0 in-place zone-file edit engine. It is
// the line-aware tokenizer the design calls for: it edits records by rewriting
// only their source line(s) and leaves everything else — comments, blank lines,
// $directives, ordering, whitespace — byte for byte, so a hand-crafted zone stays
// hand-crafted. miekg's dns.ZoneParser is used ONLY to resolve/validate records
// (it discards surface syntax and gives no source-line map), never to locate edits.
//
// Stage 0 is pure and writes nothing live: Edit returns the new bytes; CheckZone
// validates against a temp file. It handles the SAFE SUBSET — explicit-owner,
// single-line records (plus the SOA serial bump) — and REFUSES the rest with an
// *UnsafeError so the caller falls back to raw mode: owner-name omission on the
// target or the record below it, multi-line records, mid-file $ORIGIN re-scope,
// and $INCLUDE/$GENERATE.
package zonefile

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/ddns"
)

// UnsafeError means the requested edit can't be done surgically without risking
// the file; the caller should fall back to raw (whole-file) mode.
type UnsafeError struct{ Reason string }

func (e *UnsafeError) Error() string { return e.Reason }

func unsafe(format string, a ...any) error { return &UnsafeError{Reason: fmt.Sprintf(format, a...)} }

// File is a parsed zone file that maps each record to its source line span.
type File struct {
	lines       []string // physical lines (split on \n; rejoined exactly)
	origin      string
	records     []*rec  // record entries in file order (empty when !surgical)
	soa         *rec    // the SOA record
	serialTok   *tokPos // location of the SOA serial token (for the in-place bump)
	hasTTLDirec bool    // a $TTL directive is present (omitted TTLs inherit from it, not neighbours)
	noSurgery   string  // non-empty reason ⇒ surgical editing refused (raw mode only)
}

type rec struct {
	rr          dns.RR
	start, end  int  // physical line span (inclusive)
	explicit    bool // explicit owner (no leading whitespace)
	explicitTTL bool // an explicit TTL token (vs inheriting from $TTL / the prior record)
}

type tokPos struct {
	line, start, end int
	text             string
}

// Parse tokenizes data (a zone file) against origin. A nil error with
// Surgical()==false means the file is well-formed but outside the safe subset
// (raw mode only); a non-nil error means it didn't parse as a zone at all.
func Parse(data []byte, origin string) (*File, error) {
	f := &File{origin: dns.Fqdn(origin), lines: strings.Split(string(data), "\n")}

	entries := tokenizeEntries(f.lines)

	// Refuse surgical editing for constructs the line-mapper can't safely reason
	// about. A leading $ORIGIN (before any record) is fine; a later one re-scopes
	// relative names mid-file.
	seenRecord := false
	for _, e := range entries {
		if e.kind == kindDirective {
			switch e.directive {
			case "$INCLUDE", "$GENERATE":
				f.noSurgery = "file uses " + e.directive + " — raw mode required"
			case "$TTL":
				f.hasTTLDirec = true
			case "$ORIGIN":
				if seenRecord {
					f.noSurgery = "file re-scopes $ORIGIN mid-file — raw mode required"
				}
			}
		}
		if e.kind == kindRecord {
			seenRecord = true
		}
	}

	// Raw-only constructs (e.g. $GENERATE) can choke the resolver, and we won't
	// use the records anyway — skip parsing and report it's raw-only.
	if f.noSurgery != "" {
		return f, nil
	}

	// Resolve records via miekg (correct owner/TTL inheritance, $ORIGIN/@).
	rrs, err := parseAll(data, f.origin)
	if err != nil {
		return nil, fmt.Errorf("zone parse: %w", err)
	}

	// Zip record-entries (line spans) with resolved RRs (same order).
	var recs []entry
	for _, e := range entries {
		if e.kind == kindRecord {
			recs = append(recs, e)
		}
	}
	if len(recs) != len(rrs) {
		f.noSurgery = fmt.Sprintf("tokenizer/parser disagree on record count (%d vs %d) — raw mode required",
			len(recs), len(rrs))
		return f, nil
	}
	for i, e := range recs {
		r := &rec{
			rr: rrs[i], start: e.start, end: e.end, explicit: e.explicit,
			explicitTTL: hasExplicitTTL(e.tokens, e.explicit, rrs[i].Header().Rrtype),
		}
		f.records = append(f.records, r)
		if rrs[i].Header().Rrtype == dns.TypeSOA {
			f.soa = r
			f.serialTok = locateSerial(e.tokens)
		}
	}
	if f.soa == nil || f.serialTok == nil {
		f.noSurgery = "no locatable SOA serial — raw mode required"
		return f, nil
	}
	// Cross-check the located serial token against the parsed SOA serial — cheap
	// insurance that the in-place bump lands on the right token (S1).
	if v, err := strconv.ParseUint(f.serialTok.text, 10, 32); err != nil || uint32(v) != f.SOASerial() {
		f.noSurgery = "the located SOA serial token doesn't match the parsed serial — raw mode required"
	}
	return f, nil
}

// Surgical reports whether the file can be edited in place (safe subset).
func (f *File) Surgical() bool { return f.noSurgery == "" }

// Reason returns why surgical editing is refused (empty if it's allowed).
func (f *File) Reason() string { return f.noSurgery }

// SOASerial returns the current serial, or 0 if no SOA.
func (f *File) SOASerial() uint32 {
	if f.soa != nil {
		if s, ok := f.soa.rr.(*dns.SOA); ok {
			return s.Serial
		}
	}
	return 0
}

// Edit applies ops surgically and returns the new file bytes (with the SOA serial
// bumped). It changes only the targeted record lines; everything else is byte
// identical. Returns *UnsafeError if any op targets a record outside the safe
// subset — the caller then uses raw mode.
func (f *File) Edit(ops []ddns.Op) ([]byte, error) {
	if f.noSurgery != "" {
		return nil, unsafe("%s", f.noSurgery)
	}
	del := map[int]bool{} // original line indices to drop
	var adds []string

	for _, op := range ops {
		if op.RR == nil {
			return nil, fmt.Errorf("operation has no record")
		}
		switch op.Action {
		case ddns.AddRR:
			adds = append(adds, op.RR.String())
		case ddns.DelRR:
			if r := f.findExact(op.RR); r != nil {
				if err := f.canDelete(r); err != nil {
					return nil, err
				}
				del[r.start] = true
			}
		case ddns.DelRRset:
			for _, r := range f.findRRset(op.RR) {
				if err := f.canDelete(r); err != nil {
					return nil, err
				}
				del[r.start] = true
			}
		case ddns.DelName:
			for _, r := range f.findName(op.RR) {
				if err := f.canDelete(r); err != nil {
					return nil, err
				}
				del[r.start] = true
			}
		default:
			return nil, fmt.Errorf("unknown op action")
		}
	}

	// Bump the serial in place on its (surviving) line.
	out := append([]string(nil), f.lines...)
	next := nextSerial(f.SOASerial())
	st := f.serialTok
	out[st.line] = out[st.line][:st.start] + fmt.Sprint(next) + out[st.line][st.end:]

	// Drop deleted lines, then append the added records.
	var res []string
	for i, l := range out {
		if !del[i] {
			res = append(res, l)
		}
	}
	res = appendRecords(res, adds)
	return []byte(strings.Join(res, "\n")), nil
}

// canDelete enforces the safe subset for a delete/replace target: removing the
// line must not silently re-home the record below it (owner OR TTL inheritance).
func (f *File) canDelete(r *rec) error {
	if r == f.soa {
		return unsafe("refusing to delete the SOA record")
	}
	if !r.explicit || r.start != r.end {
		return unsafe("record at line %d uses owner-name omission or spans multiple lines — raw mode required", r.start+1)
	}
	nxt := f.nextRecord(r)
	if nxt == nil {
		return nil
	}
	if !nxt.explicit {
		return unsafe("the record after line %d inherits its owner from it — raw mode required", r.start+1)
	}
	// With no $TTL directive, an omitted TTL inherits from the PREVIOUS record;
	// deleting this one would change the next record's effective TTL.
	if !f.hasTTLDirec && !nxt.explicitTTL {
		return unsafe("the record after line %d inherits its TTL from it (no $TTL) — raw mode required", r.start+1)
	}
	return nil
}

func (f *File) nextRecord(r *rec) *rec {
	for i, x := range f.records {
		if x == r && i+1 < len(f.records) {
			return f.records[i+1]
		}
	}
	return nil
}

func (f *File) findExact(rr dns.RR) *rec {
	want := rrKey(rr)
	for _, r := range f.records {
		if rrKey(r.rr) == want {
			return r
		}
	}
	return nil
}

func (f *File) findRRset(rr dns.RR) []*rec {
	var out []*rec
	h := rr.Header()
	for _, r := range f.records {
		rh := r.rr.Header()
		if strings.EqualFold(rh.Name, h.Name) && rh.Rrtype == h.Rrtype {
			out = append(out, r)
		}
	}
	return out
}

func (f *File) findName(rr dns.RR) []*rec {
	var out []*rec
	h := rr.Header()
	for _, r := range f.records {
		if strings.EqualFold(r.rr.Header().Name, h.Name) {
			out = append(out, r)
		}
	}
	return out
}

// appendRecords adds new record lines, keeping a single trailing blank line (so
// the file still ends with a newline) if there was one.
func appendRecords(res, adds []string) []string {
	if len(adds) == 0 {
		return res
	}
	if n := len(res); n > 0 && res[n-1] == "" {
		head := append(res[:n-1:n-1], adds...)
		return append(head, "")
	}
	return append(res, adds...)
}

// nextSerial returns max(cur+1, YYYYMMDD00-for-today) — date-based, never regresses.
func nextSerial(cur uint32) uint32 {
	y, m, d := time.Now().Date()
	base := uint32(y)*1000000 + uint32(m)*10000 + uint32(d)*100
	next := cur + 1
	if base > next {
		next = base
	}
	return next
}

// rrKey identifies a record by name+type+rdata (case-insensitive name, TTL
// ignored) — the same identity recordmut/RFC2136 delete-exact uses.
func rrKey(rr dns.RR) string {
	h := rr.Header()
	rdata := strings.TrimPrefix(rr.String(), h.String())
	return strings.ToLower(strings.TrimSuffix(h.Name, ".")) + " " + dns.TypeToString[h.Rrtype] + " " + rdata
}

// locateSerial finds the SOA serial token: after the "SOA" token come MNAME,
// RNAME, then the serial (parens are not tokens). Returns nil if not found.
func locateSerial(toks []tokPos) *tokPos {
	for i, t := range toks {
		if strings.EqualFold(t.text, "SOA") {
			if i+3 < len(toks) {
				s := toks[i+3]
				return &s
			}
			return nil
		}
	}
	return nil
}

func directiveName(tok string) (string, bool) {
	up := strings.ToUpper(tok)
	switch up {
	case "$ORIGIN", "$TTL", "$INCLUDE", "$GENERATE":
		return up, true
	}
	return "", false
}

// hasExplicitTTL reports whether a record's source carried an explicit TTL token
// (between the owner/class and the type) rather than inheriting one.
func hasExplicitTTL(toks []tokPos, explicitOwner bool, rrtype uint16) bool {
	typeStr := dns.TypeToString[rrtype]
	i := 0
	if explicitOwner && len(toks) > 0 {
		i = 1 // skip the owner token
	}
	for ; i < len(toks); i++ {
		t := toks[i].text
		if strings.EqualFold(t, typeStr) {
			return false // reached the type with no TTL
		}
		if isClass(t) {
			continue
		}
		if looksLikeTTL(t) {
			return true
		}
	}
	return false
}

func isClass(s string) bool {
	switch strings.ToUpper(s) {
	case "IN", "CH", "HS", "CS", "ANY", "NONE":
		return true
	}
	return false
}

// looksLikeTTL matches a bare number or a BIND duration like 1h / 1h30m.
func looksLikeTTL(s string) bool {
	if s == "" {
		return false
	}
	digit := false
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case strings.ContainsRune("smhdwSMHDW", c):
		default:
			return false
		}
	}
	return digit
}

func parseAll(data []byte, origin string) ([]dns.RR, error) {
	zp := dns.NewZoneParser(bytes.NewReader(data), origin, "")
	zp.SetIncludeAllowed(false)
	var rrs []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, err
	}
	return rrs, nil
}

// --- tokenizer ---

type entryKind int

const (
	kindBlank entryKind = iota
	kindDirective
	kindRecord
)

type entry struct {
	kind       entryKind
	start, end int
	tokens     []tokPos
	explicit   bool
	directive  string // uppercase, for kindDirective
}

func tokenizeEntries(lines []string) []entry {
	var out []entry
	i := 0
	for i < len(lines) {
		toks, delta, leadWS := scanLine(lines[i])
		for k := range toks {
			toks[k].line = i
		}
		if len(toks) == 0 {
			out = append(out, entry{kind: kindBlank, start: i, end: i})
			i++
			continue
		}
		// Only the known directives are directives — a (rare, legal) owner like
		// "$x" is a record. A misclassification here is also caught downstream by
		// the tokenizer/parser count backstop, but classifying precisely is better.
		if name, ok := directiveName(toks[0].text); ok {
			out = append(out, entry{kind: kindDirective, start: i, end: i, tokens: toks, directive: name})
			i++
			continue
		}
		// a record entry — continue while parens are open
		depth := delta
		start, j := i, i
		all := toks
		for depth > 0 && j+1 < len(lines) {
			j++
			t2, d2, _ := scanLine(lines[j])
			for k := range t2 {
				t2[k].line = j
			}
			all = append(all, t2...)
			depth += d2
		}
		out = append(out, entry{kind: kindRecord, start: start, end: j, tokens: all, explicit: !leadWS})
		i = j + 1
	}
	return out
}

// scanLine returns the content tokens on a line (with byte columns), the net
// paren depth change, and whether the line begins with whitespace (⇒ owner-name
// omission for a record). Comments (`;` outside quotes) and parens are not tokens.
func scanLine(line string) (toks []tokPos, parenDelta int, leadingWS bool) {
	n := len(line)
	if n > 0 && (line[0] == ' ' || line[0] == '\t') {
		leadingWS = true
	}
	inQuote := false
	i := 0
	for i < n {
		c := line[i]
		if !inQuote && c == ';' {
			break // comment to end of line
		}
		if !inQuote && (c == ' ' || c == '\t' || c == '\r') {
			i++
			continue
		}
		if !inQuote && c == '(' {
			parenDelta++
			i++
			continue
		}
		if !inQuote && c == ')' {
			parenDelta--
			i++
			continue
		}
		start := i
		for i < n {
			c = line[i]
			if c == '"' {
				inQuote = !inQuote
				i++
				continue
			}
			if !inQuote && (c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '(' || c == ')') {
				break
			}
			i++
		}
		toks = append(toks, tokPos{start: start, end: i, text: line[start:i]})
	}
	return toks, parenDelta, leadingWS
}
