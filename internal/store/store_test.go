package store

import (
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestMarkSeenVsUpdated(t *testing.T) {
	st := openTemp(t)
	rec, tok, err := st.Add("home.myip.gr", "myip.gr", 60)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	// a fresh record has never changed nor been seen
	got, _ := st.Lookup(tok)
	if !got.LastUpdate.IsZero() && got.LastUpdate.Unix() > 0 {
		t.Fatalf("new record should have no last_update, got %v", got.LastUpdate)
	}
	if !got.LastSeen.IsZero() && got.LastSeen.Unix() > 0 {
		t.Fatalf("new record should have no last_seen, got %v", got.LastSeen)
	}

	// a nochg check-in stamps last_seen ONLY — last_ip/last_update untouched
	if err := st.MarkSeen(rec.ID); err != nil {
		t.Fatalf("markSeen: %v", err)
	}
	got, _ = st.Lookup(tok)
	if got.LastSeen.Unix() <= 0 {
		t.Fatal("MarkSeen did not stamp last_seen")
	}
	if got.LastIP != "" || got.LastUpdate.Unix() > 0 {
		t.Fatalf("MarkSeen must not touch last_ip/last_update, got ip=%q update=%v", got.LastIP, got.LastUpdate)
	}

	// an IP change stamps both last_update and last_seen
	if err := st.MarkUpdated(rec.ID, "203.0.113.10"); err != nil {
		t.Fatalf("markUpdated: %v", err)
	}
	got, _ = st.Lookup(tok)
	if got.LastIP != "203.0.113.10" || got.LastUpdate.Unix() <= 0 || got.LastSeen.Unix() <= 0 {
		t.Fatalf("MarkUpdated should set ip+update+seen, got ip=%q update=%v seen=%v",
			got.LastIP, got.LastUpdate, got.LastSeen)
	}
}

func TestAddLookupDel(t *testing.T) {
	st := openTemp(t)

	rec, tok, err := st.Add("Home.MyIP.gr", "myip.gr", 60)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if rec.FQDN != "home.myip.gr." || rec.Zone != "myip.gr." {
		t.Fatalf("fqdn normalisation: got %q / %q", rec.FQDN, rec.Zone)
	}
	if tok == "" {
		t.Fatal("empty token")
	}

	got, err := st.Lookup(tok)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.FQDN != rec.FQDN {
		t.Fatalf("lookup returned %q, want %q", got.FQDN, rec.FQDN)
	}

	if _, err := st.Lookup("wrong-token"); err != ErrNotFound {
		t.Fatalf("lookup wrong token: got %v, want ErrNotFound", err)
	}

	if err := st.MarkUpdated(rec.ID, "203.0.113.10"); err != nil {
		t.Fatalf("mark: %v", err)
	}
	got, _ = st.Lookup(tok)
	if got.LastIP != "203.0.113.10" {
		t.Fatalf("last ip: got %q", got.LastIP)
	}

	if err := st.Del("home.myip.gr"); err != nil {
		t.Fatalf("del: %v", err)
	}
	if err := st.Del("home.myip.gr"); err != ErrNotFound {
		t.Fatalf("double del: got %v, want ErrNotFound", err)
	}
}

func TestDuplicateFQDNRejected(t *testing.T) {
	st := openTemp(t)
	if _, _, err := st.Add("a.myip.gr", "myip.gr", 60); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Add("a.myip.gr", "myip.gr", 60); err == nil {
		t.Fatal("duplicate fqdn accepted")
	}
}

func TestList(t *testing.T) {
	st := openTemp(t)
	for _, n := range []string{"b.myip.gr", "a.myip.gr"} {
		if _, _, err := st.Add(n, "myip.gr", 60); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].FQDN != "a.myip.gr." {
		t.Fatalf("list: %+v", recs)
	}
}

func TestRotateAndGet(t *testing.T) {
	st := openTemp(t)
	rec, tok1, err := st.Add("home.myip.gr", "myip.gr", 60)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.MarkUpdated(rec.ID, "1.2.3.4")
	// rotate: old token stops, new works, history preserved
	rec2, tok2, err := st.Rotate("home.myip.gr")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if tok2 == tok1 {
		t.Fatal("rotate returned the same token")
	}
	if rec2.LastIP != "1.2.3.4" {
		t.Fatalf("rotate lost history: %q", rec2.LastIP)
	}
	if _, err := st.Lookup(tok1); err != ErrNotFound {
		t.Fatal("old token still valid after rotate")
	}
	if r, err := st.Lookup(tok2); err != nil || r.FQDN != "home.myip.gr." {
		t.Fatalf("new token invalid: %v", err)
	}
	// Get does not expose the token, returns the record
	g, err := st.Get("home.myip.gr")
	if err != nil || g.FQDN != "home.myip.gr." {
		t.Fatalf("get: %v %+v", err, g)
	}
	if _, _, err := st.Rotate("nope.myip.gr"); err != ErrNotFound {
		t.Fatalf("rotate missing: %v", err)
	}
}
