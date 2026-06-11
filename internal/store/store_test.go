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
