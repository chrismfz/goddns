package store

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestGrants(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.UserAdd("alice", "h", "user")
	st.GrantAdd("alice", "Example.COM.")
	st.GrantAdd("alice", "example.com") // same grant, no-op
	st.GrantAdd("alice", "b.example")
	st.GrantAdd("bob", "c.example")
	if z, _ := st.GrantsFor("alice"); !reflect.DeepEqual(z, []string{"b.example", "example.com"}) {
		t.Fatalf("alice: %v", z)
	}
	if err := st.GrantDel("alice", "b.example."); err != nil {
		t.Fatal(err)
	}
	if err := st.GrantDel("alice", "b.example"); err != ErrNoGrant {
		t.Fatalf("revoke twice: %v", err)
	}
	// deleting the user drops their grants, so a later "alice" starts clean
	if err := st.UserDel("alice"); err != nil {
		t.Fatal(err)
	}
	if z, _ := st.GrantsFor("alice"); len(z) != 0 {
		t.Fatalf("grants survived user delete: %v", z)
	}
	if all, _ := st.GrantsAll(); !reflect.DeepEqual(all, map[string][]string{"bob": {"c.example"}}) {
		t.Fatalf("all: %v", all)
	}
}

// A user-owned DDNS token works only while its owner is enabled and holds
// the zone (or is an admin); revoke/disable stop it, re-grant restores it,
// deleting the user deletes it. Admin tokens ignore grants.
func TestOwnedTokenFollowsGrant(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "o.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.UserAdd("alice", "h", "user")
	st.GrantAdd("alice", "example.com")
	_, tok, _ := st.AddFor("alice", "cam.example.com", "example.com", 60)
	_, adminTok, _ := st.Add("gw.example.com", "example.com", 60)
	works := func(tk string) bool { _, err := st.Lookup(tk); return err == nil }
	if !works(tok) || !works(adminTok) {
		t.Fatal("tokens should work")
	}
	st.GrantDel("alice", "example.com")
	if works(tok) || !works(adminTok) {
		t.Fatal("revoke: owned token must stop, admin token must not")
	}
	st.GrantAdd("alice", "example.com")
	st.UserSetDisabled("alice", true)
	if works(tok) {
		t.Fatal("disabled owner's token still works")
	}
	st.UserSetDisabled("alice", false)
	if !works(tok) {
		t.Fatal("re-enabled + granted owner's token should work again")
	}
	st.GrantDel("alice", "example.com")
	st.UserSetRole("alice", "admin")
	if !works(tok) {
		t.Fatal("an admin owner reaches every zone")
	}
	st.UserDel("alice")
	if r, err := st.Get("cam.example.com"); err == nil {
		t.Fatalf("deleting the user must delete their records: %+v", r)
	}
}
