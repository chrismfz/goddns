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
