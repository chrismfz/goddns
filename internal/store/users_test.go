package store

import (
	"path/filepath"
	"testing"
)

func TestUsersCRUD(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.UserAdd("alice", "$argon2id$x", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UserAdd("alice", "h", "user"); err == nil {
		t.Fatal("duplicate name accepted")
	}
	st.UserAdd("bob", "h2", "user")
	if err := st.UserSetRole("bob", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := st.UserSetDisabled("bob", true); err != nil {
		t.Fatal(err)
	}
	if err := st.UserSetPassword("bob", "h3"); err != nil {
		t.Fatal(err)
	}
	u, err := st.UserGet("bob")
	if err != nil || u.Role != "admin" || !u.Disabled || u.PassHash != "h3" {
		t.Fatalf("bob: %+v %v", u, err)
	}
	if l, _ := st.UserList(); len(l) != 2 || l[0].Name != "alice" {
		t.Fatalf("list: %+v", l)
	}
	if err := st.UserDel("bob"); err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{st.UserDel("bob"), st.UserSetRole("bob", "user")} {
		if err != ErrNoUser {
			t.Fatalf("missing user: %v", err)
		}
	}
	if _, err := st.UserGet("bob"); err != ErrNoUser {
		t.Fatalf("get missing: %v", err)
	}
}
