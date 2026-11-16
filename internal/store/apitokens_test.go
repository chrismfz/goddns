package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAPITokens(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.UserAdd("alice", "h", "user")
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	tk, plain, err := st.APITokenAdd("alice", "ci", []string{"zones:read", "ddns:write"}, []string{"10.0.0.0/8"}, exp)
	if err != nil || !strings.HasPrefix(plain, APITokenPrefix) || tk.TokenHash == plain {
		t.Fatalf("add: %+v %q %v", tk, plain, err)
	}
	if _, _, err := st.APITokenAdd("alice", "ci", nil, nil, time.Time{}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	got, err := st.APITokenLookup(plain)
	if err != nil || got.ID != tk.ID || strings.Join(got.Scopes, ",") != "zones:read,ddns:write" ||
		got.AllowNets[0] != "10.0.0.0/8" || !got.ExpiresAt.Equal(exp) || !got.LastUsed.IsZero() {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if _, err := st.APITokenLookup(plain + "x"); err != ErrNoAPIToken {
		t.Fatalf("bad token: %v", err)
	}
	now := time.Now()
	st.APITokenTouch(tk.ID, now)
	st.APITokenTouch(tk.ID, now.Add(10*time.Second)) // within a minute: no write
	if g, _ := st.APITokenGet(tk.ID); g.LastUsed.Unix() != now.Unix() {
		t.Fatalf("touch: %v", g.LastUsed)
	}
	st.APITokenAdd("bob", "x", nil, nil, time.Time{})
	if l, _ := st.APITokenList("alice"); len(l) != 1 {
		t.Fatalf("list alice: %d", len(l))
	}
	if l, _ := st.APITokenList(""); len(l) != 2 {
		t.Fatalf("list all: %d", len(l))
	}
	st.UserDel("alice") // drops her tokens
	if _, err := st.APITokenLookup(plain); err != ErrNoAPIToken {
		t.Fatalf("token survived its user: %v", err)
	}
	if err := st.APITokenDel(tk.ID); err != ErrNoAPIToken {
		t.Fatalf("del gone: %v", err)
	}
}
