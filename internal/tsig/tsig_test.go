package tsig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRenderRoundTrip(t *testing.T) {
	src := `// a comment
key "ddns-update" {
	algorithm hmac-sha256;
	secret "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
};
key "acme-key" {
	algorithm "hmac-sha512";
	secret "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
};
`
	keys := Parse([]byte(src))
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	if k := Find(keys, "ddns-update."); k == nil || k.Algo != "hmac-sha256" || !strings.HasPrefix(k.Secret, "AAAA") {
		t.Fatalf("ddns-update parse: %+v", k)
	}
	// quoted algorithm form (named-checkconf -p style) also parses
	if k := Find(keys, "acme-key"); k == nil || k.Algo != "hmac-sha512" {
		t.Fatalf("acme-key parse: %+v", k)
	}

	// render -> parse is stable
	again := Parse([]byte(Render(keys)))
	if len(again) != 2 || Find(again, "acme-key").Secret != Find(keys, "acme-key").Secret {
		t.Fatalf("round trip lost a key: %+v", again)
	}
}

func TestWriteFileAtomicAndRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tsig.keys")
	s1, _ := GenSecret()
	s2, _ := GenSecret()
	if s1 == s2 || len(s1) < 40 {
		t.Fatalf("GenSecret weak/dup: %q %q", s1, s2)
	}
	keys := []Key{
		{Name: "ddns-update", Algo: "hmac-sha256", Secret: s1},
		{Name: "acme-key", Algo: "hmac-sha256", Secret: s2},
	}
	if err := WriteFile(path, keys); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o, want 0640", fi.Mode().Perm())
	}

	// rotate only ddns-update; acme-key must stay intact
	loaded, _ := LoadFile(path)
	newSecret, _ := GenSecret()
	Find(loaded, "ddns-update").Secret = newSecret
	if err := WriteFile(path, loaded); err != nil {
		t.Fatal(err)
	}
	after, _ := LoadFile(path)
	if Find(after, "ddns-update").Secret != newSecret {
		t.Error("rotation did not take")
	}
	if Find(after, "acme-key").Secret != s2 {
		t.Error("rotation clobbered the other key")
	}
}
