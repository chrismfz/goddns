package zonemgr

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseInclude(t *testing.T) {
	src := `# managed by goddns
zone "a.example" { type master; file "/var/named/a.example.hosts"; };
// a hand-added one, reformatted
zone "B.Example." IN {
	type master;
	file "/var/named/b.hosts";   # the file
	allow-transfer { 192.0.2.1; };  /* nested braces */
};
options-not-here { "zone \"fake\"" ; };
zone "c.example" { type master; file "x;y.hosts"; };
`
	st, err := ParseInclude(src)
	if err != nil {
		t.Fatal(err)
	}
	var names, files []string
	for _, s := range st {
		names = append(names, s.Name)
		files = append(files, s.File)
	}
	if !reflect.DeepEqual(names, []string{"a.example", "b.example", "c.example"}) {
		t.Fatalf("names: %v", names)
	}
	if !reflect.DeepEqual(files, []string{"/var/named/a.example.hosts", "/var/named/b.hosts", "x;y.hosts"}) {
		t.Fatalf("files: %v", files)
	}
	// removing a stanza's span leaves the rest intact
	b := st[1]
	out := src[:b.Start] + src[b.End:]
	st2, err := ParseInclude(out)
	if err != nil || len(st2) != 2 || st2[1].Name != "c.example" {
		t.Fatalf("after removal: %+v %v", st2, err)
	}
	if _, err := ParseInclude(`zone "x" { type master;`); err == nil {
		t.Fatal("unbalanced stanza accepted")
	}
}

func TestIncludeReferenced(t *testing.T) {
	dir := t.TempDir()
	nc, sub, inc := filepath.Join(dir, "named.conf"), filepath.Join(dir, "zones.conf"), filepath.Join(dir, "goddns-zones.conf")
	os.WriteFile(nc, []byte("options { directory \"/var/named\"; };\n// include \""+inc+"\";\ninclude \""+sub+"\";\n"), 0o644)
	os.WriteFile(sub, []byte("zone \"x\" { type master; file \"x\"; };\n"), 0o644)
	if ok, err := IncludeReferenced(nc, inc); err != nil || ok {
		t.Fatalf("a commented-out include must not count: %v %v", ok, err)
	}
	os.WriteFile(sub, []byte("include \""+inc+"\";\n"), 0o644)
	if ok, _ := IncludeReferenced(nc, inc); !ok {
		t.Fatal("include through a sub-include not found")
	}
	if z, err := ManagedZones(filepath.Join(dir, "missing.conf")); err != nil || z != nil {
		t.Fatalf("missing include: %v %v", z, err)
	}
}
