package named

import (
	"os"
	"testing"
)

// A realistic `named-checkconf -p` dump: implicit view, a static zone, a
// dynamic delegated zone, an IP-based dynamic zone, the root hint, a couple
// of built-in empty zones, and key definitions (incl. one referenced-but-
// missing key to exercise the checks).
const dump = `
view "_default" {
	zone "myip.gr" {
		type master;
		file "/var/named/myip.gr.hosts";
		allow-update {
			"none";
		};
		update-policy {
			grant acme-key name _acme-challenge.myip.gr. TXT;
			grant ddns-update wildcard *.ddns.myip.gr. A AAAA;
		};
	};
	zone "ddns.myip.gr" {
		type master;
		file "dynamic/ddns.myip.gr.hosts";
		update-policy {
			grant ddns-update wildcard *.ddns.myip.gr. A AAAA;
		};
	};
	zone "legacy.example" {
		type master;
		file "/var/named/legacy.hosts";
		allow-update {
			192.0.2.0/24;
		};
	};
	zone "broken.example" {
		type master;
		file "/var/named/broken.hosts";
		update-policy {
			grant ghost-key name x.broken.example. A;
		};
	};
	zone "10.in-addr.arpa" {
		type master;
		file "named.empty";
	};
	zone "." {
		type hint;
		file "named.ca";
	};
};
key "ddns-update" {
	algorithm hmac-sha256;
	secret "X1PlWPmG2wWAtUOOoET95+mBh+fg9WldWqp9R8kZr0w=";
};
key "acme-key" {
	algorithm hmac-sha256;
	secret "AcMeSeCrEtAcMeSeCrEtAcMeSeCrEtAcMeSeCrEt0000=";
};
key "rndc-key" {
	algorithm hmac-sha256;
	secret "rndcsecretrndcsecretrndcsecretrndcsecret000=";
};
`

func find(inv *Inventory, name string) *Zone {
	for i := range inv.Zones {
		if inv.Zones[i].Name == name {
			return &inv.Zones[i]
		}
	}
	return nil
}

func TestParseZonesAndKeys(t *testing.T) {
	inv := Parse([]byte(dump))

	if len(inv.Keys) != 3 {
		t.Fatalf("keys: %+v", inv.Keys)
	}
	if inv.Keys[0].Name != "ddns-update" || inv.Keys[0].Algorithm != "hmac-sha256" {
		t.Fatalf("key0: %+v", inv.Keys[0])
	}

	myip := find(inv, "myip.gr")
	if myip == nil || myip.Type != "master" || !myip.Dynamic {
		t.Fatalf("myip.gr: %+v", myip)
	}
	// update-policy with grants -> keys collected, allow-update none ignored
	if got := myip.UpdateKeys; len(got) != 2 || got[0] != "acme-key" || got[1] != "ddns-update" {
		t.Fatalf("myip keys: %v", got)
	}

	ddns := find(inv, "ddns.myip.gr")
	if ddns == nil || !ddns.Dynamic || len(ddns.UpdateKeys) != 1 || ddns.UpdateKeys[0] != "ddns-update" {
		t.Fatalf("ddns: %+v", ddns)
	}
	if ddns.File != "dynamic/ddns.myip.gr.hosts" {
		t.Fatalf("ddns file: %q", ddns.File)
	}

	// IP-based allow-update -> dynamic, no key
	legacy := find(inv, "legacy.example")
	if legacy == nil || !legacy.Dynamic || len(legacy.UpdateKeys) != 0 {
		t.Fatalf("legacy: %+v", legacy)
	}

	// root hint -> not dynamic
	if root := find(inv, "."); root == nil || root.Type != "hint" || root.Dynamic {
		t.Fatalf("root: %+v", root)
	}

	// built-in empty zone filtered out of UserZones
	for _, z := range inv.UserZones() {
		if z.Name == "10.in-addr.arpa" {
			t.Fatal("built-in empty zone not filtered")
		}
	}
}

func TestCheckFindings(t *testing.T) {
	inv := Parse([]byte(dump))

	// goddns key matches and is granted -> an OK finding present
	fs := inv.Check("ddns-update", "X1PlWPmG2wWAtUOOoET95+mBh+fg9WldWqp9R8kZr0w=")
	var sawOK, sawGhost, sawIP bool
	for _, f := range fs {
		if f.Severity == OK {
			sawOK = true
		}
		if f.Severity == Error && f.Zone == "broken.example" {
			sawGhost = true // grants ghost-key (undefined)
		}
		if f.Severity == Warn && f.Zone == "legacy.example" {
			sawIP = true // dynamic via IP only
		}
	}
	if !sawOK {
		t.Error("expected an OK finding for the matching goddns key")
	}
	if !sawGhost {
		t.Error("expected an error for broken.example granting an undefined key")
	}
	if !sawIP {
		t.Error("expected a warning for legacy.example (IP-only dynamic)")
	}

	// wrong secret -> NOTAUTH error
	fs = inv.Check("ddns-update", "wrong-secret")
	var sawMismatch bool
	for _, f := range fs {
		if f.Severity == Error && contains(f.Message, "NOTAUTH") {
			sawMismatch = true
		}
	}
	if !sawMismatch {
		t.Error("expected a NOTAUTH error on secret mismatch")
	}

	// unknown goddns key -> REFUSED error
	fs = inv.Check("nonexistent", "")
	var sawMissing bool
	for _, f := range fs {
		if f.Severity == Error && contains(f.Message, "not a key") {
			sawMissing = true
		}
	}
	if !sawMissing {
		t.Error("expected an error when goddns tsig_name isn't a named key")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestPathResolutionAndKind(t *testing.T) {
	d := `
options {
	directory "/var/named";
};
view "_default" {
	zone "myip.gr" {
		type master;
		file "/var/named/myip.gr.hosts";
		update-policy { grant acme-key name _acme-challenge.myip.gr. TXT; };
	};
	zone "ddns.myip.gr" {
		type master;
		file "dynamic/ddns.myip.gr.hosts";
		update-policy { grant ddns-update wildcard *.ddns.myip.gr. A AAAA; };
	};
	zone "static.example" {
		type master;
		file "static.hosts";
	};
};
key "acme-key" { algorithm hmac-sha256; secret "a="; };
key "ddns-update" { algorithm hmac-sha256; secret "b="; };
`
	inv := Parse([]byte(d))
	if inv.Directory != "/var/named" {
		t.Fatalf("directory: %q", inv.Directory)
	}
	// absolute file stays as-is
	myip := find(inv, "myip.gr")
	if myip.Path != "/var/named/myip.gr.hosts" || myip.Kind() != "dynamic" {
		t.Fatalf("myip: path=%q kind=%q", myip.Path, myip.Kind())
	}
	// relative file resolved against directory
	ddns := find(inv, "ddns.myip.gr")
	if ddns.Path != "/var/named/dynamic/ddns.myip.gr.hosts" {
		t.Fatalf("ddns path: %q", ddns.Path)
	}
	// static (no update-policy) -> "static file"
	st := find(inv, "static.example")
	if st.Kind() != "static file" || st.Path != "/var/named/static.hosts" {
		t.Fatalf("static: kind=%q path=%q", st.Kind(), st.Path)
	}

	// the EL journal foot-gun: myip.gr is dynamic with its file directly in
	// /var/named (not dynamic/) -> warn; ddns.myip.gr under dynamic/ -> no warn.
	var warnMyip, warnDdns bool
	for _, f := range inv.Check("", "") {
		if f.Severity == Warn && f.Zone == "myip.gr" && contains(f.Message, "journal") {
			warnMyip = true
		}
		if f.Zone == "ddns.myip.gr" && contains(f.Message, "journal") {
			warnDdns = true
		}
	}
	if !warnMyip {
		t.Error("expected a journal-location warning for myip.gr (file directly in /var/named)")
	}
	if warnDdns {
		t.Error("ddns.myip.gr (under dynamic/) should NOT get the journal warning")
	}
}

func TestFileStatus(t *testing.T) {
	dir := t.TempDir()
	if FileStatus("", false) != "" {
		t.Fatal("empty path should be blank")
	}
	if FileStatus(dir+"/nope.hosts", false) != "missing" {
		t.Fatal("nonexistent file should be 'missing'")
	}
	f := dir + "/z.hosts"
	os.WriteFile(f, []byte("x"), 0o644)
	if FileStatus(f, false) != "ok" {
		t.Fatal("static existing file should be 'ok'")
	}
	if FileStatus(f, true) != "no journal yet" {
		t.Fatal("dynamic file without .jnl should be 'no journal yet'")
	}
	os.WriteFile(f+".jnl", []byte("j"), 0o644)
	if FileStatus(f, true) != "+journal" {
		t.Fatal("dynamic file with .jnl should be '+journal'")
	}
}

func TestUpdatePolicyLocal(t *testing.T) {
	// `update-policy local;` shorthand (no brace block) must be dynamic.
	d := `
view "_default" {
	zone "dyn.example" {
		type master;
		file "/var/named/dyn.hosts";
		update-policy local;
	};
};
`
	inv := Parse([]byte(d))
	z := find(inv, "dyn.example")
	if z == nil || !z.Dynamic || z.AllowUpdate != "policy (local)" {
		t.Fatalf("update-policy local should be dynamic: %+v", z)
	}
	// and it must NOT trigger the IP-only "no TSIG key" warning
	for _, f := range inv.Check("", "") {
		if f.Zone == "dyn.example" && f.Severity == Warn && contains(f.Message, "IP allow-update") {
			t.Fatal("policy-local wrongly flagged as IP-only")
		}
	}
}

func TestViewsDistinguishDuplicates(t *testing.T) {
	// Same zone name in two views -> two rows, each tagged with its view;
	// the implicit _default view is reported as "".
	d := `
view "internal" {
	zone "split.example" { type master; file "/i.hosts"; };
};
view "external" {
	zone "split.example" { type slave; file "/e.hosts"; };
};
view "_default" {
	zone "plain.example" { type master; file "/p.hosts"; };
};
`
	inv := Parse([]byte(d))
	if len(inv.Zones) != 3 {
		t.Fatalf("zones: %+v", inv.Zones)
	}
	var internal, external, plain *Zone
	for i := range inv.Zones {
		switch inv.Zones[i].View {
		case "internal":
			internal = &inv.Zones[i]
		case "external":
			external = &inv.Zones[i]
		case "":
			plain = &inv.Zones[i]
		}
	}
	if internal == nil || internal.Type != "master" {
		t.Fatalf("internal: %+v", internal)
	}
	if external == nil || external.Type != "slave" {
		t.Fatalf("external: %+v", external)
	}
	if plain == nil || plain.Name != "plain.example" {
		t.Fatalf("plain (default view tagged ''): %+v", plain)
	}
}
