package main

import (
	"flag"
	"fmt"
	"os/exec"
	"strings"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/tsig"
)

// cmdRotateKey rotates one TSIG key in goddns's own key file (the single source
// of truth that named also includes). It is transactional: on any failure it
// rolls the file back to the previous secret so named, the file, and the daemon
// stay consistent. Flow: write new secret -> rndc reconfig -> self-test that
// named accepts the new key on a local zone -> reload the daemon. Other keys in
// the file are untouched.
func cmdRotateKey(args []string) {
	fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "config file")
	noReconfig := fs.Bool("no-reconfig", false, "don't run 'rndc reconfig'/reload (print the steps instead)")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("%v", err)
	}
	if cfg.TSIGKeysFile == "" {
		fatal("rotate-key requires tsig_keys_file (goddns's own single-source key file, also included by named.conf)")
	}
	name := fs.Arg(0)
	if name == "" {
		name = cfg.TSIGName
	}

	keys, err := tsig.LoadFile(cfg.TSIGKeysFile)
	if err != nil {
		fatal("read %s: %v", cfg.TSIGKeysFile, err)
	}
	k := tsig.Find(keys, name)
	if k == nil {
		fatal("key %q not found in %s", name, cfg.TSIGKeysFile)
	}
	oldSecret := k.Secret

	newSecret, err := tsig.GenSecret()
	if err != nil {
		fatal("generate secret: %v", err)
	}
	k.Secret = newSecret
	if err := tsig.WriteFile(cfg.TSIGKeysFile, keys); err != nil {
		fatal("write %s: %v", cfg.TSIGKeysFile, err)
	}
	fmt.Printf("rotated key %q in %s\n", name, cfg.TSIGKeysFile)

	// rollback restores the previous secret and re-points named at it, so a
	// failed rotation leaves everything as it was.
	rollback := func(reason string) {
		k.Secret = oldSecret
		if err := tsig.WriteFile(cfg.TSIGKeysFile, keys); err != nil {
			fatal("%s — AND rollback write failed (%v); the key file holds the NEW secret. "+
				"Run 'rndc reconfig' and reload goddns to converge.", reason, err)
		}
		_ = exec.Command("rndc", "reconfig").Run() // best-effort: restore named to the old key
		fatal("%s — rolled back to the previous key (no change).", reason)
	}

	if *noReconfig {
		fmt.Println("next: run 'rndc reconfig', then reload goddns so it re-reads the key file.")
		return
	}

	if out, err := exec.Command("rndc", "reconfig").CombinedOutput(); err != nil {
		rollback(fmt.Sprintf("rndc reconfig failed: %v (%s)", err, strings.TrimSpace(string(out))))
	}
	fmt.Println("rndc reconfig: ok")

	// self-test: the NEW key must be accepted by named on a zone it serves.
	switch zone := pickProbeZone(cfg.NamedConf, name); {
	case zone == "":
		fmt.Println("self-test: skipped (no local zone found to probe — verify the key manually)")
	default:
		u, err := ddns.NewRFC2136(cfg.DNSServer, name, k.Algo, newSecret)
		if err != nil {
			rollback(fmt.Sprintf("self-test setup failed: %v", err))
		}
		if err := u.Verify(zone); err != nil {
			rollback(fmt.Sprintf("self-test FAILED — named did not accept the new key (%v); "+
				"check that named.conf includes %s", err, cfg.TSIGKeysFile))
		}
		fmt.Printf("self-test: named accepts the new key on %s ✓\n", zone)
	}

	// Apply to the running daemon now; it also watches the key file as a fallback.
	if out, err := exec.Command("systemctl", "reload", "goddns").CombinedOutput(); err != nil {
		fmt.Printf("note: reload goddns to apply immediately (systemctl reload goddns) — otherwise it "+
			"picks up the new secret within reload_interval. [%s]\n", strings.TrimSpace(string(out)))
	} else {
		fmt.Println("reloaded goddns ✓")
	}
}

// pickProbeZone returns a zone the server is authoritative for to self-test a
// key against — preferring one the key is granted on, else any master zone.
func pickProbeZone(namedConf, keyName string) string {
	data, err := named.CheckConf(namedConf)
	if err != nil {
		return ""
	}
	inv := named.Parse(data)
	kn := strings.TrimSuffix(keyName, ".")
	for _, z := range inv.UserZones() {
		for _, gk := range z.UpdateKeys {
			if gk == kn {
				return z.Name
			}
		}
	}
	for _, z := range inv.UserZones() {
		switch z.Kind() {
		case "static file", "dynamic":
			return z.Name
		}
	}
	return ""
}
