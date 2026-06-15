package main

import (
	"flag"
	"fmt"
	"os/exec"
	"time"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/tsig"
)

// cmdRotateKey rotates one TSIG key in goddns's own key file (the single source
// of truth that named also includes): generate a new secret, rewrite that one
// key block, run `rndc reconfig`, and self-test that named accepts the new key.
// The running daemon picks up the new secret on its next reload (it watches the
// key file). Other keys in the file are left untouched.
func cmdRotateKey(args []string) {
	fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "config file")
	noReconfig := fs.Bool("no-reconfig", false, "don't run 'rndc reconfig' (print the step instead)")
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

	newSecret, err := tsig.GenSecret()
	if err != nil {
		fatal("generate secret: %v", err)
	}
	k.Secret = newSecret
	if err := tsig.WriteFile(cfg.TSIGKeysFile, keys); err != nil {
		fatal("write %s: %v", cfg.TSIGKeysFile, err)
	}
	fmt.Printf("rotated key %q in %s\n", name, cfg.TSIGKeysFile)

	if *noReconfig {
		fmt.Printf("next: rndc reconfig   (then goddns picks up the new secret on its next reload)\n")
		return
	}
	if out, err := exec.Command("rndc", "reconfig").CombinedOutput(); err != nil {
		fatal("rndc reconfig failed: %v (%s)\nThe key file IS updated — run 'rndc reconfig' by hand.", err, out)
	}
	fmt.Println("rndc reconfig: ok")

	if err := tsigSelfTest(cfg.DNSServer, name, k.Algo, newSecret); err != nil {
		fatal("self-test FAILED — named did not accept the new key: %v\nCheck that named.conf includes %s.", err, cfg.TSIGKeysFile)
	}
	fmt.Println("self-test: named accepts the new key ✓")
	fmt.Println("the running goddns daemon picks up the new secret automatically on its next reload (it watches the key file).")
}

// tsigSelfTest sends a TSIG-signed query with the new secret; a nil error means
// both ends (named and us) agree on the key. Retries briefly to let reconfig settle.
func tsigSelfTest(server, keyName, algo, secret string) error {
	a, err := ddns.AlgoToDNS(algo)
	if err != nil {
		return err
	}
	if server == "" {
		server = "127.0.0.1:53"
	}
	key := dns.Fqdn(keyName)
	c := &dns.Client{TsigSecret: map[string]string{key: secret}, Timeout: 4 * time.Second}
	var last error
	for i := 0; i < 3; i++ {
		m := new(dns.Msg)
		m.SetQuestion(".", dns.TypeSOA)
		m.SetTsig(key, a, 300, time.Now().Unix())
		if _, _, err := c.Exchange(m, server); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	return last
}
