package main

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
)

func TestFlagsFirst(t *testing.T) {
	for _, c := range []struct{ in, want []string }{
		{[]string{"alice", "-role", "admin"}, []string{"-role", "admin", "--", "alice"}},
		{[]string{"-role=admin", "alice"}, []string{"-role=admin", "--", "alice"}},
		{[]string{"alice", "-config", "/x.conf", "-role", "user"}, []string{"-config", "/x.conf", "-role", "user", "--", "alice"}},
		{[]string{"alice", "admin"}, []string{"--", "alice", "admin"}},
		{[]string{"--", "-weird"}, []string{"--", "-weird"}},
	} {
		if got := flagsFirst(c.in, "-role", "-config"); !reflect.DeepEqual(got, c.want) {
			t.Errorf("flagsFirst(%v) = %v, want %v", c.in, got, c.want)
		}
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.String("role", "", "")
		fs.String("config", "", "")
		if err := fs.Parse(flagsFirst(c.in, "-role", "-config")); err != nil {
			t.Errorf("parse %v: %v", c.in, err)
		}
	}
}

func TestCLIAuditGoesToLogFile(t *testing.T) {
	dir := t.TempDir()
	lf := filepath.Join(dir, "goddns.log")
	cfg := &config.Config{LogFile: lf}
	// not created when missing
	logf, done := cliAuditLog(cfg)
	logf("admin-audit user=cli:t peer=local user-add name=x role=user")
	done()
	if _, err := os.Stat(lf); !os.IsNotExist(err) {
		t.Fatal("the CLI created the daemon's log file")
	}
	os.WriteFile(lf, []byte("daemon line\n"), 0o640)
	logf, done = cliAuditLog(cfg)
	logf("admin-audit user=cli:t peer=local user-del name=x")
	done()
	b, _ := os.ReadFile(lf)
	if !strings.HasPrefix(string(b), "daemon line\n") || !strings.Contains(string(b), "user-del name=x") {
		t.Fatalf("log file: %q", b)
	}
}
