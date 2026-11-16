package main

import (
	"flag"
	"reflect"
	"testing"
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
