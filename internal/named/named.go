// Package named provides READ-ONLY introspection of a BIND configuration:
// it lists zones, flags which are dynamic, lists TSIG keys, and cross-checks
// that dynamic zones reference keys that actually exist (and, optionally,
// that goddns's own TSIG key matches the one in named.conf).
//
// It never edits anything. To stay robust it does not parse raw named.conf
// (includes/views/comments make that fragile); instead it parses the output
// of `named-checkconf -p`, i.e. BIND's OWN parser, already normalised with
// includes resolved.
package named

import (
	"fmt"
	"os/exec"
	"strings"
)

// Zone is one zone clause from the parsed config.
type Zone struct {
	Name        string   // trailing dot stripped
	Type        string   // master, slave, forward, hint, stub, ...
	File        string   // zone file path as configured
	Dynamic     bool     // accepts dynamic updates (update-policy or non-none allow-update)
	UpdateKeys  []string // TSIG key names granted update rights
	AllowUpdate string   // "policy", "none", "addresses/keys", or "" if unset
}

// Key is a TSIG key definition. Secret is captured for the optional match
// check only and is NEVER printed or logged.
type Key struct {
	Name      string
	Algorithm string
	Secret    string
}

// Inventory is the parsed, read-only view of the BIND config.
type Inventory struct {
	Zones []Zone
	Keys  []Key
}

// Severity of a Finding.
type Severity int

const (
	OK Severity = iota
	Info
	Warn
	Error
)

func (s Severity) String() string {
	switch s {
	case OK:
		return "ok"
	case Info:
		return "info"
	case Warn:
		return "warn"
	default:
		return "error"
	}
}

// Finding is one result of the consistency checks.
type Finding struct {
	Severity Severity
	Zone     string // optional
	Message  string
}

// checkConfCmd is the binary to run; a var so tests can stub it.
var checkConfCmd = "named-checkconf"

// CheckConf runs `named-checkconf -p [namedConf]` and returns the normalised
// config dump. A broken config surfaces as an error with named's own message.
func CheckConf(namedConf string) ([]byte, error) {
	args := []string{"-p"}
	if namedConf != "" {
		args = append(args, namedConf)
	}
	out, err := exec.Command(checkConfCmd, args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("%s -p: %s", checkConfCmd, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("%s -p: %w", checkConfCmd, err)
	}
	return out, nil
}

// KeyNames returns the defined key names as a set.
func (inv *Inventory) keySet() map[string]bool {
	m := make(map[string]bool, len(inv.Keys))
	for _, k := range inv.Keys {
		m[k.Name] = true
	}
	return m
}

// UserZones returns zones excluding BIND's automatic empty zones (the
// RFC1918/localhost reverse zones that all use the named.empty file).
func (inv *Inventory) UserZones() []Zone {
	var out []Zone
	for _, z := range inv.Zones {
		if !z.builtinEmpty() {
			out = append(out, z)
		}
	}
	return out
}

func (z Zone) builtinEmpty() bool {
	return z.Type == "master" &&
		(z.File == "named.empty" || strings.HasSuffix(z.File, "/named.empty"))
}
