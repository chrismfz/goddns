// Package vhostmut is the Phase 2B proxy-vhost write layer: it manages
// goddns-owned drop-in fragments under proxy.d/ (one [proxy."host"] per file,
// named proxy.d/<host>.conf). It mirrors the recordmut invariant: goddns edits
// only what it owns — it writes and removes its own fragments, but NEVER
// rewrites the operator's hand-edited goddns.conf. A vhost defined in the base
// config (or in a fragment goddns didn't name <host>.conf) is reported as
// not-managed and left untouched.
//
// Writes are atomic (temp + rename + fsync). The daemon's reload poll watches
// proxy.d/, so a change applies within reload_interval — or immediately on
// `systemctl reload goddns` / SIGHUP.
package vhostmut

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/proxy"
)

// Editor manages proxy.d/ fragments next to a goddns.conf.
type Editor struct {
	ConfPath string // path to goddns.conf; proxy.d/ lives in the same directory
}

// Result describes a vhost mutation (or what one would do, for a preview).
type Result struct {
	Host     string
	File     string // the fragment path written/removed
	Action   string // "add" | "update" | "remove"
	Rule     config.ProxyRule
	Fragment string // rendered fragment text (for a set preview)
}

// Entry is one configured vhost as seen by List, with its provenance.
type Entry struct {
	Host    string
	Source  string // fragment path, or "(goddns.conf)" for a base-config vhost
	Managed bool   // true => goddns owns the proxy.d/<host>.conf fragment
	Rule    config.ProxyRule
}

func (e *Editor) dir() string          { return filepath.Join(filepath.Dir(e.ConfPath), "proxy.d") }
func (e *Editor) frag(h string) string { return filepath.Join(e.dir(), h+".conf") }

// normalize lowercases and strips a trailing dot so host comparisons match
// however the operator spelled the key (DNS is case-insensitive).
func normalize(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// Set creates or replaces the goddns-managed fragment for host. It refuses if
// host is defined in goddns.conf or in a fragment goddns doesn't own (so it
// never collides with a hand-managed vhost — which would also fail the reload).
func (e *Editor) Set(host string, rule config.ProxyRule) (*Result, error) {
	res, err := e.PreviewSet(host, rule)
	if err != nil {
		return nil, err
	}
	if err := writeFragment(res.File, res.Fragment); err != nil {
		return nil, err
	}
	return res, nil
}

// PreviewSet validates and resolves ownership without writing anything.
func (e *Editor) PreviewSet(host string, rule config.ProxyRule) (*Result, error) {
	if e.ConfPath == "" {
		return nil, fmt.Errorf("no config path: don't know where proxy.d/ lives")
	}
	host = normalize(host)
	if err := proxy.ValidateRule(host, rule); err != nil {
		return nil, err
	}
	rule.Allow = trimAll(rule.Allow)
	rule.BasicAuth = trimAll(rule.BasicAuth)
	rule.Upstream = strings.TrimSpace(rule.Upstream)

	managed, conflict, err := e.ownership(host)
	if err != nil {
		return nil, err
	}
	if conflict != "" {
		return nil, fmt.Errorf("vhost %q is defined in %s — goddns won't override it; edit it there", host, conflict)
	}
	action := "add"
	if managed {
		action = "update"
	}
	return &Result{
		Host: host, File: e.frag(host), Action: action,
		Rule: rule, Fragment: renderFragment(host, rule),
	}, nil
}

// Remove deletes the goddns-managed fragment for host.
func (e *Editor) Remove(host string) (*Result, error) {
	res, err := e.PreviewRemove(host)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(res.File); err != nil {
		return nil, err
	}
	return res, nil
}

// PreviewRemove validates that host is a goddns-managed fragment, without
// deleting it.
func (e *Editor) PreviewRemove(host string) (*Result, error) {
	if e.ConfPath == "" {
		return nil, fmt.Errorf("no config path: don't know where proxy.d/ lives")
	}
	host = normalize(host)
	// Validate the host shape before it ever becomes a filesystem path — the
	// fragment filename is derived from it, so traversal-safety is explicit,
	// not a lucky side effect of the glob never matching.
	if !proxy.ValidHost(host) {
		return nil, fmt.Errorf("invalid vhost %q", host)
	}
	managed, conflict, err := e.ownership(host)
	if err != nil {
		return nil, err
	}
	if !managed {
		if conflict != "" {
			return nil, fmt.Errorf("vhost %q is defined in %s — goddns doesn't manage it; remove it there", host, conflict)
		}
		return nil, fmt.Errorf("no goddns-managed vhost %q (looked for %s)", host, e.frag(host))
	}
	return &Result{Host: host, File: e.frag(host), Action: "remove"}, nil
}

// List returns every configured vhost (base config + every fragment) with its
// provenance, sorted by host.
func (e *Editor) List() ([]Entry, error) {
	base, err := decodeProxy(e.ConfPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", e.ConfPath, err)
	}
	var out []Entry
	for host, rule := range base {
		out = append(out, Entry{Host: normalize(host), Source: "(goddns.conf)", Managed: false, Rule: rule})
	}
	files, err := e.fragmentFiles()
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		rules, err := decodeProxy(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		for host, rule := range rules {
			h := normalize(host)
			out = append(out, Entry{Host: h, Source: f, Managed: f == e.frag(h), Rule: rule})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}

// ownership reports whether goddns owns host's fragment (proxy.d/<host>.conf
// exists and defines it) and, if host is ALSO defined somewhere goddns doesn't
// own, where (conflict). A managed host with no conflict is safe to edit; a
// conflict means refuse.
func (e *Editor) ownership(host string) (managed bool, conflict string, err error) {
	base, err := decodeProxy(e.ConfPath)
	if err != nil {
		return false, "", fmt.Errorf("read %s: %w", e.ConfPath, err)
	}
	for k := range base {
		if normalize(k) == host {
			conflict = "goddns.conf"
		}
	}
	files, err := e.fragmentFiles()
	if err != nil {
		return false, "", err
	}
	own := e.frag(host)
	for _, f := range files {
		rules, err := decodeProxy(f)
		if err != nil {
			return false, "", fmt.Errorf("read %s: %w", f, err)
		}
		definesHost := false
		for k := range rules {
			if normalize(k) == host {
				definesHost = true
			}
		}
		switch {
		case f == own:
			// goddns owns proxy.d/<host>.conf ONLY if it is a single-host
			// fragment for exactly this host — the shape goddns renders.
			// A hand-made fragment that happens to share the name but defines
			// other/multiple hosts is NOT ours: overwriting or deleting it
			// would silently destroy those vhosts, so treat it as a conflict.
			if len(rules) == 1 && definesHost {
				managed = true
			} else {
				conflict = relName(own)
			}
		case definesHost:
			// host is defined in some other fragment we don't own.
			conflict = relName(f)
		}
	}
	return managed, conflict, nil
}

func (e *Editor) fragmentFiles() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(e.dir(), "*.conf"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// decodeProxy reads only the [proxy."..."] table from a TOML file (the rest is
// ignored). A missing file is not an error — it yields no vhosts.
func decodeProxy(path string) (map[string]config.ProxyRule, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	var f struct {
		Proxy map[string]config.ProxyRule `toml:"proxy"`
	}
	if _, err := toml.DecodeFile(path, &f); err != nil {
		return nil, err
	}
	return f.Proxy, nil
}

// renderFragment renders a clean, deterministic TOML fragment for one vhost,
// with a managed-by marker. Only non-empty/non-zero optional fields are emitted.
func renderFragment(host string, pr config.ProxyRule) string {
	var b strings.Builder
	b.WriteString("# Managed by goddns — edit via `goddns vhost` or the admin UI.\n")
	b.WriteString("# Hand-editing is fine (goddns reads it back); keep one vhost per file.\n\n")
	fmt.Fprintf(&b, "[proxy.%q]\n", host)
	fmt.Fprintf(&b, "upstream        = %q\n", pr.Upstream)
	fmt.Fprintf(&b, "upstream_verify = %t\n", pr.UpstreamVerify)
	fmt.Fprintf(&b, "preserve_host   = %t\n", pr.PreserveHost)
	if pr.BMCCompat {
		fmt.Fprintf(&b, "bmc_compat      = %t\n", pr.BMCCompat)
	}
	if len(pr.ConsolePorts) > 0 {
		parts := make([]string, len(pr.ConsolePorts))
		for i, p := range pr.ConsolePorts {
			parts[i] = strconv.Itoa(p)
		}
		fmt.Fprintf(&b, "console_ports   = [%s]\n", strings.Join(parts, ", "))
	}
	if len(pr.Allow) > 0 {
		fmt.Fprintf(&b, "allow           = %s\n", tomlStrArray(pr.Allow))
	}
	if pr.RateLimit > 0 {
		fmt.Fprintf(&b, "rate_limit      = %d\n", pr.RateLimit)
	}
	if len(pr.BasicAuth) > 0 {
		fmt.Fprintf(&b, "basic_auth      = %s\n", tomlStrArray(pr.BasicAuth))
	}
	return b.String()
}

func tomlStrArray(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func trimAll(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// relName shortens an absolute fragment path to proxy.d/<file> for messages.
func relName(f string) string {
	return filepath.Join("proxy.d", filepath.Base(f))
}

// writeFragment writes content to path atomically (temp + rename + fsync),
// creating proxy.d/ if needed. Fragments may carry basic_auth bcrypt hashes, so
// they are mode 0640 like goddns.conf.
func writeFragment(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".vhost-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	// Match the fragment's group to proxy.d/ so the goddns daemon can read what
	// the CLI wrote. Without this, `sudo goddns vhost set` (run as root) leaves a
	// root:root 0640 file the daemon — which runs as the goddns user — can't
	// read, crash-looping it at the next reload. Best-effort: a no-op when the
	// writer already matches (e.g. the daemon itself), and harmless if it fails.
	if gid := dirGID(dir); gid >= 0 {
		_ = tmp.Chown(-1, gid)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// dirGID returns the group owner of dir, or -1 if it can't be determined.
func dirGID(dir string) int {
	fi, err := os.Stat(dir)
	if err != nil {
		return -1
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Gid)
	}
	return -1
}
