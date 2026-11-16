// Package zonemgr creates and deletes the zones goddns owns: static master
// zones whose stanzas live in ONE managed include file (managed_include, e.g.
// /etc/named/goddns-zones.conf) and whose zone files live in managed_zone_dir.
//
// goddns never edits named.conf itself. The operator adds one line,
//
//	include "/etc/named/goddns-zones.conf";
//
// and goddns writes only that file — which stays a plain, hand-editable
// named.conf fragment: add or remove a stanza with vi and goddns sees it,
// because what exists is always read back from BIND (named-checkconf -p) and
// from this file, never from a database. Zones defined anywhere else are the
// operator's (or a panel's): goddns edits their records where allowed, but
// never creates or deletes them.
//
// Every change is checked before BIND sees it and undone if the check fails:
// named-checkzone on the new file, named-checkconf on the whole config, and
// only then rndc reconfig. A deleted zone's file is renamed aside
// (<file>.deleted-<UTC time>), never removed.
package zonemgr

import (
	"fmt"
	"os"
	"strings"
)

// Stanza is one `zone "name" { ... };` block found in the managed include.
type Stanza struct {
	Name       string // as written, lowercased, without a trailing dot
	File       string // its `file "..."` value ("" if none)
	Start, End int    // byte span in the include, End exclusive, incl. the trailing ';'
}

// ParseInclude finds the zone stanzas in a named.conf fragment. It skips
// comments (#, //, /* */) and quoted strings, and matches braces, so a stanza
// reformatted by hand (multi-line, extra options) is still found whole.
// Anything it can't read as a zone stanza is left alone.
func ParseInclude(src string) ([]Stanza, error) {
	var out []Stanza
	i, n := 0, len(src)
	for i < n {
		j := skipSpaceComments(src, i)
		if j >= n {
			break
		}
		i = j
		if !strings.HasPrefix(src[i:], "zone") || (i+4 < n && isIdent(src[i+4])) {
			// not a zone statement: skip to the end of this statement
			end, err := skipStatement(src, i)
			if err != nil {
				return nil, err
			}
			i = end
			continue
		}
		start := i
		k := skipSpaceComments(src, i+4)
		if k >= n || src[k] != '"' {
			return nil, fmt.Errorf("managed include: zone statement without a quoted name at byte %d", start)
		}
		q := strings.IndexByte(src[k+1:], '"')
		if q < 0 {
			return nil, fmt.Errorf("managed include: unterminated zone name at byte %d", k)
		}
		name := strings.TrimSuffix(strings.ToLower(src[k+1:k+1+q]), ".")
		end, err := skipStatement(src, k+1+q+1)
		if err != nil {
			return nil, err
		}
		out = append(out, Stanza{Name: name, File: fileOption(src[start:end]), Start: start, End: end})
		i = end
	}
	return out, nil
}

// fileOption pulls the `file "..."` value out of a stanza body.
func fileOption(stanza string) string {
	i := 0
	for {
		j := strings.Index(stanza[i:], "file")
		if j < 0 {
			return ""
		}
		j += i
		if (j == 0 || !isIdent(stanza[j-1])) && j+4 < len(stanza) && !isIdent(stanza[j+4]) {
			k := skipSpaceComments(stanza, j+4)
			if k < len(stanza) && stanza[k] == '"' {
				if q := strings.IndexByte(stanza[k+1:], '"'); q >= 0 {
					return stanza[k+1 : k+1+q]
				}
			}
		}
		i = j + 4
	}
}

func isIdent(c byte) bool {
	return c == '-' || c == '_' || c == '.' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// skipSpaceComments returns the index of the next byte that is neither
// whitespace nor inside a comment.
func skipSpaceComments(s string, i int) int {
	for i < len(s) {
		switch {
		case s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r':
			i++
		case s[i] == '#' || strings.HasPrefix(s[i:], "//"):
			nl := strings.IndexByte(s[i:], '\n')
			if nl < 0 {
				return len(s)
			}
			i += nl + 1
		case strings.HasPrefix(s[i:], "/*"):
			e := strings.Index(s[i+2:], "*/")
			if e < 0 {
				return len(s)
			}
			i += 2 + e + 2
		default:
			return i
		}
	}
	return i
}

// skipStatement returns the index just past the ';' that ends the statement
// starting at i, matching braces and skipping strings and comments.
func skipStatement(s string, i int) (int, error) {
	depth := 0
	for i < len(s) {
		j := skipSpaceComments(s, i)
		if j >= len(s) {
			break
		}
		i = j
		switch s[i] {
		case '"':
			q := strings.IndexByte(s[i+1:], '"')
			if q < 0 {
				return 0, fmt.Errorf("managed include: unterminated string")
			}
			i += q + 2
			continue
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				return 0, fmt.Errorf("managed include: unbalanced '}' at byte %d", i)
			}
		case ';':
			if depth == 0 {
				return i + 1, nil
			}
		}
		i++
	}
	if depth != 0 {
		return 0, fmt.Errorf("managed include: unbalanced braces")
	}
	return len(s), nil
}

// ManagedZones returns the zone names in the managed include at path. A
// missing file is no zones (nothing created yet); a file that can't be
// parsed is an error, so a caller never treats a broken file as "empty".
func ManagedZones(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	st, err := ParseInclude(string(b))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(st))
	for _, s := range st {
		out = append(out, s.Name)
	}
	return out, nil
}

// IncludeReferenced reports whether named.conf (or any file it includes,
// recursively) has an `include "<path>";` for the managed include. It reads
// the operator's files textually and only for this one fact.
func IncludeReferenced(namedConf, include string) (bool, error) {
	seen := map[string]bool{}
	var walk func(p string) (bool, error)
	walk = func(p string) (bool, error) {
		if seen[p] || len(seen) > 64 {
			return false, nil
		}
		seen[p] = true
		b, err := os.ReadFile(p)
		if err != nil {
			if p == namedConf {
				return false, err
			}
			return false, nil // an unreadable sub-include can't hold ours
		}
		src := string(b)
		for i := 0; i < len(src); {
			j := skipSpaceComments(src, i)
			if j >= len(src) {
				break
			}
			if strings.HasPrefix(src[j:], "include") && (j+7 >= len(src) || !isIdent(src[j+7])) {
				k := skipSpaceComments(src, j+7)
				if k < len(src) && src[k] == '"' {
					if q := strings.IndexByte(src[k+1:], '"'); q >= 0 {
						target := src[k+1 : k+1+q]
						if target == include {
							return true, nil
						}
						if ok, _ := walk(target); ok {
							return true, nil
						}
					}
				}
			}
			end, err := skipStatement(src, j)
			if err != nil {
				return false, nil
			}
			i = end
		}
		return false, nil
	}
	return walk(namedConf)
}
