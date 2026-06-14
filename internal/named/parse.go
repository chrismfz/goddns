package named

import (
	"regexp"
	"strings"
)

var (
	reType     = regexp.MustCompile(`(?m)\btype\s+([a-z-]+)\s*;`)
	reFile     = regexp.MustCompile(`(?m)\bfile\s+"([^"]*)"`)
	reAlgo     = regexp.MustCompile(`(?m)\balgorithm\s+([A-Za-z0-9-]+)\s*;`)
	reSecret   = regexp.MustCompile(`(?m)\bsecret\s+"([^"]*)"`)
	reGrant    = regexp.MustCompile(`(?m)\b(?:grant|deny)\s+(\S+)\s+`)
	reAllowKey = regexp.MustCompile(`\bkey\s+"?([^";{}\s]+)"?`)
)

type block struct{ name, body string }

// Parse turns `named-checkconf -p` output into an Inventory. It scans for
// zone/key blocks at any nesting depth (zones live inside the implicit
// view), so it is view-agnostic.
func Parse(dump []byte) *Inventory {
	src := string(dump)
	inv := &Inventory{}

	for _, b := range extractBlocks(src, "key") {
		inv.Keys = append(inv.Keys, Key{
			Name:      b.name,
			Algorithm: firstSubmatch(reAlgo, b.body),
			Secret:    firstSubmatch(reSecret, b.body),
		})
	}

	for _, b := range extractBlocks(src, "zone") {
		name := strings.TrimSuffix(b.name, ".")
		if name == "" {
			name = "." // root zone, don't strip to empty
		}
		z := Zone{
			Name: name,
			Type: firstSubmatch(reType, b.body),
			File: firstSubmatch(reFile, b.body),
		}
		if up, ok := namedBlock(b.body, "update-policy"); ok {
			for _, m := range reGrant.FindAllStringSubmatch(up, -1) {
				z.UpdateKeys = appendUniq(z.UpdateKeys, strings.TrimSuffix(m[1], "."))
			}
			if len(z.UpdateKeys) > 0 {
				z.Dynamic = true
				z.AllowUpdate = "policy"
			}
		}
		if au, ok := namedBlock(b.body, "allow-update"); ok {
			if isNone(au) {
				if z.AllowUpdate == "" {
					z.AllowUpdate = "none"
				}
			} else {
				z.Dynamic = true
				for _, m := range reAllowKey.FindAllStringSubmatch(au, -1) {
					z.UpdateKeys = appendUniq(z.UpdateKeys, strings.TrimSuffix(m[1], "."))
				}
				if z.AllowUpdate == "" {
					z.AllowUpdate = "addresses/keys"
				}
			}
		}
		inv.Zones = append(inv.Zones, z)
	}
	return inv
}

// extractBlocks finds every `<keyword> "<name>" ... { <body> }` at any depth.
func extractBlocks(src, keyword string) []block {
	re := regexp.MustCompile(`(?m)^\s*` + keyword + `\s+"([^"]+)"`)
	var out []block
	for _, loc := range re.FindAllStringSubmatchIndex(src, -1) {
		name := src[loc[2]:loc[3]]
		br := strings.IndexByte(src[loc[1]:], '{')
		if br < 0 {
			continue
		}
		if body, ok := readBalanced(src, loc[1]+br+1); ok {
			out = append(out, block{name: name, body: body})
		}
	}
	return out
}

// readBalanced returns the content from start (just past a '{') up to the
// matching '}', skipping quoted strings so braces inside strings don't count.
func readBalanced(src string, start int) (string, bool) {
	depth := 1
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '"':
			i++
			for i < len(src) && src[i] != '"' {
				if src[i] == '\\' {
					i++
				}
				i++
			}
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				return src[start:i], true
			}
		}
	}
	return "", false
}

// namedBlock returns the body of a `name { ... }` sub-block within body.
func namedBlock(body, name string) (string, bool) {
	re := regexp.MustCompile(`(?m)\b` + regexp.QuoteMeta(name) + `\s*\{`)
	loc := re.FindStringIndex(body)
	if loc == nil {
		return "", false
	}
	return readBalanced(body, loc[1])
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}

func appendUniq(xs []string, x string) []string {
	for _, e := range xs {
		if e == x {
			return xs
		}
	}
	return append(xs, x)
}

// isNone reports whether an allow-update body is effectively `{ none; }`.
func isNone(body string) bool {
	b := strings.ToLower(strings.Trim(strings.TrimSpace(body), `";`))
	b = strings.TrimSpace(strings.Trim(b, `"`))
	return b == "none" || b == `"none"`
}
