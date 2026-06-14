package named

import (
	"regexp"
	"strings"
)

var (
	reType   = regexp.MustCompile(`(?m)\btype\s+([a-z-]+)\s*;`)
	reFile   = regexp.MustCompile(`(?m)\bfile\s+"([^"]*)"`)
	reAlgo   = regexp.MustCompile(`(?m)\balgorithm\s+([A-Za-z0-9-]+)\s*;`)
	reSecret = regexp.MustCompile(`(?m)\bsecret\s+"([^"]*)"`)
	// named-checkconf -p quotes the grant identity, e.g. grant "ddns-update."
	// — capture the name without the surrounding quotes (the trailing dot is
	// stripped separately).
	reGrant     = regexp.MustCompile(`(?m)\b(?:grant|deny)\s+"?([^"\s]+)"?`)
	reAllowKey  = regexp.MustCompile(`\bkey\s+"?([^";{}\s]+)"?`)
	reDirectory = regexp.MustCompile(`(?m)^\s*directory\s+"([^"]*)"\s*;`)
	rePolicyLcl = regexp.MustCompile(`(?m)\bupdate-policy\s+local\s*;`) // BIND shorthand, no brace block
)

// resolvePath makes an absolute zone-file path from a (possibly relative)
// file and the directory option.
func resolvePath(dir, file string) string {
	if file == "" || strings.HasPrefix(file, "/") || dir == "" {
		return file
	}
	return strings.TrimRight(dir, "/") + "/" + file
}

type block struct {
	name, body string
	start, end int // byte offsets in the source, for view containment
}

// Parse turns `named-checkconf -p` output into an Inventory. It scans for
// zone/key blocks at any nesting depth; each zone is tagged with the view
// that encloses it (so split-horizon configs aren't collapsed into
// confusing duplicates).
func Parse(dump []byte) *Inventory {
	src := string(dump)
	inv := &Inventory{Directory: firstSubmatch(reDirectory, src)}
	views := extractBlocks(src, "view")

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
		file := firstSubmatch(reFile, b.body)
		z := Zone{
			Name: name,
			View: viewOf(b.start, views),
			Type: firstSubmatch(reType, b.body),
			File: file,
			Path: resolvePath(inv.Directory, file),
		}
		if up, ok := namedBlock(b.body, "update-policy"); ok {
			for _, m := range reGrant.FindAllStringSubmatch(up, -1) {
				z.UpdateKeys = appendUniq(z.UpdateKeys, strings.TrimSuffix(m[1], "."))
			}
			z.Dynamic = true
			z.AllowUpdate = "policy"
		} else if rePolicyLcl.MatchString(b.body) {
			// `update-policy local;` — dynamic via the local session key,
			// no external TSIG key listed.
			z.Dynamic = true
			z.AllowUpdate = "policy (local)"
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

// extractBlocks finds every `<keyword> "<name>" ... { <body> }` at any depth,
// recording each block's [start,end) byte range in src.
func extractBlocks(src, keyword string) []block {
	re := regexp.MustCompile(`(?m)^\s*` + keyword + `\s+"([^"]+)"`)
	var out []block
	for _, loc := range re.FindAllStringSubmatchIndex(src, -1) {
		name := src[loc[2]:loc[3]]
		br := strings.IndexByte(src[loc[1]:], '{')
		if br < 0 {
			continue
		}
		if body, end, ok := readBalanced(src, loc[1]+br+1); ok {
			out = append(out, block{name: name, body: body, start: loc[0], end: end})
		}
	}
	return out
}

// viewOf returns the name of the view block whose range contains offset (the
// implicit "_default" view is reported as "" so it isn't shown as noise).
func viewOf(offset int, views []block) string {
	for _, v := range views {
		if offset > v.start && offset < v.end {
			if v.name == "_default" {
				return ""
			}
			return v.name
		}
	}
	return ""
}

// readBalanced returns the content from start (just past a '{') up to the
// matching '}' and the index of that '}', skipping quoted strings so braces
// inside strings don't count.
func readBalanced(src string, start int) (string, int, bool) {
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
				return src[start:i], i, true
			}
		}
	}
	return "", 0, false
}

// namedBlock returns the body of a `name { ... }` sub-block within body.
func namedBlock(body, name string) (string, bool) {
	re := regexp.MustCompile(`(?m)\b` + regexp.QuoteMeta(name) + `\s*\{`)
	loc := re.FindStringIndex(body)
	if loc == nil {
		return "", false
	}
	b, _, ok := readBalanced(body, loc[1])
	return b, ok
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
