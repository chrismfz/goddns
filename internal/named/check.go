package named

import (
	"crypto/subtle"
	"strings"
)

// Check cross-checks the inventory for the common DDNS foot-guns and, when
// goddns's own TSIG name/secret are supplied, whether they match a key in
// named.conf. Pass empty strings to skip the goddns-key comparison.
func (inv *Inventory) Check(goddnsTSIGName, goddnsTSIGSecret string) []Finding {
	var f []Finding
	keys := inv.keySet()
	granted := map[string]bool{} // keys that are granted on at least one zone

	for _, z := range inv.UserZones() {
		for _, k := range z.UpdateKeys {
			granted[k] = true
			if !keys[k] {
				f = append(f, Finding{Error, z.Name,
					"grants update key '" + k + "' which is not defined in named.conf (updates will fail)"})
			}
		}
		// Only warn for pure IP-based allow-update (no key). Don't warn for
		// `update-policy local;` (localhost session key — a safe special case).
		if z.Dynamic && len(z.UpdateKeys) == 0 && z.AllowUpdate == "addresses/keys" {
			f = append(f, Finding{Warn, z.Name,
				"is dynamic via IP allow-update only (no TSIG key) — anyone from those IPs can update it"})
		}
		// Predict the EL journal foot-gun: a dynamic zone whose file sits
		// directly in the BIND directory (not a writable subdir like
		// dynamic/) often can't create its .jnl on EL, where /var/named is
		// root:named and not group-writable.
		if z.Dynamic && (z.Type == "master" || z.Type == "primary") &&
			z.Path != "" && inv.Directory != "" &&
			dirOf(z.Path) == strings.TrimRight(inv.Directory, "/") {
			f = append(f, Finding{Warn, z.Name,
				"dynamic zone file is directly in " + inv.Directory + " — on EL the journal often can't be created there; conventionally dynamic zone files live under " + strings.TrimRight(inv.Directory, "/") + "/dynamic/"})
		}
	}

	for _, k := range inv.Keys {
		if k.Name == "rndc-key" || k.Name == "session-key" {
			continue // control keys, not for zone updates
		}
		if !granted[k.Name] {
			f = append(f, Finding{Info, "",
				"key '" + k.Name + "' is defined but not granted update rights on any zone"})
		}
	}

	if goddnsTSIGName != "" {
		name := goddnsTSIGName
		if name[len(name)-1] == '.' {
			name = name[:len(name)-1]
		}
		var match *Key
		for i := range inv.Keys {
			if inv.Keys[i].Name == name {
				match = &inv.Keys[i]
				break
			}
		}
		switch {
		case match == nil:
			f = append(f, Finding{Error, "",
				"goddns tsig_name '" + name + "' is not a key in named.conf (updates will be REFUSED)"})
		case goddnsTSIGSecret != "" && subtle.ConstantTimeCompare([]byte(match.Secret), []byte(goddnsTSIGSecret)) != 1:
			f = append(f, Finding{Error, "",
				"goddns tsig_secret does NOT match the '" + name + "' key in named.conf (updates will fail with NOTAUTH)"})
		case !granted[name]:
			f = append(f, Finding{Warn, "",
				"goddns key '" + name + "' matches named.conf but is not granted on any zone (updates will be REFUSED)"})
		default:
			f = append(f, Finding{OK, "",
				"goddns TSIG key '" + name + "' matches named.conf and is granted update rights"})
		}
	}
	return f
}

// dirOf returns the directory portion of a path (no trailing slash).
func dirOf(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}
