// Package tsig manages goddns's own TSIG keyring: a goddns-owned file holding
// one or more `key "name" { algorithm ...; secret "..."; };` blocks, included
// once by named.conf. It is the single source of truth for the keys goddns
// signs with — both goddns and BIND read it — so a rotation rewrites exactly
// one file and both ends stay in sync. Supports multiple keys (multiple
// domains/zones) from the start.
package tsig

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Key is one TSIG key: name, named.conf algorithm, and base64 secret.
type Key struct {
	Name   string
	Algo   string
	Secret string
}

var (
	reBlock  = regexp.MustCompile(`(?s)key\s+"([^"]+)"\s*\{(.*?)\}`)
	reAlgo   = regexp.MustCompile(`algorithm\s+"?([A-Za-z0-9-]+)"?\s*;`)
	reSecret = regexp.MustCompile(`secret\s+"([^"]+)"`)
)

// Parse extracts every key block from a key-file's bytes. Key blocks have no
// nested braces, so a non-greedy body match is sufficient.
func Parse(data []byte) []Key {
	var keys []Key
	for _, m := range reBlock.FindAllSubmatch(data, -1) {
		k := Key{Name: strings.TrimSuffix(string(m[1]), ".")}
		if a := reAlgo.FindSubmatch(m[2]); a != nil {
			k.Algo = string(a[1])
		}
		if s := reSecret.FindSubmatch(m[2]); s != nil {
			k.Secret = string(s[1])
		}
		keys = append(keys, k)
	}
	return keys
}

// LoadFile reads and parses a key file.
func LoadFile(path string) ([]Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data), nil
}

// Find returns the key with the given name (trailing dot ignored), or nil.
func Find(keys []Key, name string) *Key {
	name = strings.TrimSuffix(name, ".")
	for i := range keys {
		if strings.TrimSuffix(keys[i].Name, ".") == name {
			return &keys[i]
		}
	}
	return nil
}

// Render serialises a keyring back to named.conf key-block syntax.
func Render(keys []Key) string {
	var b strings.Builder
	b.WriteString("// Managed by goddns (rotate with `goddns rotate-key`). Included once by named.conf.\n")
	for _, k := range keys {
		algo := k.Algo
		if algo == "" {
			algo = "hmac-sha256"
		}
		fmt.Fprintf(&b, "key \"%s\" {\n\talgorithm %s;\n\tsecret \"%s\";\n};\n",
			strings.TrimSuffix(k.Name, "."), algo, k.Secret)
	}
	return b.String()
}

// WriteFile writes the keyring atomically (temp + rename in the same dir),
// preserving the existing file's mode and owner/group so BIND keeps read access.
func WriteFile(path string, keys []Key) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tsig-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.WriteString(Render(keys)); err != nil {
		tmp.Close()
		return err
	}
	// fsync before rename: a key file BIND must read shouldn't survive a crash
	// as a zero-length or stale file.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Preserve mode + ownership of the existing file (default 0640 / goddns:named)
	// so a rotation doesn't lock BIND out of reading the key.
	mode := os.FileMode(0o640)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(tmpName, int(st.Uid), int(st.Gid))
		}
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// GenSecret returns a fresh 32-byte base64 secret suitable for HMAC TSIG.
func GenSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
