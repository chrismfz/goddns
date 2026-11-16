// Package auth hashes and verifies login passwords.
//
// New passwords (the SQLite users table) are argon2id, in the standard PHC
// string format ($argon2id$v=19$m=…,t=…,p=…$salt$key) that other tools —
// including ngm's — read and write. bcrypt ($2a$/$2b$/$2y$) stays verifiable
// because goddns.conf's [admin] users and basic_auth entries are bcrypt.
//
// It uses golang.org/x/crypto/argon2 directly (already a dependency) instead
// of a wrapper module: the PHC encode/decode is a few lines.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// MinPasswordLen is the shortest password goddns accepts anywhere.
const MinPasswordLen = 8

// maxPasswordLen bounds the work an attacker can make one verify do (argon2
// hashes the whole input) and matches bcrypt's effective limit.
const maxPasswordLen = 72

// argon2id parameters: RFC 9106's second recommended option (64 MiB, t=3,
// p=4), tuned down to t=1/p=2 like the common library default for an
// interactive login on a small VM. Login is IP-throttled before it hashes.
const (
	argonMemory  = 64 * 1024 // KiB
	argonTime    = 1
	argonThreads = 2
	argonSaltLen = 16
	argonKeyLen  = 32
)

// maxConcurrentHashes bounds how many argon2id computations run at once. Each
// one allocates argonMemory (64 MiB); the login throttle is per source IP, so
// without this a login flood from many addresses could exhaust memory. Extra
// callers wait their turn instead.
const maxConcurrentHashes = 4

var hashSem = make(chan struct{}, maxConcurrentHashes)

// hashWait is how long a caller waits for a hash slot before giving up with
// ErrBusy, so a flood sheds load instead of queueing every request forever.
var hashWait = 3 * time.Second

// ErrBusy means every hash slot stayed taken for hashWait: the caller should
// answer "try again" (503), not count it as a failed password.
var ErrBusy = errors.New("auth: too many password checks in progress, try again")

func idKey(pass, salt []byte, t, m uint32, p uint8, n uint32) ([]byte, error) {
	timer := time.NewTimer(hashWait)
	defer timer.Stop()
	select {
	case hashSem <- struct{}{}:
	case <-timer.C:
		return nil, ErrBusy
	}
	defer func() { <-hashSem }()
	return argon2.IDKey(pass, salt, t, m, p, n), nil
}

// ErrMismatch is returned when a password does not match its hash.
var ErrMismatch = errors.New("auth: password mismatch")

// CheckPolicy reports whether pass is acceptable as a new password.
func CheckPolicy(pass string) error {
	switch {
	case len(pass) < MinPasswordLen:
		return fmt.Errorf("password too short (min %d characters)", MinPasswordLen)
	case len(pass) > maxPasswordLen:
		return fmt.Errorf("password too long (max %d bytes)", maxPasswordLen)
	}
	return nil
}

// Hash returns an argon2id PHC string for pass.
func Hash(pass string) (string, error) {
	if err := CheckPolicy(pass); err != nil {
		return "", err
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := idKey([]byte(pass), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	if err != nil {
		return "", err
	}
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify checks pass against an argon2id or bcrypt hash. It returns
// ErrMismatch on a wrong password and another error for a malformed hash.
func Verify(hash, pass string) error {
	if len(pass) > maxPasswordLen {
		return ErrMismatch
	}
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		return verifyArgon2id(hash, pass)
	case strings.HasPrefix(hash, "$2"):
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil {
			return ErrMismatch
		}
		return nil
	default:
		return errors.New("auth: unknown hash format")
	}
}

// IsHash reports whether s looks like a hash Verify understands.
func IsHash(s string) bool {
	if strings.HasPrefix(s, "$2") {
		return true
	}
	_, _, _, _, err := parseArgon2id(s)
	return err == nil
}

func verifyArgon2id(hash, pass string) error {
	p, salt, want, ver, err := parseArgon2id(hash)
	if err != nil {
		return err
	}
	if ver != argon2.Version {
		return fmt.Errorf("auth: argon2 version %d not supported", ver)
	}
	got, err := idKey([]byte(pass), salt, p.time, p.memory, p.threads, uint32(len(want)))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

type argonParams struct {
	memory, time uint32
	threads      uint8
}

// parseArgon2id decodes a PHC string. It bounds the parameters so a crafted
// hash (a DB the attacker can write is already game over, but a corrupt row
// shouldn't OOM the daemon) can't demand gigabytes per verify.
func parseArgon2id(s string) (argonParams, []byte, []byte, int, error) {
	var p argonParams
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, 0, errors.New("auth: malformed argon2id hash")
	}
	var ver int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &ver); err != nil {
		return p, nil, nil, 0, errors.New("auth: malformed argon2id version")
	}
	var threads uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &threads); err != nil {
		return p, nil, nil, 0, errors.New("auth: malformed argon2id parameters")
	}
	// Exact form only: Sscanf ignores trailing text, so a PHC string with extra
	// parameters (keyid=, data=) would parse and then never verify.
	if parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", p.memory, p.time, threads) || parts[2] != fmt.Sprintf("v=%d", ver) {
		return p, nil, nil, 0, errors.New("auth: unsupported argon2id parameter form")
	}
	if p.memory == 0 || p.memory > 1024*1024 || p.time == 0 || p.time > 16 || threads == 0 || threads > 64 {
		return p, nil, nil, 0, errors.New("auth: argon2id parameters out of range")
	}
	p.threads = uint8(threads)
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return p, nil, nil, 0, errors.New("auth: malformed argon2id salt")
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return p, nil, nil, 0, errors.New("auth: malformed argon2id key")
	}
	return p, salt, key, ver, nil
}

// dummyHash is verified against when the user doesn't exist, so an unknown
// name costs the same argon2id work as a real one (no enumeration by timing).
// Built on first use, not at init: every process linking this package (the
// CLI, zoned, tests) would otherwise pay a 64 MiB hash before main().
var (
	dummyOnce sync.Once
	dummyHash string
)

// Burn performs one argon2id verify against a throwaway hash. It returns
// ErrBusy when no hash slot frees up in time.
func Burn(pass string) error {
	dummyOnce.Do(func() {
		h, err := Hash("goddns-dummy-password")
		if err != nil {
			// ErrBusy on the very first use: fall back to a fixed valid
			// hash rather than leave the timing path empty.
			h = "$argon2id$v=19$m=65536,t=1,p=2$MDEyMzQ1Njc4OWFiY2RlZg$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"
		}
		dummyHash = h
	})
	if err := Verify(dummyHash, pass); errors.Is(err, ErrBusy) {
		return err
	}
	return nil
}
