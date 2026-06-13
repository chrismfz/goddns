package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const minSecretLen = 16

// LoadSecret returns the HMAC key used to sign session and CSRF tokens.
// Priority: GODDNS_ADMIN_SECRET env, then the file at path, else a freshly
// generated 32-byte key persisted to path (0600) so sessions survive
// restarts. The env override is the likeliest operator footgun, so it is
// length-checked too.
func LoadSecret(path string) ([]byte, error) {
	if v := os.Getenv("GODDNS_ADMIN_SECRET"); v != "" {
		if len(v) < minSecretLen {
			return nil, fmt.Errorf("GODDNS_ADMIN_SECRET must be at least %d bytes", minSecretLen)
		}
		return []byte(v), nil
	}
	if b, err := os.ReadFile(path); err == nil && len(b) >= minSecretLen {
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("persisting admin secret: %w", err)
	}
	return key, nil
}

// macB64 is HMAC-SHA256 over NUL-separated parts (so fields can't run
// together), base64url-encoded.
func macB64(secret []byte, parts ...string) string {
	m := hmac.New(sha256.New, secret)
	for _, p := range parts {
		m.Write([]byte(p))
		m.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// newSession returns "b64(user)|exp.sig". The user is base64-encoded so the
// '|' separator can never be ambiguous. The MAC also covers credFP (the
// user's current bcrypt hash), so changing the password invalidates every
// existing session for that user.
func newSession(secret []byte, credFP, user string, ttl time.Duration) string {
	exp := time.Now().Add(ttl).Unix()
	msg := base64.RawURLEncoding.EncodeToString([]byte(user)) + "|" + strconv.FormatInt(exp, 10)
	return msg + "." + macB64(secret, msg, credFP)
}

// parseSession validates a token. lookup returns the user's current credFP
// (bcrypt hash) and whether the user still exists — so removing a user, or
// changing their password, invalidates outstanding sessions immediately.
func parseSession(secret []byte, tok string, lookup func(string) (string, bool)) (string, bool) {
	msg, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return "", false
	}
	b64user, expS, ok := strings.Cut(msg, "|")
	if !ok {
		return "", false
	}
	userB, err := base64.RawURLEncoding.DecodeString(b64user)
	if err != nil {
		return "", false
	}
	user := string(userB)
	exp, err := strconv.ParseInt(expS, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	credFP, ok := lookup(user)
	if !ok {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(macB64(secret, msg, credFP)), []byte(sig)) != 1 {
		return "", false
	}
	return user, true
}

// csrfToken binds the CSRF value to the user AND their current credential,
// so it rotates on password change and can't be replayed across users.
func csrfToken(secret []byte, credFP, user string) string {
	return macB64(secret, "csrf", user, credFP)
}

func csrfValid(secret []byte, credFP, user, got string) bool {
	return subtle.ConstantTimeCompare([]byte(csrfToken(secret, credFP, user)), []byte(got)) == 1
}
