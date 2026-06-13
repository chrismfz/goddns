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

// LoadSecret returns the HMAC key used to sign session and CSRF tokens.
// Priority: GODDNS_ADMIN_SECRET env, then the file at path, else a freshly
// generated 32-byte key persisted to path (0600) so sessions survive
// restarts. Keeping it stable is what stops every login dropping on reboot.
func LoadSecret(path string) ([]byte, error) {
	if v := os.Getenv("GODDNS_ADMIN_SECRET"); v != "" {
		return []byte(v), nil
	}
	if b, err := os.ReadFile(path); err == nil && len(b) >= 16 {
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

func mac(secret []byte, msg string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// newSession returns a signed token "b64(user|exp).sig" valid for ttl.
func newSession(secret []byte, user string, ttl time.Duration) string {
	exp := time.Now().Add(ttl).Unix()
	msg := user + "|" + strconv.FormatInt(exp, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(msg)) + "." + mac(secret, msg)
}

// parseSession validates the token and returns the user on success.
func parseSession(secret []byte, tok string) (string, bool) {
	raw, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return "", false
	}
	msgB, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", false
	}
	msg := string(msgB)
	if subtle.ConstantTimeCompare([]byte(mac(secret, msg)), []byte(sig)) != 1 {
		return "", false
	}
	user, expS, ok := strings.Cut(msg, "|")
	if !ok {
		return "", false
	}
	exp, err := strconv.ParseInt(expS, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	return user, true
}

// csrfToken binds a CSRF value to the logged-in user, so a stolen token from
// one session can't be replayed in another.
func csrfToken(secret []byte, user string) string {
	return mac(secret, "csrf|"+user)
}

func csrfValid(secret []byte, user, got string) bool {
	want := csrfToken(secret, user)
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}
