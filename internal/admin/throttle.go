package admin

import (
	"sync"
	"time"
)

// loginThrottle slows password guessing on the admin login form. The admin
// vhost is dispatched around the reverse proxy, so the proxy's per-host
// rate limiter never applies here — this is the only brake besides bcrypt.
// Both the client IP and the target username are throttled: locking the IP
// stops one host hammering many accounts; the soft per-account backoff
// slows a distributed campaign against one account without a hard lockout
// that an attacker could weaponise to deny a legit user (the cap is small).
type loginThrottle struct {
	mu    sync.Mutex
	fails map[string]*failRec
}

type failRec struct {
	n     int
	until time.Time
	seen  time.Time
}

const (
	throttleThreshold = 8                // free attempts before backoff kicks in
	throttleWindow    = 15 * time.Minute // idle reset + max backoff
)

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{fails: map[string]*failRec{}}
}

// blockedUntil returns the latest lock expiry across keys (zero if open).
func (t *loginThrottle) blockedUntil(keys ...string) time.Time {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	var until time.Time
	for _, k := range keys {
		if r, ok := t.fails[k]; ok && now.Before(r.until) && r.until.After(until) {
			until = r.until
		}
	}
	return until
}

func (t *loginThrottle) fail(keys ...string) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.fails) > 4096 { // opportunistic sweep, bounds memory
		for k, r := range t.fails {
			if now.Sub(r.seen) > throttleWindow {
				delete(t.fails, k)
			}
		}
	}
	for _, k := range keys {
		r := t.fails[k]
		if r == nil || now.Sub(r.seen) > throttleWindow {
			r = &failRec{}
			t.fails[k] = r
		}
		r.n++
		r.seen = now
		if r.n >= throttleThreshold {
			d := time.Minute << uint(r.n-throttleThreshold) // 1m,2m,4m...
			if d > throttleWindow {
				d = throttleWindow
			}
			r.until = now.Add(d)
		}
	}
}

func (t *loginThrottle) ok(keys ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		delete(t.fails, k)
	}
}
