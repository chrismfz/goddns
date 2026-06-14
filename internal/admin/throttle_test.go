package admin

import (
	"testing"
	"time"
)

// Regression for the backoff shift overflow: many consecutive failures must
// keep the lock in the FUTURE and capped at the window, never wrap negative.
func TestThrottleNoOverflow(t *testing.T) {
	tr := newLoginThrottle()
	for i := 0; i < 50; i++ {
		tr.fail("ip:x")
	}
	until := tr.blockedUntil("ip:x")
	now := time.Now()
	if !until.After(now) {
		t.Fatalf("lock wrapped into the past (overflow): until=%v now=%v", until, now)
	}
	if until.Sub(now) > throttleWindow+time.Second {
		t.Fatalf("lock exceeds the window cap: %v", until.Sub(now))
	}
}
