package proxy

import (
	"net"
	"sync"
	"time"
)

// limiter is a per-client-IP token bucket: rate tokens/sec, burst capacity
// 2×rate. Cheap enough to sit in front of every proxied request; buckets
// idle for >10 minutes are purged opportunistically.
type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
	sweep   time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(ratePerSec int) *limiter {
	return &limiter{
		rate:    float64(ratePerSec),
		burst:   float64(ratePerSec * 2),
		buckets: make(map[string]*bucket),
		sweep:   time.Now(),
	}
}

func (l *limiter) allow(ip net.IP) bool {
	key := ip.String()
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if now.Sub(l.sweep) > 10*time.Minute {
		for k, v := range l.buckets {
			if now.Sub(v.last) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.sweep = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
