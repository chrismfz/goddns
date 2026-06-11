package proxy

import (
	"net"
	"sync"
	"time"
)

// limiter is a per-client token bucket: rate tokens/sec, burst capacity
// 2×rate. IPv6 clients are bucketed by /64 — a residential customer holds a
// whole /64, so per-address buckets would let one host mint unlimited fresh
// buckets (and grow the map unboundedly) just by rotating source addresses.
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

// key collapses an IP to its bucket identity. nil (unparseable RemoteAddr)
// shares a single bucket rather than bypassing the limit.
func bucketKey(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

func (l *limiter) allow(ip net.IP) bool {
	key := bucketKey(ip)
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

	// Periodic sweep of idle buckets; under pressure (many distinct
	// clients) sweep aggressively so the map cannot grow without bound.
	idle := 10 * time.Minute
	if len(l.buckets) > 16384 {
		idle = time.Minute
	}
	if now.Sub(l.sweep) > time.Minute && (len(l.buckets) > 16384 || now.Sub(l.sweep) > 10*time.Minute) {
		for k, v := range l.buckets {
			if now.Sub(v.last) > idle {
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
