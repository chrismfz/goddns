package proxy

import (
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// HostStat is an immutable snapshot of one proxied host's live counters, for
// the admin dashboard. Counters are cumulative since process start (in-memory;
// they reset on restart — no persistence, no disk I/O on the hot path).
type HostStat struct {
	Host                            string
	Requests                        int64
	Active                          int64 // in-flight right now (incl. live console sessions)
	BytesIn                         int64 // client -> goddns (request bodies + console input)
	BytesOut                        int64 // goddns -> client (responses + console output)
	Status2xx, Status3xx, Status4xx int64
	Status5xx                       int64
	LastSeen                        time.Time
}

// counters holds one host's atomically-updated tallies.
type counters struct {
	requests atomic.Int64
	active   atomic.Int64
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
	s2xx     atomic.Int64
	s3xx     atomic.Int64
	s4xx     atomic.Int64
	s5xx     atomic.Int64
	lastSeen atomic.Int64 // unix seconds
}

func (c *counters) note(status int) {
	switch {
	case status >= 500:
		c.s5xx.Add(1)
	case status >= 400:
		c.s4xx.Add(1)
	case status >= 300:
		c.s3xx.Add(1)
	case status >= 200:
		c.s2xx.Add(1)
	}
}

// stats maps host -> counters. Entries are created only for hosts that exist in
// the routing table (see ServeHTTP), so a flood of random Host headers against
// the public listener can never grow the map without bound.
type stats struct {
	mu sync.RWMutex
	m  map[string]*counters
}

func newStats() *stats { return &stats{m: make(map[string]*counters)} }

func (s *stats) host(h string) *counters {
	s.mu.RLock()
	c := s.m[h]
	s.mu.RUnlock()
	if c != nil {
		return c
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c = s.m[h]; c == nil {
		c = &counters{}
		s.m[h] = c
	}
	return c
}

// prune drops counters for hosts no longer in keep (a reload removed them), so
// the table and the stats map stay in step.
func (s *stats) prune(keep map[string]*rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h := range s.m {
		if _, ok := keep[h]; !ok {
			delete(s.m, h)
		}
	}
}

func (s *stats) snapshot() []HostStat {
	s.mu.RLock()
	out := make([]HostStat, 0, len(s.m))
	for h, c := range s.m {
		var seen time.Time
		if ls := c.lastSeen.Load(); ls > 0 {
			seen = time.Unix(ls, 0)
		}
		out = append(out, HostStat{
			Host: h, Requests: c.requests.Load(), Active: c.active.Load(),
			BytesIn: c.bytesIn.Load(), BytesOut: c.bytesOut.Load(),
			Status2xx: c.s2xx.Load(), Status3xx: c.s3xx.Load(),
			Status4xx: c.s4xx.Load(), Status5xx: c.s5xx.Load(),
			LastSeen: seen,
		})
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// countReadCloser tallies bytes read from a request body into n.
type countReadCloser struct {
	rc io.ReadCloser
	n  *atomic.Int64
}

func (c *countReadCloser) Read(b []byte) (int, error) {
	n, err := c.rc.Read(b)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

func (c *countReadCloser) Close() error { return c.rc.Close() }

// countConn tallies bytes read/written over a hijacked (websocket/BMC console)
// connection, so streamed console bandwidth isn't invisible to the counters.
// A few handshake bytes that the reverse proxy writes through the buffered
// writer before the copy loop are not counted — the figure is a close estimate,
// not an exact byte ledger.
type countConn struct {
	net.Conn
	in, out *atomic.Int64
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.in.Add(int64(n))
	}
	return n, err
}

func (c *countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.out.Add(int64(n))
	}
	return n, err
}
