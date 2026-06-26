package main

import (
	"errors"
	"net"
	"sort"
	"sync"
	"testing"
)

// fakeLis is a net.Listener whose Accept blocks until Close, so the manager's
// accept goroutine exits cleanly without a real socket.
type fakeLis struct {
	port    int
	closed  chan struct{}
	once    sync.Once
	onClose func(int)
}

func (f *fakeLis) Accept() (net.Conn, error) { <-f.closed; return nil, errors.New("closed") }
func (f *fakeLis) Addr() net.Addr            { return &net.TCPAddr{} }
func (f *fakeLis) Close() error {
	f.once.Do(func() {
		if f.onClose != nil {
			f.onClose(f.port)
		}
		close(f.closed)
	})
	return nil
}

func TestConsoleManagerSync(t *testing.T) {
	var mu sync.Mutex
	var opened, closed []int
	m := &consoleManager{
		active: map[int]net.Listener{},
		open: func(p int) (net.Listener, error) {
			mu.Lock()
			opened = append(opened, p)
			mu.Unlock()
			return &fakeLis{port: p, closed: make(chan struct{}), onClose: func(cp int) {
				mu.Lock()
				closed = append(closed, cp)
				mu.Unlock()
			}}, nil
		},
	}
	activePorts := func() []int {
		var ps []int
		for p := range m.active {
			ps = append(ps, p)
		}
		sort.Ints(ps)
		return ps
	}

	// open 5900
	m.sync([]int{5900})
	if got := activePorts(); len(got) != 1 || got[0] != 5900 {
		t.Fatalf("after sync([5900]) active = %v", got)
	}

	// add 5901 — 5900 stays open (not reopened), 5901 opens
	m.sync([]int{5900, 5901})
	if got := activePorts(); len(got) != 2 || got[0] != 5900 || got[1] != 5901 {
		t.Fatalf("after sync([5900,5901]) active = %v", got)
	}

	// drop 5900 — it closes, 5901 stays
	m.sync([]int{5901})
	if got := activePorts(); len(got) != 1 || got[0] != 5901 {
		t.Fatalf("after sync([5901]) active = %v", got)
	}

	// drop all
	m.sync(nil)
	if got := activePorts(); len(got) != 0 {
		t.Fatalf("after sync(nil) active = %v", got)
	}

	mu.Lock()
	defer mu.Unlock()
	// 5900 opened once (not reopened on the second sync), 5901 opened once
	sort.Ints(opened)
	if len(opened) != 2 || opened[0] != 5900 || opened[1] != 5901 {
		t.Fatalf("opened = %v, want each port opened exactly once", opened)
	}
	sort.Ints(closed)
	if len(closed) != 2 || closed[0] != 5900 || closed[1] != 5901 {
		t.Fatalf("closed = %v, want both ports closed exactly once", closed)
	}
}
