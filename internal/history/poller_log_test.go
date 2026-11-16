package history

import (
	"fmt"
	"strings"
	"testing"
)

// A failure that persists across cycles is logged once, a changed one again,
// and the recovery once (issue #62: the log filled up every few minutes).
func TestPollerLogsFailuresOnce(t *testing.T) {
	var lines []string
	p := &Poller{Logf: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }}
	for i := 0; i < 5; i++ {
		p.fail("BIND config", "history: cannot read BIND config: exit status 1")
	}
	p.fail("BIND config", "history: cannot read BIND config: permission denied")
	p.ok("BIND config")
	p.ok("BIND config") // already fine: silent
	if len(lines) != 3 || !strings.Contains(lines[0], "exit status 1") ||
		!strings.Contains(lines[1], "permission denied") || !strings.Contains(lines[2], "working again") {
		t.Fatalf("got %d lines: %q", len(lines), lines)
	}
}
