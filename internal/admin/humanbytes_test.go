package admin

import (
	"math"
	"testing"
)

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1<<20 - 1, "1024.0 KB"},
		{1 << 20, "1.0 MB"},
		{1 << 30, "1.0 GB"},
		{1 << 40, "1.0 TB"},
		{1 << 50, "1.0 PB"}, // the boundary that used to panic ("KMGT"[4])
		{1 << 60, "1.0 EB"},
		{math.MaxInt64, "8.0 EB"}, // must not panic at the top of the range
	}
	for _, c := range cases {
		if got := humanBytes(c.n); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}
