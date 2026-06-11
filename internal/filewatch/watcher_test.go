package filewatch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTouchWithoutChangeIsSuppressed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.conf")
	if err := os.WriteFile(p, []byte("a = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(p)
	if _, ok := w.Changed(); !ok {
		t.Fatal("first read should report change")
	}
	// bare touch: new mtime, same content
	if err := os.Chtimes(p, time.Now().Add(time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.Changed(); ok {
		t.Fatal("mtime-only change should be suppressed by the content hash")
	}
	// real edit
	if err := os.WriteFile(p, []byte("a = 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.Changed(); !ok {
		t.Fatal("content change not reported")
	}
}
