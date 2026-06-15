package zoned

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/filezone"
	"github.com/chrismfz/goddns/internal/named"
)

const zoneText = `$ORIGIN example.
$TTL 60
@	IN	SOA	ns.example. host.example. 1 3 4 5 6
@	IN	NS	ns.example.
www	IN	A	1.1.1.1
`

// testServer starts a Server on a temp socket with a stubbed file editor (no
// live BIND) and returns the socket path.
func testServer(t *testing.T, editable []string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	zonePath := filepath.Join(dir, "example.db")
	if err := os.WriteFile(zonePath, []byte(zoneText), 0o640); err != nil {
		t.Fatal(err)
	}
	inv := &named.Inventory{Zones: []named.Zone{{Name: "example", Type: "master", Path: zonePath}}}
	cfg := &config.Config{EditableZones: editable}

	srv := &Server{
		Cfg: func() (*config.Config, error) { return cfg, nil },
		editor: func(*config.Config) *filezone.Editor {
			return &filezone.Editor{
				Editable: cfg.EditableZones, LockDir: filepath.Join(dir, "l"), BackupDir: filepath.Join(dir, "b"),
				Inv:       func() (*named.Inventory, error) { return inv, nil },
				CheckZone: func(string, []byte) error { return nil },
				Reload:    func(string) error { return nil },
				Verify:    func(string, uint32) error { return nil },
			}
		},
	}
	sock := filepath.Join(dir, "zoned.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	return sock, zonePath
}

func TestZonedPreviewThenApply(t *testing.T) {
	sock, zonePath := testServer(t, []string{"example"})

	// preview: a diff, no write
	resp, err := Call(sock, Request{Zone: "example", Action: "add", RR: "new 60 IN A 9.9.9.9", Apply: false})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(resp.Added) != 1 || !strings.Contains(resp.Added[0], "new.example.") {
		t.Fatalf("preview Added = %v", resp.Added)
	}
	if b, _ := os.ReadFile(zonePath); strings.Contains(string(b), "9.9.9.9") {
		t.Fatal("preview must not write")
	}

	// apply: writes through the (stubbed) pipeline
	resp, err = Call(sock, Request{Zone: "example", Action: "add", RR: "new 60 IN A 9.9.9.9", Apply: true})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if resp.Serial == 0 || resp.Backup == "" {
		t.Fatalf("apply response missing serial/backup: %+v", resp)
	}
	if b, _ := os.ReadFile(zonePath); !strings.Contains(string(b), "new.example.") {
		t.Fatalf("apply didn't write:\n%s", b)
	}
}

func TestZonedRevalidatesAllowlist(t *testing.T) {
	// the helper trusts its OWN config, not the client: a zone not enabled here
	// is refused even though the client asked for it.
	sock, _ := testServer(t, nil) // empty allowlist
	if _, err := Call(sock, Request{Zone: "example", Action: "add", RR: "x 60 IN A 1.1.1.1", Apply: true}); err == nil ||
		!strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("helper must re-check the allowlist, got %v", err)
	}
}

func TestZonedRejectsBadAction(t *testing.T) {
	sock, _ := testServer(t, []string{"example"})
	if _, err := Call(sock, Request{Zone: "example", Action: "delset", RR: "www A", Apply: true}); err == nil ||
		!strings.Contains(err.Error(), "unsupported action") {
		t.Fatalf("helper must reject non add/del actions, got %v", err)
	}
}
