package zonefile

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/miekg/dns"
)

// ErrCheckzoneMissing means named-checkzone isn't installed; the caller decides
// whether to treat that as fatal (it should, before a live write) or skip (tests).
var ErrCheckzoneMissing = errors.New("named-checkzone not found in PATH")

// CheckZone validates zone content with `named-checkzone` in strict mode. It
// writes to a private temp file (read-only validation — it never touches the live
// zone) and returns the tool's output on rejection. Strict flags make checkzone
// fail (not warn) on integrity problems it can detect; the design's post-reload
// semantic verify covers what it can't.
func CheckZone(zone string, content []byte) error {
	// Validate the zone name before it becomes an exec argument: a name starting
	// with '-' would be parsed as a flag (argument injection), and the design's
	// option-(b) threat model has the zone name flowing from a less-trusted path.
	if _, ok := dns.IsDomainName(zone); zone == "" || strings.HasPrefix(zone, "-") || !ok {
		return fmt.Errorf("invalid zone name %q", zone)
	}
	bin, err := exec.LookPath("named-checkzone")
	if err != nil {
		return ErrCheckzoneMissing
	}
	tmp, err := os.CreateTemp("", "goddns-checkzone-*.zone")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	out, err := exec.Command(bin, "-k", "fail", "-m", "fail", "-n", "fail", "-i", "full",
		zone, tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("named-checkzone rejected %q: %s", zone, strings.TrimSpace(string(out)))
	}
	return nil
}
