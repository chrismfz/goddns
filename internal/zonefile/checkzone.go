package zonefile

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
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
