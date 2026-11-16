package service

import (
	"net"
	"strconv"
	"strings"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/vhostmut"
)

// VhostEditing reports whether proxy.d/ vhost CRUD is enabled.
func (s *Service) VhostEditing() bool { return s.ConfPath != "" }

var errVhostOff = invalid("vhost editing is not enabled")

// VhostList returns every configured vhost with its provenance (managed
// proxy.d/ fragment vs base config).
func (s *Service) VhostList(a Actor) ([]vhostmut.Entry, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	if !s.VhostEditing() {
		return nil, errVhostOff
	}
	return s.vhostEditor().List()
}

// VhostManaged returns the set of hosts (normalized) whose proxy.d/ fragment
// goddns owns. Best-effort: on any error (or editing off) the set is empty, so
// a caller shows everything read-only.
func (s *Service) VhostManaged(a Actor) map[string]bool {
	managed := map[string]bool{}
	if !s.VhostEditing() || s.requireAdmin(a) != nil {
		return managed
	}
	if entries, err := s.vhostEditor().List(); err == nil {
		for _, e := range entries {
			managed[e.Host] = e.Managed
		}
	}
	return managed
}

// normHost lowercases and strips whitespace and a trailing dot, so every vhost
// entry point matches however the caller spelled the host (vhostmut
// normalizes the same way internally).
func normHost(h string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".") }

// VhostGet returns the goddns-managed vhost for host.
func (s *Service) VhostGet(a Actor, host string) (vhostmut.Entry, error) {
	host = normHost(host)
	entries, err := s.VhostList(a)
	if err != nil {
		return vhostmut.Entry{}, err
	}
	for _, e := range entries {
		if e.Host == host && e.Managed {
			return e, nil
		}
	}
	return vhostmut.Entry{}, invalid("no goddns-managed vhost %q to edit", host)
}

// VhostSet creates or replaces a managed vhost. apply=false previews the
// rendered fragment; apply=true writes it, audits and triggers a reload.
func (s *Service) VhostSet(a Actor, host string, rule config.ProxyRule, apply bool) (*vhostmut.Result, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	if !s.VhostEditing() {
		return nil, errVhostOff
	}
	host = normHost(host)
	// Reject a console port that collides with the proxy listener up front, so
	// a caller can't silently write a fragment that then breaks every reload.
	if _, plPort, e := net.SplitHostPort(s.cfg().ProxyListen); e == nil && plPort != "" {
		for _, p := range rule.ConsolePorts {
			if strconv.Itoa(p) == plPort {
				return nil, invalid("console_ports %d collides with proxy_listen (%s)", p, plPort)
			}
		}
	}
	ed := s.vhostEditor()
	res, err := ed.PreviewSet(host, rule)
	if err != nil || !apply {
		return res, err
	}
	if _, err := ed.Set(host, rule); err != nil {
		return nil, err
	}
	s.Audit(a, "vhost-%s host=%s upstream=%s", res.Action, res.Host, rule.Upstream)
	s.reload()
	return res, nil
}

// VhostRemove deletes a managed vhost. apply=false previews; apply=true
// removes the fragment, audits and triggers a reload.
func (s *Service) VhostRemove(a Actor, host string, apply bool) (*vhostmut.Result, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	if !s.VhostEditing() {
		return nil, errVhostOff
	}
	host = normHost(host)
	ed := s.vhostEditor()
	res, err := ed.PreviewRemove(host)
	if err != nil || !apply {
		return res, err
	}
	if _, err := ed.Remove(host); err != nil {
		return nil, err
	}
	s.Audit(a, "vhost-remove host=%s", res.Host)
	s.reload()
	return res, nil
}

func (s *Service) reload() {
	if s.Reload != nil {
		s.Reload()
	}
}
