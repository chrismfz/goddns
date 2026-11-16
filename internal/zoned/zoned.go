// Package zoned is the Phase-4 Stage-4 privileged write helper (design option b).
// The unprivileged goddns daemon (admin UI) never writes /var/named or runs
// rndc; instead it sends a STRUCTURED record op over a unix socket to this
// helper, which runs as root, RE-VALIDATES everything from its own config
// (never trusting the client), and performs the file edit + reload. So a
// compromised internet-facing daemon can at most request a single record edit on
// an already-enabled static zone — it never holds a file descriptor into the
// zone directory.
package zoned

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/filezone"
	"github.com/chrismfz/goddns/internal/zonemgr"
)

const maxRequest = 64 << 10 // cap an untrusted request body

// Request is one structured record edit. The helper re-derives the op and
// re-validates the zone against its OWN config — Zone is a hint, not a grant.
type Request struct {
	Zone   string   `json:"zone"`
	Action string   `json:"action"`       // "add" | "del" | "zone-create" | "zone-delete"
	RR     string   `json:"rr"`           // zone-file line (add/del)
	NS     []string `json:"ns,omitempty"` // apex nameservers (zone-create)
	Apply  bool     `json:"apply"`        // false = preview (diff only), true = write
}

// Response is the preview/apply result (mirrors the filezone.Result fields the
// UI needs).
type Response struct {
	OK      bool     `json:"ok"`
	Error   string   `json:"error,omitempty"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	Serial  uint32   `json:"serial,omitempty"`
	Backup  string   `json:"backup,omitempty"`

	// zone-create / zone-delete
	File    string `json:"file,omitempty"`
	Stanza  string `json:"stanza,omitempty"`
	Content string `json:"content,omitempty"`
	Parent  string `json:"parent,omitempty"`
	MovedTo string `json:"moved_to,omitempty"`
	Refused bool   `json:"refused,omitempty"` // the error is a refusal of the request, not a failure
}

// Server is the helper. Cfg loads the CURRENT config each request (so
// editable_zones / named_conf are re-read, never taken from the client).
type Server struct {
	Cfg     func() (*config.Config, error)
	PeerGID int                                   // >0: require the connecting peer be uid 0 or this gid (SO_PEERCRED)
	editor  func(*config.Config) *filezone.Editor // tests override; nil = from cfg
	zoneMgr func(*config.Config) *zonemgr.Manager // tests override; nil = zonemgr.ForConfig
}

// Serve handles one request per connection on ln until ctx is cancelled, with a
// small bound on concurrent handlers (a root service must not let a local flood
// spawn unbounded goroutines / concurrent zone writes).
func (s *Server) Serve(ctx context.Context, ln net.Listener) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	sem := make(chan struct{}, 8)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // ln closed on ctx cancel
		}
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			s.serveConn(conn)
		}()
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if !peerOK(conn, s.PeerGID) {
		writeResp(conn, Response{Error: "permission denied"})
		return
	}
	var req Request
	if err := json.NewDecoder(io.LimitReader(conn, maxRequest)).Decode(&req); err != nil {
		writeResp(conn, Response{Error: "bad request: " + err.Error()})
		return
	}
	writeResp(conn, s.process(req))
}

// peerOK verifies the connecting peer's credentials (SO_PEERCRED) as defence in
// depth over the socket's 0660 root:goddns perms: only uid 0 or the goddns gid.
// allowGID <= 0 disables the check (tests / no group resolved).
func peerOK(conn net.Conn, allowGID int) bool {
	if allowGID <= 0 {
		return true
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var cerr error
	if cerr = raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); cerr != nil {
		return false
	}
	return cred != nil && (cred.Uid == 0 || int(cred.Gid) == allowGID)
}

// process re-validates and runs the edit. Everything (allowlist, static-master,
// panel, surgical safety, checkzone) is enforced by filezone against the
// helper's own config — the client's claims are never trusted.
func (s *Server) process(req Request) Response {
	if req.Action == "zone-create" || req.Action == "zone-delete" {
		return s.processZone(req)
	}
	if req.Action != "add" && req.Action != "del" {
		return Response{Error: fmt.Sprintf("unsupported action %q (helper accepts add/del/zone-create/zone-delete)", req.Action)}
	}
	cfg, err := s.Cfg()
	if err != nil {
		return Response{Error: "config: " + err.Error()}
	}
	rr, err := filezone.ParseRR(req.RR, req.Zone)
	if err != nil {
		return Response{Error: fmt.Sprintf("parse %q: %v", req.RR, err)}
	}
	act := ddns.AddRR
	if req.Action == "del" {
		act = ddns.DelRR
	}
	ops := []ddns.Op{{Action: act, RR: rr}}

	ed := s.editorFor(cfg)
	var res *filezone.Result
	if req.Apply {
		res, err = ed.Apply(req.Zone, ops)
	} else {
		res, err = ed.Preview(req.Zone, ops)
	}
	if err != nil {
		return Response{Error: err.Error()}
	}
	// Audit on the helper's own side: the daemon's audit log is the thing assumed
	// compromised in this threat model, so the root writer records what it applied.
	if req.Apply {
		log.Printf("zoned-audit: %s zone=%s rr=%q serial=%d backup=%s", req.Action, req.Zone, req.RR, res.Serial, res.Backup)
	}
	return Response{OK: true, Added: res.Added, Removed: res.Removed, Serial: res.Serial, Backup: res.Backup}
}

func (s *Server) editorFor(cfg *config.Config) *filezone.Editor {
	if s.editor != nil {
		return s.editor(cfg)
	}
	return &filezone.Editor{
		NamedConf: cfg.NamedConf, DNSServer: cfg.DNSServer,
		Editable: zonemgr.EditableZones(cfg.EditableZones, cfg.ManagedInclude), Keep: cfg.HistoryKeep,
	}
}

// processZone creates or deletes a managed zone. The helper re-derives
// everything from ITS config (include, zone dir, named.conf): the request
// names only the zone and its nameservers, and zonemgr re-validates both.
func (s *Server) processZone(req Request) Response {
	cfg, err := s.Cfg()
	if err != nil {
		return Response{Error: "config: " + err.Error()}
	}
	m := zonemgr.ForConfig(cfg)
	if s.zoneMgr != nil {
		m = s.zoneMgr(cfg)
	}
	var p *zonemgr.Plan
	switch {
	case req.Action == "zone-create" && req.Apply:
		p, err = m.Create(zonemgr.CreateRequest{Zone: req.Zone, NS: req.NS})
	case req.Action == "zone-create":
		p, err = m.PlanCreate(zonemgr.CreateRequest{Zone: req.Zone, NS: req.NS})
	case req.Apply:
		p, err = m.Delete(req.Zone)
	default:
		p, err = m.PlanDelete(req.Zone)
	}
	if err != nil {
		return Response{Error: err.Error(), Refused: zonemgr.IsRefused(err)}
	}
	if req.Apply {
		log.Printf("zoned-audit: %s zone=%s file=%s moved_to=%s", req.Action, p.Zone, p.File, p.MovedTo)
	}
	return Response{OK: true, File: p.File, Stanza: p.Stanza, Content: p.Content, Parent: p.Parent, MovedTo: p.MovedTo}
}

func writeResp(conn net.Conn, r Response) {
	_ = json.NewEncoder(conn).Encode(r)
}

// Call sends a request to the helper socket and returns its response. Used by
// the daemon (admin UI) so it never touches /var/named itself.
func Call(socket string, req Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("zoned helper not reachable at %s (%w) — is goddns-zoned running?", socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(io.LimitReader(conn, maxRequest)).Decode(&resp); err != nil {
		return nil, err
	}
	if !resp.OK && resp.Error != "" {
		return &resp, fmt.Errorf("%s", resp.Error)
	}
	return &resp, nil
}
