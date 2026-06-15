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
	"net"
	"time"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/filezone"
)

// Request is one structured record edit. The helper re-derives the op and
// re-validates the zone against its OWN config — Zone is a hint, not a grant.
type Request struct {
	Zone   string `json:"zone"`
	Action string `json:"action"` // "add" | "del"
	RR     string `json:"rr"`     // zone-file line
	Apply  bool   `json:"apply"`  // false = preview (diff only), true = write
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
}

// Server is the helper. Cfg loads the CURRENT config each request (so
// editable_zones / named_conf are re-read, never taken from the client).
type Server struct {
	Cfg    func() (*config.Config, error)
	editor func(*config.Config) *filezone.Editor // tests override; nil = from cfg
}

// Serve handles one request per connection on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // ln closed on ctx cancel
		}
		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeResp(conn, Response{Error: "bad request: " + err.Error()})
		return
	}
	writeResp(conn, s.process(req))
}

// process re-validates and runs the edit. Everything (allowlist, static-master,
// panel, surgical safety, checkzone) is enforced by filezone against the
// helper's own config — the client's claims are never trusted.
func (s *Server) process(req Request) Response {
	if req.Action != "add" && req.Action != "del" {
		return Response{Error: fmt.Sprintf("unsupported action %q (helper accepts add/del only)", req.Action)}
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
	return Response{OK: true, Added: res.Added, Removed: res.Removed, Serial: res.Serial, Backup: res.Backup}
}

func (s *Server) editorFor(cfg *config.Config) *filezone.Editor {
	if s.editor != nil {
		return s.editor(cfg)
	}
	return &filezone.Editor{
		NamedConf: cfg.NamedConf, DNSServer: cfg.DNSServer,
		Editable: cfg.EditableZones, Keep: cfg.HistoryKeep,
	}
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
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	if !resp.OK && resp.Error != "" {
		return &resp, fmt.Errorf("%s", resp.Error)
	}
	return &resp, nil
}
