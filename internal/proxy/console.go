package proxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

// consoleDial opens the upstream console connection over TLS. Overridable in
// tests so the splice path can run without a real BMC.
var consoleDial = func(addr string, verify bool) (net.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: !verify, MinVersion: tls.VersionTLS10}) // #nosec G402 — BMCs are self-signed; opt-in via upstream_verify
}

// ruleForSNI returns the routing rule for a TLS SNI server name, or nil.
func (p *Proxy) ruleForSNI(sni string) *rule {
	return (*p.rules.Load())[hostKey(sni)]
}

// ServeConsole handles one accepted TLS connection on a console port. It
// completes the handshake to read the SNI, routes to the matching host,
// enforces that host's allow-list, dials the SAME upstream host on `port` over
// TLS, and splices the two streams (counting bytes into the host's stats). The
// console protocol after the TLS handshake is opaque (a WebSocket/KVM stream),
// so goddns byte-splices it rather than parsing — one host = one upstream,
// routed purely by SNI. The connection is always closed on return.
func (p *Proxy) ServeConsole(conn net.Conn, port int) {
	defer conn.Close()
	tconn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	_ = tconn.SetDeadline(time.Now().Add(15 * time.Second)) // bound the handshake
	if err := tconn.Handshake(); err != nil {
		return
	}
	sni := hostKey(tconn.ConnectionState().ServerName)
	rl := p.ruleForSNI(sni)
	if rl == nil || !rl.hasConsolePort(port) {
		log.Printf("console %d: no proxied host for SNI %q", port, sni)
		return
	}
	peerStr, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if !rl.allows(net.ParseIP(peerStr)) {
		log.Printf("console %s:%d: forbidden peer %s", sni, port, peerStr)
		return
	}
	up, err := consoleDial(net.JoinHostPort(rl.upstreamHost, strconv.Itoa(port)), rl.src.UpstreamVerify)
	if err != nil {
		log.Printf("console %s:%d -> %s: dial failed: %v", sni, port, rl.upstreamHost, err)
		return
	}
	defer up.Close()
	_ = tconn.SetDeadline(time.Time{}) // KVM sessions are long-lived; clear the bound

	c := p.stats.host(sni)
	c.requests.Add(1)
	c.lastSeen.Store(time.Now().Unix())
	c.active.Add(1)
	defer c.active.Add(-1)

	splice(tconn, up, &c.bytesOut, &c.bytesIn)
}

// splice copies bytes both ways between the client and the upstream until
// either side closes, tallying client-read bytes into `in` and client-written
// bytes into `out`.
func splice(client, upstream net.Conn, out, in *atomic.Int64) {
	cc := &countConn{Conn: client, in: in, out: out}
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		client.Close()
		upstream.Close()
		done <- struct{}{}
	}
	go cp(upstream, cc) // client -> upstream (cc.Read tallies `in`)
	go cp(cc, upstream) // upstream -> client (cc.Write tallies `out`)
	<-done
	<-done
}
