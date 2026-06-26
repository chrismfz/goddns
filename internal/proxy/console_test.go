package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrismfz/goddns/internal/config"
)

func selfSigned(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{name},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// echoServer accepts one connection and echoes everything back.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	return ln
}

// consoleListener wires a TLS console listener in front of proxy p and routes
// every accepted conn to ServeConsole on the given port.
func consoleListener(t *testing.T, p *Proxy, cert tls.Certificate, port int) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.ServeConsole(c, port)
		}
	}()
	return ln
}

func TestConsoleSpliceEndToEnd(t *testing.T) {
	echo := echoServer(t)
	defer echo.Close()
	// route the console dial to our echo server instead of a real BMC
	orig := consoleDial
	consoleDial = func(addr string, verify bool) (net.Conn, error) { return net.Dial("tcp", echo.Addr().String()) }
	defer func() { consoleDial = orig }()

	p := newProxy(t, map[string]config.ProxyRule{
		"idrac.test": {Upstream: "https://10.0.0.5", ConsolePorts: []int{5900}},
	})
	ln := consoleListener(t, p, selfSigned(t, "idrac.test"), 5900)
	defer ln.Close()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "idrac.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping-console")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "ping-console" {
		t.Fatalf("expected the upstream echo through the splice, got %q err=%v", buf[:n], err)
	}

	// stats reflect a live console session for the host
	if s, ok := stat(p, "idrac.test"); !ok || s.Requests != 1 || s.BytesIn < 12 {
		t.Fatalf("console session not counted: ok=%v %+v", ok, s)
	}
}

func TestConsoleRejectsUnknownSNI(t *testing.T) {
	called := int32(0)
	orig := consoleDial
	consoleDial = func(addr string, verify bool) (net.Conn, error) {
		atomic.AddInt32(&called, 1)
		return nil, io.EOF
	}
	defer func() { consoleDial = orig }()

	p := newProxy(t, map[string]config.ProxyRule{
		"idrac.test": {Upstream: "https://10.0.0.5", ConsolePorts: []int{5900}},
	})
	ln := consoleListener(t, p, selfSigned(t, "idrac.test"), 5900)
	defer ln.Close()

	// an SNI with no matching host must be dropped before any upstream dial
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "evil.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection for an unknown SNI should be closed, not served")
	}
	if atomic.LoadInt32(&called) != 0 {
		t.Fatal("an unknown SNI must never reach the upstream dial")
	}
}

func TestConsoleRejectsWrongPort(t *testing.T) {
	called := int32(0)
	orig := consoleDial
	consoleDial = func(addr string, verify bool) (net.Conn, error) { atomic.AddInt32(&called, 1); return nil, io.EOF }
	defer func() { consoleDial = orig }()

	// host only exposes 5900; a connection arriving on 5901 must be refused
	p := newProxy(t, map[string]config.ProxyRule{
		"idrac.test": {Upstream: "https://10.0.0.5", ConsolePorts: []int{5900}},
	})
	ln := consoleListener(t, p, selfSigned(t, "idrac.test"), 5901)
	defer ln.Close()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "idrac.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a port the host doesn't expose should be refused")
	}
	if atomic.LoadInt32(&called) != 0 {
		t.Fatal("a wrong port must never reach the upstream dial")
	}
}

func TestConsoleRejectsDisallowedPeer(t *testing.T) {
	called := int32(0)
	orig := consoleDial
	consoleDial = func(addr string, verify bool) (net.Conn, error) { atomic.AddInt32(&called, 1); return nil, io.EOF }
	defer func() { consoleDial = orig }()

	// allow only a CIDR the loopback client is NOT in
	p := newProxy(t, map[string]config.ProxyRule{
		"idrac.test": {Upstream: "https://10.0.0.5", ConsolePorts: []int{5900}, Allow: []string{"10.0.0.0/8"}},
	})
	ln := consoleListener(t, p, selfSigned(t, "idrac.test"), 5900)
	defer ln.Close()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "idrac.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a peer outside the allow list should be refused")
	}
	if atomic.LoadInt32(&called) != 0 {
		t.Fatal("a forbidden peer must never reach the upstream dial")
	}
}

func TestSpliceCountsBothWays(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	var out, in atomic.Int64
	// client side = a2, upstream side = b1; splice copies a2<->b1
	go splice(a2, b1, &out, &in)

	// client writes -> should reach upstream (counted as `in`)
	go func() { a1.Write([]byte("12345")); a1.Close() }()
	got := make([]byte, 5)
	io.ReadFull(b2, got)
	if string(got) != "12345" {
		t.Fatalf("client->upstream = %q", got)
	}
	b2.Close()
	// give the copies a moment to settle the counters
	time.Sleep(50 * time.Millisecond)
	if in.Load() != 5 {
		t.Fatalf("in counter = %d, want 5", in.Load())
	}
}
