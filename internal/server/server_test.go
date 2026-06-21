package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"petris.dev/pds/internal/config"
)

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ecdsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// New ignores non-ed25519 host keys (clients only trust ed25519) but still builds the
// server as long as one ed25519 key remains.
func TestNewIgnoresNonEd25519HostKeys(t *testing.T) {
	signers := []ssh.Signer{ecdsaSigner(t), testSigner(t), rsaSigner(t)}
	if _, err := New(&config.Server{SSHListen: "127.0.0.1:0", AllowAnonymous: true}, signers); err != nil {
		t.Fatalf("New with a mix of host keys should succeed: %v", err)
	}
}

// New fails when no ed25519 host key is available, even if other types are present.
func TestNewRequiresEd25519HostKey(t *testing.T) {
	signers := []ssh.Signer{ecdsaSigner(t), rsaSigner(t)}
	if _, err := New(&config.Server{SSHListen: "127.0.0.1:0", AllowAnonymous: true}, signers); err == nil {
		t.Fatal("New with only non-ed25519 host keys should fail")
	}
}

// nonEd25519AuthorizedKey returns an authorizedKeys entry holding a single ecdsa key,
// which the ed25519-only server must ignore.
func nonEd25519AuthorizedKey(t *testing.T) config.ClientEntry {
	t.Helper()
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ecdsaSigner(t).PublicKey())))
	return config.ClientEntry{Host: "web01", Keys: []string{line}}
}

// An anonymous server whose authorizedKeys are all non-ed25519 should still start
// (anonymous-only), not fail — the keys are ignored with a warning.
func TestNewAllIgnoredAuthorizedKeysAnonymousOK(t *testing.T) {
	cfg := &config.Server{
		SSHListen:      "127.0.0.1:0",
		AllowAnonymous: true,
		AuthorizedKeys: []config.ClientEntry{nonEd25519AuthorizedKey(t)},
	}
	if _, err := New(cfg, []ssh.Signer{testSigner(t)}); err != nil {
		t.Fatalf("anonymous server with all-ignored authorizedKeys should start: %v", err)
	}
}

// The same config without anonymous access is fatal: no one could ever authenticate.
func TestNewAllIgnoredAuthorizedKeysNoAnonFails(t *testing.T) {
	cfg := &config.Server{
		SSHListen:      "127.0.0.1:0",
		AllowAnonymous: false,
		AuthorizedKeys: []config.ClientEntry{nonEd25519AuthorizedKey(t)},
	}
	if _, err := New(cfg, []ssh.Signer{testSigner(t)}); err == nil {
		t.Fatal("non-anonymous server with no usable authorizedKeys should fail")
	}
}

// When either endpoint stops, runGroups must return and tear down the other, so the
// HTTP endpoint never outlives SSH serving (and vice versa).
func TestServeTearsDownBoth(t *testing.T) {
	srv, err := New(&config.Server{SSHListen: "127.0.0.1:0", AllowAnonymous: true}, []ssh.Signer{testSigner(t)})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	gSSH := staticGroupFor(ln, srv.Serve)
	httpSrv := &http.Server{Handler: srv.HTTPHandler(), ReadHeaderTimeout: handshakeTimeout}
	gHTTP := staticGroupFor(hln, httpSrv.Serve)

	done := make(chan error, 1)
	go func() {
		done <- runGroups([]*listenGroup{gSSH, gHTTP}, []<-chan time.Time{nil, nil})
	}()

	// Stop SSH out from under the group; runGroups should return and tear down HTTP.
	ln.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runGroups did not return after the SSH listener closed")
	}

	// The HTTP listener must now be closed.
	if _, err := hln.Accept(); err == nil {
		t.Error("HTTP listener still open after runGroups returned")
	}
}

// Tearing down an HTTP listener must close its active connections, not just stop
// accepting new ones — otherwise unauthenticated reads outlive the endpoint.
func TestHTTPPrepareClosesConnections(t *testing.T) {
	srv, err := New(&config.Server{SSHListen: "127.0.0.1:0", AllowAnonymous: true}, []ssh.Signer{testSigner(t)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serve, closeFn := srv.httpPrepare(ln)
	go func() { _ = serve() }()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Establish a keep-alive connection and read its response so it is held open
	// server-side (idle keep-alive), not yet closed.
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 4096)); err != nil {
		t.Fatalf("first response read failed: %v", err)
	}

	// Tearing the listener down must close the live connection.
	closeFn()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 4096)); err == nil {
		t.Error("connection should be closed after closeFn, but the read succeeded")
	}
}

// staticGroupFor builds a static (no-grace) listenGroup that serves an
// already-open listener, so a test can close that listener to simulate the
// endpoint stopping.
func staticGroupFor(ln net.Listener, serve func(net.Listener) error) *listenGroup {
	used := false
	return &listenGroup{
		src: func() ([]string, error) { return []string{ln.Addr().String()}, nil },
		listen: func(string) (net.Listener, error) {
			if used {
				return nil, net.ErrClosed
			}
			used = true
			return ln, nil
		},
		prepare: func(l net.Listener) (func() error, func()) {
			return func() error { return serve(l) }, func() { _ = l.Close() }
		},
		now: time.Now,
	}
}
