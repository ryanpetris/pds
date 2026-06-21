package server

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"petris.net/pds/internal/config"
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

// When either listener stops, serve must return and close the other listener too, so the
// HTTP endpoint never outlives SSH serving (and vice versa).
func TestServeTearsDownBoth(t *testing.T) {
	srv, err := New(&config.Server{Listen: "127.0.0.1:0", AllowAnonymous: true}, []ssh.Signer{testSigner(t)})
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

	done := make(chan error, 1)
	go func() { done <- srv.serve(ln, hln) }()

	// Stop SSH; serve should return and tear down the HTTP listener.
	ln.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after the SSH listener closed")
	}

	// The HTTP listener must now be closed.
	if _, err := hln.Accept(); err == nil {
		t.Error("HTTP listener still open after serve returned")
	}
}
