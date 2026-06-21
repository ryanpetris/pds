// Package e2e exercises pds + pdsd over a loopback SSH/SFTP connection.
package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"petris.net/pds/internal/client"
	"petris.net/pds/internal/config"
	"petris.net/pds/internal/server"
)

type keypair struct {
	signer  ssh.Signer
	pubLine string // authorized_keys format
	pemPath string // private key on disk (for client identities)
}

func genKey(t *testing.T, dir, name string) keypair {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	pemPath := filepath.Join(dir, name)
	if err := os.WriteFile(pemPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return keypair{signer: signer, pubLine: pubLine, pemPath: pemPath}
}

// harness starts a server and returns the endpoint plus the host/client keys.
func harness(t *testing.T) (endpoint string, host, clientKey keypair, dataDir string) {
	t.Helper()
	keyDir := t.TempDir()
	dataDir = t.TempDir()
	host = genKey(t, keyDir, "host")
	clientKey = genKey(t, keyDir, "client")

	scripts := filepath.Join(dataDir, "scripts")
	metrics := filepath.Join(dataDir, "metrics")
	if err := os.MkdirAll(scripts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(metrics, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scripts, "hello.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Server{
		Listen:         "127.0.0.1:0",
		ExecBucket:     "scripts",
		AuthorizedKeys: []config.ClientEntry{{Host: "web01", Keys: []string{clientKey.pubLine}}},
		Buckets: map[string]config.Bucket{
			"scripts": {Path: scripts, Mode: "ro"},
			"metrics": {Path: metrics, Mode: "rw", Versioned: true, ByHost: true, Extension: "yaml", Validator: "yaml"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	srv, err := server.New(cfg, []ssh.Signer{host.signer})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)
	return ln.Addr().String(), host, clientKey, dataDir
}

func dial(t *testing.T, endpoint string, trusted []string, identity string) (*client.Client, error) {
	t.Helper()
	cfg := &config.Client{Endpoint: endpoint, TrustedKeys: trusted, Identities: []string{identity}}
	return client.Dial(cfg)
}

func TestHappyPath(t *testing.T) {
	endpoint, host, clientKey, dataDir := harness(t)

	c, err := dial(t, endpoint, []string{host.pubLine}, clientKey.pemPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// ls root surfaces buckets + .pds
	var b bytes.Buffer
	if err := c.Ls("/", &b); err != nil {
		t.Fatalf("ls: %v", err)
	}
	for _, want := range []string{"scripts/", "metrics/", ".pds/"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("ls root missing %q:\n%s", want, b.String())
		}
	}

	// .pds/exec alias resolves to the scripts bucket.
	b.Reset()
	if err := c.Pull(".pds/exec/hello.sh", &b); err != nil {
		t.Fatalf("pull via alias: %v", err)
	}
	if !strings.Contains(b.String(), "echo hi") {
		t.Errorf("alias pull content = %q", b.String())
	}

	// meta
	b.Reset()
	if err := c.Meta("metrics", &b); err != nil {
		t.Fatalf("meta: %v", err)
	}
	if !strings.Contains(b.String(), "byHost: true") {
		t.Errorf("meta = %q", b.String())
	}

	// push + byHost filing + latest symlink + read back via .self
	if err := c.Push("metrics", strings.NewReader("a: 1\n")); err != nil {
		t.Fatalf("push: %v", err)
	}
	link, err := os.Readlink(filepath.Join(dataDir, "metrics", "web01", "latest.yaml"))
	if err != nil {
		t.Fatalf("latest symlink missing: %v", err)
	}
	if !strings.HasSuffix(link, ".yaml") {
		t.Errorf("latest -> %q", link)
	}
	b.Reset()
	if err := c.Pull("metrics/.self/latest.yaml", &b); err != nil {
		t.Fatalf("pull .self: %v", err)
	}
	if b.String() != "a: 1\n" {
		t.Errorf(".self content = %q", b.String())
	}

	// invalid push is rejected
	if err := c.Push("metrics", strings.NewReader("foo: [bar")); err == nil {
		t.Errorf("invalid yaml push should be rejected")
	}

	// read-only bucket rejects push
	if err := c.Push("scripts", strings.NewReader("x")); err == nil {
		t.Errorf("push to ro bucket should be rejected")
	}
}

func TestUntrustedHostKeyRejected(t *testing.T) {
	endpoint, _, clientKey, _ := harness(t)
	other := genKey(t, t.TempDir(), "other")
	if _, err := dial(t, endpoint, []string{other.pubLine}, clientKey.pemPath); err == nil {
		t.Fatalf("dial with wrong trusted host key should fail")
	}
}

func TestUnauthorizedClientRejected(t *testing.T) {
	endpoint, host, _, _ := harness(t)
	stranger := genKey(t, t.TempDir(), "stranger")
	if _, err := dial(t, endpoint, []string{host.pubLine}, stranger.pemPath); err == nil {
		t.Fatalf("dial with unauthorized client key should fail")
	}
}

func TestTraversalContained(t *testing.T) {
	endpoint, host, clientKey, _ := harness(t)
	c, err := dial(t, endpoint, []string{host.pubLine}, clientKey.pemPath)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Attempting to climb out of a bucket resolves to a non-existent bucket, not /etc.
	var b bytes.Buffer
	if err := c.Pull("scripts/../../etc/passwd", &b); err == nil {
		t.Fatalf("traversal pull should fail, got %q", b.String())
	}
}
