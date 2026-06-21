// Package e2e exercises pds + pdsd over a loopback SSH/SFTP connection.
package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"petris.dev/pds/internal/client"
	"petris.dev/pds/internal/config"
	"petris.dev/pds/internal/server"
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

// harness starts a server and returns the SSH endpoint plus the host/client keys.
func harness(t *testing.T) (endpoint string, host, clientKey keypair, dataDir string) {
	return harnessWith(t, func(*config.Server) {})
}

// harnessWith is harness with a hook to tweak the server config before it starts.
func harnessWith(t *testing.T, tweak func(*config.Server)) (endpoint string, host, clientKey keypair, dataDir string) {
	srv, host, clientKey, dataDir := newServer(t, tweak)
	return serveSSH(t, srv), host, clientKey, dataDir
}

// newServer builds a configured server (two buckets, an exec bucket) without starting any
// listener, so callers can serve SSH and/or mount the HTTP handler as needed.
func newServer(t *testing.T, tweak func(*config.Server)) (srv *server.Server, host, clientKey keypair, dataDir string) {
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
		SSHListen:      "127.0.0.1:0",
		ExecBucket:     "scripts",
		AuthorizedKeys: []config.ClientEntry{{Host: "web01", Keys: []string{clientKey.pubLine}}},
		Buckets: map[string]config.Bucket{
			"scripts": {Path: scripts, Mode: "ro"},
			"metrics": {Path: metrics, Mode: "rw", Versioned: true, ByHost: true, Extension: "yaml", Validator: "yaml"},
		},
	}
	tweak(cfg)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	srv, err := server.New(cfg, []ssh.Signer{host.signer})
	if err != nil {
		t.Fatal(err)
	}
	return srv, host, clientKey, dataDir
}

// serveSSH starts srv on an ephemeral loopback port and returns the endpoint.
func serveSSH(t *testing.T, srv *server.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)
	return ln.Addr().String()
}

// clientConfig builds a client config from an endpoint string (host:port).
func clientConfig(t *testing.T, endpoint string, trusted []string) *config.Client {
	t.Helper()
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return &config.Client{Host: host, SSHPort: port, TrustedKeys: trusted}
}

func dial(t *testing.T, endpoint string, trusted []string, identity string) (*client.Client, error) {
	t.Helper()
	cfg := clientConfig(t, endpoint, trusted)
	cfg.Identities = []string{identity}
	return client.Dial(cfg)
}

// dialAnon dials with no SSH key at all: HOME is pointed at an empty dir so there are
// no ~/.ssh/id_* identities, exercising the no-key -> anonymous path in Dial.
func dialAnon(t *testing.T, endpoint string, trusted []string) (*client.Client, error) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return client.Dial(clientConfig(t, endpoint, trusted))
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

// TestReadDir covers the raw directory accessor that backs shell completion: it
// returns entries (not formatted text) for buckets at the root and scripts under
// the .pds/exec alias.
func TestReadDir(t *testing.T) {
	endpoint, host, clientKey, _ := harness(t)
	c, err := dial(t, endpoint, []string{host.pubLine}, clientKey.pemPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	names := func(remote string) map[string]bool {
		infos, err := c.ReadDir(remote)
		if err != nil {
			t.Fatalf("ReadDir(%q): %v", remote, err)
		}
		m := map[string]bool{}
		for _, fi := range infos {
			m[fi.Name()] = true
		}
		return m
	}

	root := names("/")
	for _, want := range []string{"scripts", "metrics", ".pds"} {
		if !root[want] {
			t.Errorf("ReadDir(/) missing %q: %v", want, root)
		}
	}
	if execs := names(".pds/exec"); !execs["hello.sh"] {
		t.Errorf("ReadDir(.pds/exec) missing hello.sh: %v", execs)
	}
}

func TestAnonymousReadOnly(t *testing.T) {
	endpoint, host, clientKey, _ := harnessWith(t, func(c *config.Server) {
		c.AllowAnonymous = true
	})

	// Anonymous clients connect without a key and can read.
	anon, err := dialAnon(t, endpoint, []string{host.pubLine})
	if err != nil {
		t.Fatalf("anonymous dial: %v", err)
	}
	defer anon.Close()

	var b bytes.Buffer
	if err := anon.Pull(".pds/exec/hello.sh", &b); err != nil {
		t.Fatalf("anonymous pull: %v", err)
	}
	if !strings.Contains(b.String(), "echo hi") {
		t.Errorf("anonymous pull content = %q", b.String())
	}
	b.Reset()
	if err := anon.Ls("/", &b); err != nil {
		t.Fatalf("anonymous ls: %v", err)
	}
	if !strings.Contains(b.String(), "scripts/") {
		t.Errorf("anonymous ls root = %q", b.String())
	}

	// ...but cannot push.
	if err := anon.Push("metrics", strings.NewReader("a: 1\n")); err == nil {
		t.Errorf("anonymous push should be rejected")
	}
	// ...and have no .self host directory.
	b.Reset()
	if err := anon.Pull("metrics/.self/latest.yaml", &b); err == nil {
		t.Errorf("anonymous .self access should fail")
	}

	// Authenticated clients still keep their host identity (push works) even with
	// anonymous access enabled.
	c, err := dial(t, endpoint, []string{host.pubLine}, clientKey.pemPath)
	if err != nil {
		t.Fatalf("authenticated dial: %v", err)
	}
	defer c.Close()
	if err := c.Push("metrics", strings.NewReader("a: 1\n")); err != nil {
		t.Fatalf("authenticated push: %v", err)
	}
}

func TestAnonymousDisabledByDefault(t *testing.T) {
	endpoint, host, _, _ := harness(t)
	if _, err := dialAnon(t, endpoint, []string{host.pubLine}); err == nil {
		t.Fatalf("anonymous dial should fail when allowAnonymous is unset")
	}
}

// An unauthorized key against an anonymous-enabled server falls back to read-only
// anonymous access rather than failing.
func TestAnonymousFallback(t *testing.T) {
	endpoint, host, _, _ := harnessWith(t, func(c *config.Server) {
		c.AllowAnonymous = true
	})
	stranger := genKey(t, t.TempDir(), "stranger")

	c, err := dial(t, endpoint, []string{host.pubLine}, stranger.pemPath)
	if err != nil {
		t.Fatalf("expected fallback to anonymous to succeed, got: %v", err)
	}
	defer c.Close()

	var b bytes.Buffer
	if err := c.Pull(".pds/exec/hello.sh", &b); err != nil {
		t.Fatalf("fallback read: %v", err)
	}
	if !strings.Contains(b.String(), "echo hi") {
		t.Errorf("fallback read content = %q", b.String())
	}
	// Fallback access is read-only.
	if err := c.Push("metrics", strings.NewReader("a: 1\n")); err == nil {
		t.Errorf("fallback client should not be able to push")
	}
}

// httpGet fetches url and returns the body and status code.
func httpGet(t *testing.T, url string) (string, int) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode
}

// Read-only HTTP serves bucket contents on its own port alongside SSH.
func TestHTTPReadOnly(t *testing.T) {
	srv, host, clientKey, _ := newServer(t, func(c *config.Server) {
		c.AllowAnonymous = true
		c.HTTPListen = ":0"
	})
	sshEndpoint := serveSSH(t, srv)

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { httpLn.Close() })
	go http.Serve(httpLn, srv.HTTPHandler())
	base := "http://" + httpLn.Addr().String()

	// File read.
	if body, code := httpGet(t, base+"/scripts/hello.sh"); code != 200 || !strings.Contains(body, "echo hi") {
		t.Fatalf("GET hello.sh = %d %q", code, body)
	}

	// Directory -> JSON listing including the virtual .meta.
	body, code := httpGet(t, base+"/scripts")
	if code != 200 {
		t.Fatalf("GET /scripts = %d", code)
	}
	var entries []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		t.Fatalf("listing not JSON: %v (%q)", err, body)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name] = true
	}
	if !names["hello.sh"] || !names[".meta"] {
		t.Errorf("listing missing entries: %q", body)
	}

	// meta document.
	if body, code := httpGet(t, base+"/metrics/.meta"); code != 200 || !strings.Contains(body, "byHost") {
		t.Errorf("GET .meta = %d %q", code, body)
	}

	// .self has no host over HTTP; .push is write-only -> both 404.
	if _, code := httpGet(t, base+"/metrics/.self/latest.yaml"); code != 404 {
		t.Errorf(".self code = %d, want 404", code)
	}
	if _, code := httpGet(t, base+"/metrics/.push"); code != 404 {
		t.Errorf(".push code = %d, want 404", code)
	}

	// Writes are rejected with 405.
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		req, _ := http.NewRequest(method, base+"/metrics", strings.NewReader("x"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 405 {
			t.Errorf("%s code = %d, want 405", method, resp.StatusCode)
		}
	}

	// SSH still works on its own port concurrently.
	c, err := dial(t, sshEndpoint, []string{host.pubLine}, clientKey.pemPath)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	defer c.Close()
	if err := c.Push("metrics", strings.NewReader("a: 1\n")); err != nil {
		t.Fatalf("ssh push: %v", err)
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

// hostSignerLines returns three host-key signers (ed25519, ecdsa p256, rsa) and their
// authorized_keys lines, for exercising mixed-host-key servers.
func hostSignerLines(t *testing.T) (signers []ssh.Signer, ed, ec, rsaLine string) {
	t.Helper()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edS, err := ssh.NewSignerFromKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	ecK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecS, err := ssh.NewSignerFromKey(ecK)
	if err != nil {
		t.Fatal(err)
	}
	rsaK, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaS, err := ssh.NewSignerFromKey(rsaK)
	if err != nil {
		t.Fatal(err)
	}
	line := func(s ssh.Signer) string {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
	}
	return []ssh.Signer{edS, ecS, rsaS}, line(edS), line(ecS), line(rsaS)
}

// rawMultiHostKeyServer starts a minimal SSH+SFTP server presenting all of the given
// host keys (bypassing server.New's ed25519 filtering), so a test can exercise the
// client's host-key negotiation against a server that offers several key types. It
// accepts any client key.
func rawMultiHostKeyServer(t *testing.T, signers []ssh.Signer) string {
	t.Helper()
	sc := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	for _, s := range signers {
		sc.AddHostKey(s)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveRawSFTP(nConn, sc)
		}
	}()
	return ln.Addr().String()
}

// serveRawSFTP completes one SSH handshake and serves the sftp subsystem over the real
// filesystem — enough for the client's sftp.NewClient to succeed after the host key is
// verified.
func serveRawSFTP(nConn net.Conn, sc *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, sc)
	if err != nil {
		nConn.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, requests, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			// Closing the channel when the sftp session ends lets the client's sftp
			// recv loop see EOF, so client.Close() returns instead of blocking.
			defer ch.Close()
			for req := range requests {
				if req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
					_ = req.Reply(true, nil)
					srv, err := sftp.NewServer(ch)
					if err != nil {
						return
					}
					_ = srv.Serve()
					_ = srv.Close()
					return
				}
				_ = req.Reply(false, nil)
			}
		}()
	}
}

// Against a server offering ed25519+ecdsa+rsa host keys, Dial must pin negotiation to
// the trusted ed25519 key — Go's default negotiation would otherwise settle on the
// (untrusted) ecdsa key and fail. This is the regression test for the original bug.
func TestDialPinsEd25519AgainstMultiHostKeyServer(t *testing.T) {
	signers, edLine, _, _ := hostSignerLines(t)
	endpoint := rawMultiHostKeyServer(t, signers)
	clientKey := genKey(t, t.TempDir(), "client")
	c, err := dial(t, endpoint, []string{edLine}, clientKey.pemPath)
	if err != nil {
		t.Fatalf("dial against multi-host-key server trusting ed25519: %v", err)
	}
	c.Close()
}

// A non-ed25519 trusted key is rejected before dialing (the client only supports
// ed25519 host keys).
func TestDialRejectsNonEd25519TrustedKey(t *testing.T) {
	_, _, ecdsaLine, _ := hostSignerLines(t)
	cfg := &config.Client{Host: "127.0.0.1", SSHPort: 1, TrustedKeys: []string{ecdsaLine}}
	cfg.Identities = []string{genKey(t, t.TempDir(), "client").pemPath}
	if _, err := client.Dial(cfg); err == nil {
		t.Fatal("dial with a non-ed25519 trusted key should error")
	}
}

// An untrusted host key must fail rather than silently downgrade to anonymous, even when
// the server allows anonymous access.
func TestDialUntrustedHostKeyDoesNotDowngrade(t *testing.T) {
	endpoint, _, clientKey, _ := harnessWith(t, func(c *config.Server) { c.AllowAnonymous = true })
	bogus := genKey(t, t.TempDir(), "bogus").pubLine // ed25519, but not the server's host key
	if _, err := dial(t, endpoint, []string{bogus}, clientKey.pemPath); err == nil {
		t.Fatal("expected dial to fail on an untrusted host key, not connect anonymously")
	}
}

// With no client identity, Dial connects read-only as the anonymous user.
func TestDialAnonymousConnects(t *testing.T) {
	endpoint, host, _, _ := harnessWith(t, func(c *config.Server) { c.AllowAnonymous = true })
	c, err := dialAnon(t, endpoint, []string{host.pubLine})
	if err != nil {
		t.Fatalf("anonymous dial: %v", err)
	}
	defer c.Close()
	var b bytes.Buffer
	if err := c.Ls("/", &b); err != nil {
		t.Fatalf("ls: %v", err)
	}
}
