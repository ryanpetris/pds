package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"petris.dev/pds/internal/config"
)

func TestResolveEndpoints(t *testing.T) {
	t.Setenv("PDS_ENDPOINT", "")
	cfg := &config.Client{Endpoints: []config.ClientEndpoint{
		{Host: "pds.example.com", SSHPort: 2222},
		{Host: "::1", SSHPort: 2200},
		{Host: " [2001:db8::1] ", SSHPort: 2022},
	}}
	want := []string{"pds.example.com:2222", "[::1]:2200", "[2001:db8::1]:2022"}
	got, err := ResolveEndpoints(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveEndpoints = %v, want %v", got, want)
	}

	// The environment override is one exclusive candidate, even when config has many.
	t.Setenv("PDS_ENDPOINT", "other:22")
	got, err = ResolveEndpoints(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"other:22"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveEndpoints override = %v, want %v", got, want)
	}
}

func TestResolveEndpointsInvalid(t *testing.T) {
	t.Setenv("PDS_ENDPOINT", "")
	tests := []struct {
		name string
		cfg  *config.Client
	}{
		{name: "nil config"},
		{name: "empty config", cfg: &config.Client{}},
		{name: "missing host", cfg: &config.Client{Endpoints: []config.ClientEndpoint{{SSHPort: 22}}}},
		{name: "missing port", cfg: &config.Client{Endpoints: []config.ClientEndpoint{{Host: "host"}}}},
		{name: "large port", cfg: &config.Client{Endpoints: []config.ClientEndpoint{{Host: "host", SSHPort: 65536}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ResolveEndpoints(tt.cfg); err == nil {
				t.Fatal("ResolveEndpoints should error")
			}
		})
	}
}

func TestResolveHTTPURLs(t *testing.T) {
	t.Setenv("PDS_ENDPOINT", "")
	cfg := &config.Client{Endpoints: []config.ClientEndpoint{
		// HTTP resolution does not require an SSH port when there is no override.
		{Host: "one.example.com", HTTPPort: 8081},
		{Host: "no-http.example.com", SSHPort: 2222},
		{Host: "::1", SSHPort: 2223, HTTPPort: 8083},
	}}
	want := []string{"http://one.example.com:8081", "http://[::1]:8083"}
	got, err := ResolveHTTPURLs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveHTTPURLs = %v, want %v", got, want)
	}

	// An override follows the matching server's HTTP port and yields only that URL.
	t.Setenv("PDS_ENDPOINT", "[::1]:2223")
	got, err = ResolveHTTPURLs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"http://[::1]:8083"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveHTTPURLs override = %v, want %v", got, want)
	}
}

func TestResolveHTTPURLsOverrideMustMatch(t *testing.T) {
	cfg := &config.Client{Endpoints: []config.ClientEndpoint{
		{Host: "one.example.com", SSHPort: 2221, HTTPPort: 8081},
		{Host: "two.example.com", SSHPort: 2222},
	}}

	t.Setenv("PDS_ENDPOINT", "other.example.com:2221")
	if _, err := ResolveHTTPURLs(cfg); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unmatched override error = %v", err)
	}

	t.Setenv("PDS_ENDPOINT", "two.example.com:2222")
	if _, err := ResolveHTTPURLs(cfg); err == nil || !strings.Contains(err.Error(), "httpPort") {
		t.Fatalf("override without HTTP port error = %v", err)
	}

	t.Setenv("PDS_ENDPOINT", "")
	if _, err := ResolveHTTPURLs(&config.Client{Endpoints: []config.ClientEndpoint{
		{Host: "one.example.com", SSHPort: 2221},
	}}); err == nil {
		t.Fatal("ResolveHTTPURLs should error when no endpoint has HTTP enabled")
	}
}

func TestDialFallsBackInOrder(t *testing.T) {
	prepareDialEnvironment(t)
	signer := testHostSigner(t)
	server := startTestSSHServer(t, signer, nil, true)
	dead := closedEndpoint(t)

	cfg := testClientConfig(t, []string{dead, server.endpoint}, signer)
	c, err := Dial(cfg)
	if err != nil {
		t.Fatalf("Dial = %v", err)
	}
	defer c.Close()
	if c.endpoint != server.endpoint {
		t.Errorf("connected endpoint = %q, want %q", c.endpoint, server.endpoint)
	}
	if got := server.accepts.Load(); got != 1 {
		t.Errorf("successful endpoint accepted %d connections, want 1", got)
	}
}

func TestDialUsesFirstUsableEndpoint(t *testing.T) {
	prepareDialEnvironment(t)
	firstSigner := testHostSigner(t)
	secondSigner := testHostSigner(t)
	first := startTestSSHServer(t, firstSigner, nil, true)
	second := startTestSSHServer(t, secondSigner, nil, true)

	cfg := testClientConfig(t, []string{first.endpoint, second.endpoint}, firstSigner, secondSigner)
	c, err := Dial(cfg)
	if err != nil {
		t.Fatalf("Dial = %v", err)
	}
	defer c.Close()
	if c.endpoint != first.endpoint {
		t.Errorf("connected endpoint = %q, want %q", c.endpoint, first.endpoint)
	}
	if got := second.accepts.Load(); got != 0 {
		t.Errorf("secondary accepted %d connections after primary succeeded", got)
	}
}

func TestDialRetriesSFTPStartupFailure(t *testing.T) {
	prepareDialEnvironment(t)
	firstSigner := testHostSigner(t)
	secondSigner := testHostSigner(t)
	first := startTestSSHServer(t, firstSigner, nil, false)
	second := startTestSSHServer(t, secondSigner, nil, true)

	cfg := testClientConfig(t, []string{first.endpoint, second.endpoint}, firstSigner, secondSigner)
	c, err := Dial(cfg)
	if err != nil {
		t.Fatalf("Dial = %v", err)
	}
	defer c.Close()
	if c.endpoint != second.endpoint {
		t.Errorf("connected endpoint = %q, want %q", c.endpoint, second.endpoint)
	}
}

func TestDialBoundsWholeEndpointAttempt(t *testing.T) {
	prepareDialEnvironment(t)
	stalled, accepted := startStalledServer(t)
	signer := testHostSigner(t)
	server := startTestSSHServer(t, signer, nil, true)
	timeout := 150 * time.Millisecond
	cfg := testClientConfig(t, []string{stalled, server.endpoint}, signer)
	cfg.DialTimeout = &timeout

	started := time.Now()
	c, err := Dial(cfg)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("Dial = %v", err)
	}
	defer c.Close()
	if !accepted.Load() {
		t.Fatal("stalled endpoint was not attempted")
	}
	if c.endpoint != server.endpoint {
		t.Errorf("connected endpoint = %q, want %q", c.endpoint, server.endpoint)
	}
	if elapsed < timeout/2 || elapsed > 2*time.Second {
		t.Errorf("Dial took %v with %v endpoint timeout", elapsed, timeout)
	}
}

func TestDialUntrustedHostKeyStopsFailover(t *testing.T) {
	prepareDialEnvironment(t)
	untrustedSigner := testHostSigner(t)
	trustedSigner := testHostSigner(t)
	first := startTestSSHServer(t, untrustedSigner, nil, true)
	second := startTestSSHServer(t, trustedSigner, nil, true)

	cfg := testClientConfig(t, []string{first.endpoint, second.endpoint}, trustedSigner)
	_, err := Dial(cfg)
	if !errors.Is(err, errUntrustedHostKey) {
		t.Fatalf("Dial error = %v, want untrusted host key", err)
	}
	if got := second.accepts.Load(); got != 0 {
		t.Errorf("secondary accepted %d connections after untrusted host key", got)
	}
}

func TestDialAuthenticationRejectionStopsFailover(t *testing.T) {
	prepareDialEnvironment(t)
	rejectSigner := testHostSigner(t)
	goodSigner := testHostSigner(t)
	first := startTestSSHServer(t, rejectSigner, func(cfg *ssh.ServerConfig) {
		cfg.PublicKeyCallback = func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("denied")
		}
	}, true)
	second := startTestSSHServer(t, goodSigner, nil, true)

	cfg := testClientConfig(t, []string{first.endpoint, second.endpoint}, rejectSigner, goodSigner)
	_, err := Dial(cfg)
	if !errors.Is(err, errAuthenticationRejected) {
		t.Fatalf("Dial error = %v, want authentication rejection", err)
	}
	if got := second.accepts.Load(); got != 0 {
		t.Errorf("secondary accepted %d connections after authentication rejection", got)
	}
}

func TestDialAllEndpointsUnavailableIncludesEveryError(t *testing.T) {
	prepareDialEnvironment(t)
	signer := testHostSigner(t)
	first := closedEndpoint(t)
	second := closedEndpoint(t)
	cfg := testClientConfig(t, []string{first, second}, signer)

	_, err := Dial(cfg)
	if err == nil {
		t.Fatal("Dial should fail")
	}
	for _, want := range []string{"unable to contact any configured endpoint", first, second} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Dial error %q does not contain %q", err, want)
		}
	}
}

type testSSHServer struct {
	endpoint string
	accepts  atomic.Int32
}

func startTestSSHServer(t *testing.T, signer ssh.Signer, configure func(*ssh.ServerConfig), serveSFTP bool) *testSSHServer {
	t.Helper()
	cfg := &ssh.ServerConfig{NoClientAuth: configure == nil}
	if configure != nil {
		configure(cfg)
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	server := &testSSHServer{endpoint: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			server.accepts.Add(1)
			go serveTestSSH(conn, cfg, serveSFTP)
		}
	}()
	return server
}

func serveTestSSH(netConn net.Conn, cfg *ssh.ServerConfig, serveSFTP bool) {
	conn, chans, reqs, err := ssh.NewServerConn(netConn, cfg)
	if err != nil {
		_ = netConn.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for request := range requests {
				if request.Type != "subsystem" || len(request.Payload) < 4 || string(request.Payload[4:]) != "sftp" {
					_ = request.Reply(false, nil)
					continue
				}
				if !serveSFTP {
					_ = request.Reply(false, nil)
					return
				}
				_ = request.Reply(true, nil)
				server, err := sftp.NewServer(channel)
				if err != nil {
					return
				}
				_ = server.Serve()
				_ = server.Close()
				return
			}
		}()
	}
}

func startStalledServer(t *testing.T) (string, *atomic.Bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := &atomic.Bool{}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted.Store(true)
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
	}()
	return ln.Addr().String(), accepted
}

func testHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func trustedKeyLine(signer ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func testClientConfig(t *testing.T, addresses []string, signers ...ssh.Signer) *config.Client {
	t.Helper()
	endpoints := make([]config.ClientEndpoint, 0, len(addresses))
	for _, address := range addresses {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatal(err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			t.Fatal(err)
		}
		endpoints = append(endpoints, config.ClientEndpoint{Host: host, SSHPort: port})
	}
	trusted := make([]string, 0, len(signers))
	for _, signer := range signers {
		trusted = append(trusted, trustedKeyLine(signer))
	}
	return &config.Client{Endpoints: endpoints, TrustedKeys: trusted}
}

func closedEndpoint(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func prepareDialEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("PDS_ENDPOINT", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USER", "test-client")
}
