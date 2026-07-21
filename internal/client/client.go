// Package client implements pds: it dials a pdsd endpoint over SSH (pinning the
// server host key against a trusted pool), authenticates with the user's SSH
// identities, and exposes bucket operations over SFTP.
package client

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"petris.dev/pds/internal/config"
	"petris.dev/pds/internal/sshkeys"
)

// Client is a connected pds session.
type Client struct {
	endpoint string
	ssh      *ssh.Client
	sftp     *sftp.Client
}

// errUntrustedHostKey is the sentinel returned by the host-key callback when the
// server's key is not in the trusted pool. It lets Dial tell a host-key rejection
// (possible MITM — never fall back) apart from a credentials rejection.
var errUntrustedHostKey = errors.New("untrusted server host key")

// errAuthenticationRejected marks an endpoint that was reached but rejected both the
// configured identities and the anonymous fallback. Trying another endpoint would hide
// a credentials or server-policy problem, so Dial treats it as terminal.
var errAuthenticationRejected = errors.New("SSH authentication rejected")

// ResolveEndpoints returns the configured SSH endpoints in attempt order. PDS_ENDPOINT
// remains a singular hard override, which also keeps pds exec children pinned to the
// server selected by their parent. IPv6 hosts are bracketed via net.JoinHostPort.
func ResolveEndpoints(cfg *config.Client) ([]string, error) {
	if v := os.Getenv("PDS_ENDPOINT"); v != "" {
		return []string{v}, nil
	}
	if cfg == nil || len(cfg.Endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints are configured")
	}

	endpoints := make([]string, 0, len(cfg.Endpoints))
	for i, endpoint := range cfg.Endpoints {
		resolved, err := resolveEndpoint(endpoint)
		if err != nil {
			return nil, fmt.Errorf("endpoint %d: %w", i+1, err)
		}
		endpoints = append(endpoints, resolved)
	}
	return endpoints, nil
}

// ResolveHTTPURLs returns configured read-only HTTP base URLs in endpoint order,
// omitting endpoints without an HTTP port. Under PDS_ENDPOINT it returns only the URL
// belonging to the matching configured SSH endpoint; the override cannot safely borrow
// an HTTP port from a different server.
func ResolveHTTPURLs(cfg *config.Client) ([]string, error) {
	if cfg == nil || len(cfg.Endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints are configured")
	}

	if v := os.Getenv("PDS_ENDPOINT"); v != "" {
		for i, endpoint := range cfg.Endpoints {
			// HTTP-only entries cannot be the source of an SSH endpoint override.
			if strings.TrimSpace(endpoint.Host) == "" || endpoint.SSHPort <= 0 || endpoint.SSHPort > 65535 {
				continue
			}
			sshEndpoint, err := resolveEndpoint(endpoint)
			if err != nil {
				return nil, fmt.Errorf("endpoint %d: %w", i+1, err)
			}
			if !sameEndpoint(v, sshEndpoint) {
				continue
			}
			url, err := resolveHTTPURL(endpoint)
			if err != nil {
				return nil, fmt.Errorf("endpoint %d: %w", i+1, err)
			}
			return []string{url}, nil
		}
		return nil, fmt.Errorf("PDS_ENDPOINT %q does not match a configured endpoint", v)
	}

	urls := make([]string, 0, len(cfg.Endpoints))
	for i, endpoint := range cfg.Endpoints {
		if endpoint.HTTPPort == 0 {
			continue
		}
		url, err := resolveHTTPURL(endpoint)
		if err != nil {
			return nil, fmt.Errorf("endpoint %d: %w", i+1, err)
		}
		urls = append(urls, url)
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("httpPort is not configured for any endpoint")
	}
	return urls, nil
}

func resolveEndpoint(endpoint config.ClientEndpoint) (string, error) {
	if strings.TrimSpace(endpoint.Host) == "" {
		return "", fmt.Errorf("host is not configured")
	}
	if endpoint.SSHPort <= 0 || endpoint.SSHPort > 65535 {
		return "", fmt.Errorf("sshPort must be between 1 and 65535")
	}
	return net.JoinHostPort(normHost(endpoint.Host), strconv.Itoa(endpoint.SSHPort)), nil
}

func resolveHTTPURL(endpoint config.ClientEndpoint) (string, error) {
	if strings.TrimSpace(endpoint.Host) == "" {
		return "", fmt.Errorf("host is not configured")
	}
	if endpoint.HTTPPort <= 0 || endpoint.HTTPPort > 65535 {
		return "", fmt.Errorf("httpPort must be between 1 and 65535")
	}
	return "http://" + net.JoinHostPort(normHost(endpoint.Host), strconv.Itoa(endpoint.HTTPPort)), nil
}

// sameEndpoint compares host:port values semantically so harmless differences such as
// IPv6 brackets, hostname case, or a leading zero in the port do not break override
// matching for ResolveHTTPURLs.
func sameEndpoint(a, b string) bool {
	ah, ap, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	bh, bp, err := net.SplitHostPort(b)
	if err != nil {
		return false
	}
	api, err := strconv.Atoi(ap)
	if err != nil {
		return false
	}
	bpi, err := strconv.Atoi(bp)
	if err != nil {
		return false
	}
	return strings.EqualFold(normHost(ah), normHost(bh)) && api == bpi
}

// normHost strips a single surrounding [...] pair so a config host of "[::1]" or "::1"
// both work; net.JoinHostPort re-adds brackets for IPv6 as needed.
func normHost(h string) string {
	h = strings.TrimSpace(h)
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		return h[1 : len(h)-1]
	}
	return h
}

// Dial tries the configured endpoints in order and returns the first usable SSH+SFTP
// session. Trust and identities are loaded once. Each endpoint gets one absolute
// deadline covering TCP, SSH authentication (including same-endpoint anonymous
// fallback), and SFTP startup. Availability and protocol failures advance to the next
// endpoint; an untrusted host key or exhausted authentication is terminal.
func Dial(cfg *config.Client) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("client config is nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	endpoints, err := ResolveEndpoints(cfg)
	if err != nil {
		return nil, err
	}

	trusted, err := sshkeys.TrustedSet(cfg.TrustedKeys)
	if err != nil {
		return nil, err
	}
	hostKey := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if sshkeys.Trusted(trusted, key) {
			return nil
		}
		return fmt.Errorf("%w %s", errUntrustedHostKey, ssh.FingerprintSHA256(key))
	}

	signers, err := loadIdentities(cfg.Identities)
	if err != nil {
		return nil, err
	}

	var endpointErrors []error
	for _, endpoint := range endpoints {
		deadline := time.Now().Add(cfg.EffectiveDialTimeout())
		c, err := dialEndpoint(endpoint, signers, hostKey, deadline)
		if err == nil {
			return c, nil
		}
		labelled := fmt.Errorf("%s: %w", endpoint, err)
		if errors.Is(err, errUntrustedHostKey) || errors.Is(err, errAuthenticationRejected) {
			return nil, labelled
		}
		endpointErrors = append(endpointErrors, labelled)
	}
	return nil, fmt.Errorf("unable to contact any configured endpoint: %w", errors.Join(endpointErrors...))
}

// dialEndpoint performs keyed authentication first when identities are available, then
// retries the anonymous user only when the same server explicitly rejected those keys.
// Both connections share deadline, so fallback cannot extend the endpoint's budget.
func dialEndpoint(endpoint string, signers []ssh.Signer, hostKey ssh.HostKeyCallback, deadline time.Time) (*Client, error) {
	if len(signers) > 0 {
		c, err := dialSSH(endpoint, keyConfig(signers, hostKey), deadline)
		if err == nil {
			return c, nil
		}
		if errors.Is(err, errUntrustedHostKey) || !authRejected(err) {
			return nil, err
		}
	}

	c, err := dialSSH(endpoint, anonConfig(hostKey), deadline)
	if err != nil && authRejected(err) {
		return nil, fmt.Errorf("%w: %v", errAuthenticationRejected, err)
	}
	return c, err
}

// ed25519HostKeyAlgos pins host-key negotiation to ed25519: the only host-key type the
// client trusts (see sshkeys.TrustedSet). ed25519 has a single algorithm and no hash
// variants, so this is the complete set.
var ed25519HostKeyAlgos = []string{ssh.KeyAlgoED25519}

// keyConfig builds a client config that authenticates by public key as the local user.
func keyConfig(signers []ssh.Signer, hostKey ssh.HostKeyCallback) *ssh.ClientConfig {
	user := os.Getenv("USER")
	if user == "" {
		user = "pds"
	}
	return &ssh.ClientConfig{
		User:              user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback:   hostKey,
		HostKeyAlgorithms: ed25519HostKeyAlgos,
	}
}

// anonConfig builds a keyless client config; the server's anonymous fallback keys off
// the reserved user name.
func anonConfig(hostKey ssh.HostKeyCallback) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:              config.AnonymousUser,
		HostKeyCallback:   hostKey,
		HostKeyAlgorithms: ed25519HostKeyAlgos,
	}
}

// dialSSH establishes one SSH connection and opens SFTP before deadline. The network
// deadline is cleared only after the complete endpoint attempt succeeds.
func dialSSH(endpoint string, sshCfg *ssh.ClientConfig, deadline time.Time) (*Client, error) {
	dialer := net.Dialer{Deadline: deadline}
	netConn, err := dialer.Dial("tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("TCP dial: %w", err)
	}
	if err := netConn.SetDeadline(deadline); err != nil {
		netConn.Close()
		return nil, fmt.Errorf("setting connection deadline: %w", err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, endpoint, sshCfg)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}
	conn := ssh.NewClient(sshConn, chans, reqs)
	sc, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("starting SFTP: %w", err)
	}
	if err := netConn.SetDeadline(time.Time{}); err != nil {
		sc.Close()
		conn.Close()
		return nil, fmt.Errorf("clearing connection deadline: %w", err)
	}
	return &Client{endpoint: endpoint, ssh: conn, sftp: sc}, nil
}

// authRejected reports whether err is the SSH client's "no auth method succeeded"
// failure (as opposed to a transport/host-key/network error).
func authRejected(err error) bool {
	return strings.Contains(err.Error(), "unable to authenticate")
}

// Close releases the connection.
func (c *Client) Close() error {
	if c.sftp != nil {
		c.sftp.Close()
	}
	if c.ssh != nil {
		return c.ssh.Close()
	}
	return nil
}

// loadIdentities loads explicit identity files if configured, else falls back to
// ~/.ssh/id_*.
func loadIdentities(paths []string) ([]ssh.Signer, error) {
	if len(paths) == 0 {
		signers, _, err := sshkeys.LoadSigners(sshkeys.DefaultSSHDir())
		return signers, err
	}
	var signers []ssh.Signer
	for _, p := range paths {
		p = expandHome(p)
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", p, err)
		}
		s, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", p, err)
		}
		signers = append(signers, s)
	}
	return signers, nil
}

func expandHome(p string) string {
	if p == "~" {
		return os.Getenv("HOME")
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(os.Getenv("HOME"), p[2:])
	}
	return p
}
