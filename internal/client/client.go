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

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"petris.net/pds/internal/config"
	"petris.net/pds/internal/sshkeys"
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

// ResolveEndpoint returns the SSH endpoint to dial as host:port. PDS_ENDPOINT overrides
// the configured host/sshPort. IPv6 hosts are bracketed via net.JoinHostPort. It errors
// if neither PDS_ENDPOINT nor a complete host/sshPort is configured.
func ResolveEndpoint(cfg *config.Client) (string, error) {
	if v := os.Getenv("PDS_ENDPOINT"); v != "" {
		return v, nil
	}
	if cfg.Host == "" {
		return "", fmt.Errorf("host is not configured")
	}
	if cfg.SSHPort <= 0 {
		return "", fmt.Errorf("sshPort is not configured")
	}
	return net.JoinHostPort(normHost(cfg.Host), strconv.Itoa(cfg.SSHPort)), nil
}

// ResolveHTTPURL returns the read-only HTTP base URL (http://host:port) for the server,
// using the configured httpPort. The host follows PDS_ENDPOINT when set so it tracks the
// SSH dial target. It errors when httpPort or host is not configured.
func ResolveHTTPURL(cfg *config.Client) (string, error) {
	if cfg.HTTPPort <= 0 {
		return "", fmt.Errorf("httpPort is not configured")
	}
	host := normHost(cfg.Host)
	if v := os.Getenv("PDS_ENDPOINT"); v != "" {
		if h, _, err := net.SplitHostPort(v); err == nil {
			host = h
		}
	}
	if host == "" {
		return "", fmt.Errorf("host is not configured")
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(cfg.HTTPPort)), nil
}

// normHost strips a single surrounding [...] pair so a config host of "[::1]" or "::1"
// both work; net.JoinHostPort re-adds brackets for IPv6 as needed.
func normHost(h string) string {
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		return h[1 : len(h)-1]
	}
	return h
}

// Dial connects to the configured endpoint (PDS_ENDPOINT overrides), verifying the
// server host key against the trusted pool. It authenticates with the user's SSH
// identities and, if the server rejects them (or none are available), automatically
// retries read-only as the anonymous user. A host-key mismatch or network failure is
// never downgraded — those abort.
func Dial(cfg *config.Client) (*Client, error) {
	endpoint, err := ResolveEndpoint(cfg)
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
	if len(signers) > 0 {
		c, err := dialSSH(endpoint, keyConfig(signers, hostKey))
		if err == nil {
			return c, nil
		}
		// Only downgrade to anonymous when the server rejected our credentials —
		// never on a host-key mismatch or a network error.
		if errors.Is(err, errUntrustedHostKey) || !authRejected(err) {
			return nil, err
		}
		fmt.Fprintln(os.Stderr, "pds: key authentication rejected; connecting anonymously (read-only)")
	}
	return dialSSH(endpoint, anonConfig(hostKey))
}

// keyConfig builds a client config that authenticates by public key as the local user.
func keyConfig(signers []ssh.Signer, hostKey ssh.HostKeyCallback) *ssh.ClientConfig {
	user := os.Getenv("USER")
	if user == "" {
		user = "pds"
	}
	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: hostKey,
	}
}

// anonConfig builds a keyless client config; the server's anonymous fallback keys off
// the reserved user name.
func anonConfig(hostKey ssh.HostKeyCallback) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            config.AnonymousUser,
		HostKeyCallback: hostKey,
	}
}

// dialSSH establishes one SSH connection with the given config and opens SFTP over it.
func dialSSH(endpoint string, sshCfg *ssh.ClientConfig) (*Client, error) {
	conn, err := ssh.Dial("tcp", endpoint, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", endpoint, err)
	}
	sc, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
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
