// Package client implements pds: it dials a pdsd endpoint over SSH (pinning the
// server host key against a trusted pool), authenticates with the user's SSH
// identities, and exposes bucket operations over SFTP.
package client

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// Dial connects to the configured endpoint (PDS_ENDPOINT overrides), verifying the
// server host key against the trusted pool and authenticating with SSH identities.
func Dial(cfg *config.Client) (*Client, error) {
	endpoint := cfg.Endpoint
	if v := os.Getenv("PDS_ENDPOINT"); v != "" {
		endpoint = v
	}

	trusted, err := sshkeys.TrustedSet(cfg.TrustedKeys)
	if err != nil {
		return nil, err
	}
	signers, err := loadIdentities(cfg.Identities)
	if err != nil {
		return nil, err
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("no usable SSH identities (check identities or ~/.ssh/id_*)")
	}

	user := os.Getenv("USER")
	if user == "" {
		user = "pds"
	}
	sshCfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if sshkeys.Trusted(trusted, key) {
				return nil
			}
			return fmt.Errorf("untrusted server host key %s", ssh.FingerprintSHA256(key))
		},
	}

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
