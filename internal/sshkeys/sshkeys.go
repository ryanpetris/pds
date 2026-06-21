// Package sshkeys holds SSH key helpers shared by client and server: parsing
// authorized_keys-format public keys, loading host/identity private keys from a
// .ssh directory, and building the lookup structures used for authentication and
// host-key pinning.
package sshkeys

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"petris.net/pds/internal/config"
)

// ParsePublicKey parses a single authorized_keys-format line.
func ParsePublicKey(line string) (ssh.PublicKey, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// blob returns a stable string key for a public key (its SSH wire encoding).
func blob(pk ssh.PublicKey) string { return string(pk.Marshal()) }

// TrustedSet parses a list of authorized_keys-format public keys into a membership
// set keyed by wire encoding, for client-side host-key pinning.
func TrustedSet(lines []string) (map[string]bool, error) {
	set := make(map[string]bool, len(lines))
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		pk, err := ParsePublicKey(ln)
		if err != nil {
			return nil, fmt.Errorf("trusted key %q: %w", ln, err)
		}
		set[blob(pk)] = true
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("no usable trusted keys")
	}
	return set, nil
}

// Trusted reports whether pk is in the set.
func Trusted(set map[string]bool, pk ssh.PublicKey) bool { return set[blob(pk)] }

// ClientHostMap maps each authorized client public key to the host name it
// authenticates as, built from the server's authorizedKeys config.
func ClientHostMap(entries []config.ClientEntry) (map[string]string, error) {
	m := make(map[string]string)
	for _, ce := range entries {
		for _, k := range ce.Keys {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			pk, err := ParsePublicKey(k)
			if err != nil {
				return nil, fmt.Errorf("authorizedKeys host %q key %q: %w", ce.Host, k, err)
			}
			m[blob(pk)] = ce.Host
		}
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("no usable authorized client keys")
	}
	return m, nil
}

// HostFor returns the configured host name for an offered public key, if any.
func HostFor(m map[string]string, pk ssh.PublicKey) (string, bool) {
	h, ok := m[blob(pk)]
	return h, ok
}

// LoadSigners loads private keys matching id_* (excluding *.pub) from dir. Keys that
// cannot be parsed (e.g. passphrase-protected) are skipped and reported in skipped.
func LoadSigners(dir string) (signers []ssh.Signer, skipped []string, err error) {
	matches, err := filepath.Glob(filepath.Join(dir, "id_*"))
	if err != nil {
		return nil, nil, err
	}
	for _, p := range matches {
		if strings.HasSuffix(p, ".pub") {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		s, err := ssh.ParsePrivateKey(data)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		signers = append(signers, s)
	}
	return signers, skipped, nil
}

// DefaultSSHDir returns ~/.ssh.
func DefaultSSHDir() string {
	return filepath.Join(os.Getenv("HOME"), ".ssh")
}
