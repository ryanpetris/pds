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

	"petris.dev/pds/internal/config"
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
// set keyed by wire encoding, for client-side host-key pinning. The client pins
// host-key negotiation to ed25519, so every trusted key must be an ed25519 key; any
// other format (ecdsa, rsa, dsa, host certificate, …) is rejected rather than silently
// ignored, since it could never be negotiated and matched.
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
		if pk.Type() != ssh.KeyAlgoED25519 {
			return nil, fmt.Errorf("trusted key %q: only ed25519 host keys are supported, got %s", ln, pk.Type())
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
// authenticates as, built from the server's authorizedKeys config. Non-ed25519 keys are
// ignored (the system standardizes on ed25519) and reported in warnings rather than
// failing, so a stray key of another type doesn't take the server down. A key that
// cannot be parsed at all is still a hard error. The returned map may be empty (e.g.
// every entry was ignored); the caller decides whether that is acceptable (it is for an
// anonymous-capable server).
func ClientHostMap(entries []config.ClientEntry) (m map[string]string, warnings []string, err error) {
	m = make(map[string]string)
	for _, ce := range entries {
		for _, k := range ce.Keys {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			pk, err := ParsePublicKey(k)
			if err != nil {
				return nil, warnings, fmt.Errorf("authorizedKeys host %q key %q: %w", ce.Host, k, err)
			}
			if pk.Type() != ssh.KeyAlgoED25519 {
				warnings = append(warnings, fmt.Sprintf("authorizedKeys host %q: ignoring non-ed25519 key (%s)", ce.Host, pk.Type()))
				continue
			}
			m[blob(pk)] = ce.Host
		}
	}
	return m, warnings, nil
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
