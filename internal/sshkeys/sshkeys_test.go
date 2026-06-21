package sshkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"petris.dev/pds/internal/config"
)

// pubLine returns an authorized_keys-format line for the SSH public key wrapping pub.
func pubLine(t *testing.T, pub interface{}) string {
	t.Helper()
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

func ed25519Line(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pubLine(t, pub)
}

func ecdsaLine(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pubLine(t, &k.PublicKey)
}

func rsaLine(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pubLine(t, &k.PublicKey)
}

func TestTrustedSetAcceptsEd25519(t *testing.T) {
	line := ed25519Line(t)
	set, err := TrustedSet([]string{line, "", "  "})
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := ParsePublicKey(line)
	if !Trusted(set, pk) {
		t.Error("ed25519 key should be trusted")
	}
}

func TestTrustedSetRejectsNonEd25519(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
	}{
		{"ecdsa", ecdsaLine(t)},
		{"rsa", rsaLine(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := TrustedSet([]string{tc.line}); err == nil {
				t.Errorf("%s trusted key should be rejected", tc.name)
			}
		})
	}
}

func TestTrustedSetRejectsMixedPool(t *testing.T) {
	// A single non-ed25519 entry in an otherwise valid pool is rejected, not ignored.
	if _, err := TrustedSet([]string{ed25519Line(t), ecdsaLine(t)}); err == nil {
		t.Error("pool containing a non-ed25519 key should be rejected")
	}
}

func TestTrustedSetEmptyAndBad(t *testing.T) {
	if _, err := TrustedSet(nil); err == nil {
		t.Error("empty trusted key list should error")
	}
	if _, err := TrustedSet([]string{"", "   "}); err == nil {
		t.Error("blank-only trusted key list should error")
	}
	if _, err := TrustedSet([]string{"not-a-key"}); err == nil {
		t.Error("unparseable trusted key should error")
	}
}

func TestClientHostMapKeepsEd25519(t *testing.T) {
	line := ed25519Line(t)
	m, warnings, err := ClientHostMap([]config.ClientEntry{{Host: "web01", Keys: []string{line}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	pk, _ := ParsePublicKey(line)
	if h, ok := HostFor(m, pk); !ok || h != "web01" {
		t.Errorf("HostFor = %q, %v; want web01, true", h, ok)
	}
}

func TestClientHostMapIgnoresNonEd25519WithWarning(t *testing.T) {
	ed := ed25519Line(t)
	m, warnings, err := ClientHostMap([]config.ClientEntry{
		{Host: "web01", Keys: []string{ed}},
		{Host: "web02", Keys: []string{ecdsaLine(t)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 {
		t.Errorf("map should contain only the ed25519 key, got %d entries", len(m))
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "web02") {
		t.Errorf("expected one warning mentioning web02, got %v", warnings)
	}
}

func TestClientHostMapAllIgnoredReturnsEmpty(t *testing.T) {
	// When every authorized key is ignored, the map is empty but it is NOT an error —
	// the caller (server.New) decides based on AllowAnonymous. Warnings explain why.
	m, warnings, err := ClientHostMap([]config.ClientEntry{{Host: "web01", Keys: []string{rsaLine(t)}}})
	if err != nil {
		t.Fatalf("all-ignored should not error: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("map should be empty, got %v", m)
	}
	if len(warnings) != 1 {
		t.Errorf("expected one warning, got %v", warnings)
	}
}

func TestClientHostMapUnparseableErrors(t *testing.T) {
	if _, _, err := ClientHostMap([]config.ClientEntry{{Host: "web01", Keys: []string{"garbage"}}}); err == nil {
		t.Error("unparseable authorized key should be a hard error")
	}
}
