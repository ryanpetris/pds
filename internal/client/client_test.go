package client

import (
	"testing"

	"petris.net/pds/internal/config"
)

func TestResolveEndpoint(t *testing.T) {
	t.Setenv("PDS_ENDPOINT", "")
	cfg := &config.Client{Host: "pds.example.com", SSHPort: 2222}
	if got, err := ResolveEndpoint(cfg); err != nil || got != "pds.example.com:2222" {
		t.Errorf("ResolveEndpoint = %q, %v", got, err)
	}
	// PDS_ENDPOINT overrides host/sshPort.
	t.Setenv("PDS_ENDPOINT", "other:22")
	if got, err := ResolveEndpoint(cfg); err != nil || got != "other:22" {
		t.Errorf("ResolveEndpoint override = %q, %v", got, err)
	}
}

func TestResolveEndpointMissingFields(t *testing.T) {
	t.Setenv("PDS_ENDPOINT", "")
	if _, err := ResolveEndpoint(&config.Client{SSHPort: 2222}); err == nil {
		t.Errorf("ResolveEndpoint without host should error")
	}
	if _, err := ResolveEndpoint(&config.Client{Host: "h"}); err == nil {
		t.Errorf("ResolveEndpoint without sshPort should error")
	}
}

func TestResolveEndpointIPv6(t *testing.T) {
	t.Setenv("PDS_ENDPOINT", "")
	for _, host := range []string{"::1", "[::1]"} {
		cfg := &config.Client{Host: host, SSHPort: 2222}
		if got, err := ResolveEndpoint(cfg); err != nil || got != "[::1]:2222" {
			t.Errorf("ResolveEndpoint(%q) = %q, %v, want [::1]:2222", host, got, err)
		}
	}
}

func TestResolveHTTPURL(t *testing.T) {
	t.Setenv("PDS_ENDPOINT", "")

	// httpPort unset -> error.
	if _, err := ResolveHTTPURL(&config.Client{Host: "h", SSHPort: 22}); err == nil {
		t.Errorf("ResolveHTTPURL without httpPort should error")
	}

	cfg := &config.Client{Host: "pds.example.com", SSHPort: 2222, HTTPPort: 8080}
	if got, err := ResolveHTTPURL(cfg); err != nil || got != "http://pds.example.com:8080" {
		t.Errorf("ResolveHTTPURL = %q, %v", got, err)
	}

	// IPv6 host is bracketed.
	v6 := &config.Client{Host: "::1", SSHPort: 2222, HTTPPort: 8080}
	if got, err := ResolveHTTPURL(v6); err != nil || got != "http://[::1]:8080" {
		t.Errorf("ResolveHTTPURL(v6) = %q, %v", got, err)
	}
}
