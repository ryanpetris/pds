package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMergeMap(t *testing.T) {
	dst := map[string]any{
		"scalar": "old",
		"list":   []any{"a", "b"},
		"nested": map[string]any{"keep": 1, "over": "old"},
	}
	src := map[string]any{
		"scalar": "new",
		"list":   []any{"b", "c"},
		"nested": map[string]any{"over": "new", "add": 2},
	}
	mergeMap(dst, src)

	if dst["scalar"] != "new" {
		t.Errorf("scalar override failed: %v", dst["scalar"])
	}
	list := dst["list"].([]any)
	if len(list) != 3 { // a, b, c (b deduped)
		t.Errorf("list union failed: %v", list)
	}
	nested := dst["nested"].(map[string]any)
	if nested["keep"] != 1 || nested["over"] != "new" || nested["add"] != 2 {
		t.Errorf("nested merge failed: %v", nested)
	}
}

func TestMergeConfigMapClientEndpointsReplace(t *testing.T) {
	dst := map[string]any{
		"endpoints":   []any{map[string]any{"host": "old", "sshPort": 22}},
		"trustedKeys": []any{"old-key"},
	}
	src := map[string]any{
		"endpoints":   []any{map[string]any{"host": "new", "sshPort": 2222}},
		"trustedKeys": []any{"new-key"},
	}
	mergeConfigMap(dst, src, RoleClient)

	endpoints := dst["endpoints"].([]any)
	if len(endpoints) != 1 || endpoints[0].(map[string]any)["host"] != "new" {
		t.Errorf("client endpoints should be replaced, got %v", endpoints)
	}
	keys := dst["trustedKeys"].([]any)
	if len(keys) != 2 {
		t.Errorf("other client lists should still be unioned, got %v", keys)
	}
}

func TestMergeConfigMapServerEndpointsStillUnion(t *testing.T) {
	dst := map[string]any{"endpoints": []any{"a"}}
	src := map[string]any{"endpoints": []any{"b"}}
	mergeConfigMap(dst, src, RoleServer)

	endpoints := dst["endpoints"].([]any)
	if len(endpoints) != 2 {
		t.Errorf("server lists should retain generic union behavior, got %v", endpoints)
	}
}

func TestClientEndpointsReplaceAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	override := filepath.Join(dir, "override.yaml")
	if err := os.WriteFile(base, []byte(`
endpoints:
  - host: primary.example
    sshPort: 22
  - host: secondary.example
    sshPort: 22
trustedKeys: [base-key]
identities: [base-identity]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(override, []byte(`
endpoints:
  - host: override.example
    sshPort: 2222
trustedKeys: [override-key]
identities: [override-identity]
`), 0o644); err != nil {
		t.Fatal(err)
	}

	merged := map[string]any{}
	if err := mergeFile(merged, base, RoleClient); err != nil {
		t.Fatal(err)
	}
	if err := mergeFile(merged, override, RoleClient); err != nil {
		t.Fatal(err)
	}
	var client Client
	if err := decode(merged, &client); err != nil {
		t.Fatal(err)
	}
	if len(client.Endpoints) != 1 || client.Endpoints[0].Host != "override.example" {
		t.Errorf("endpoints were not replaced by the later file: %+v", client.Endpoints)
	}
	if len(client.TrustedKeys) != 2 || len(client.Identities) != 2 {
		t.Errorf("non-endpoint lists should be unioned: trusted=%v identities=%v", client.TrustedKeys, client.Identities)
	}
}

func TestLayeredLoadAndPrecedence(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	dir := filepath.Join(xdg, "pds", "server")
	if err := os.MkdirAll(filepath.Join(dir, "config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, body string) {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "config.yaml"), `
sshListen: ":1"
authorizedKeys:
  - host: web01
    keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBASE base"]
buckets:
  scripts:
    path: /srv/scripts
    mode: ro
`)
	// Drop-in overrides sshListen and adds a bucket; lists union.
	write(filepath.Join(dir, "config.d", "10-extra.yaml"), `
sshListen: ":2222"
buckets:
  metrics:
    path: /data/metrics
    mode: rw
    extension: yaml
    validator: yaml
`)

	merged, err := loadMerged(RoleServer, "")
	if err != nil {
		t.Fatalf("loadMerged: %v", err)
	}
	var s Server
	if err := decode(merged, &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if s.SSHListen != ":2222" {
		t.Errorf("drop-in should override sshListen, got %q", s.SSHListen)
	}
	if len(s.Buckets) != 2 {
		t.Errorf("expected 2 buckets, got %d", len(s.Buckets))
	}
	if err := s.Validate(); err != nil {
		t.Errorf("merged config should validate: %v", err)
	}
}

func TestLoadServerExpandsBucketHome(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	dir := filepath.Join(xdg, "pds", "server")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `
sshListen: ":1"
authorizedKeys:
  - host: web01
    keys: ["ssh-ed25519 AAAAEXAMPLE web01"]
buckets:
  data:
    path: "~/buckets/data"
    mode: ro
  abs:
    path: "/srv/abs"
    mode: ro
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := LoadServer("")
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if got, want := s.Buckets["data"].Path, filepath.Join(home, "buckets/data"); got != want {
		t.Errorf("~ not expanded: got %q want %q", got, want)
	}
	if got := s.Buckets["abs"].Path; got != "/srv/abs" {
		t.Errorf("absolute path changed: %q", got)
	}
}

func TestValidateExecBucketMustBeRO(t *testing.T) {
	s := Server{
		SSHListen:      ":1",
		AuthorizedKeys: []ClientEntry{{Host: "h", Keys: []string{"k"}}},
		ExecBucket:     "scripts",
		Buckets: map[string]Bucket{
			"scripts": {Path: "/s", Mode: "rw", Extension: "sh", Validator: "none"},
		},
	}
	if err := s.Validate(); err == nil {
		t.Fatalf("execBucket pointing at an rw bucket must fail validation")
	}
	s.Buckets["scripts"] = Bucket{Path: "/s", Mode: "ro"}
	if err := s.Validate(); err != nil {
		t.Fatalf("ro execBucket should validate: %v", err)
	}
}

func TestValidateRWNeedsValidator(t *testing.T) {
	s := Server{
		SSHListen:      ":1",
		AuthorizedKeys: []ClientEntry{{Host: "h", Keys: []string{"k"}}},
		Buckets: map[string]Bucket{
			"m": {Path: "/m", Mode: "rw", Extension: "yaml"}, // no validator
		},
	}
	if err := s.Validate(); err == nil {
		t.Fatalf("rw bucket without validator must fail")
	}
}

func TestValidateExtension(t *testing.T) {
	mk := func(ext string) *Server {
		return &Server{
			SSHListen:      ":1",
			AuthorizedKeys: []ClientEntry{{Host: "h", Keys: []string{"k"}}},
			Buckets:        map[string]Bucket{"m": {Path: "/m", Mode: "rw", Extension: ext, Validator: "none"}},
		}
	}
	for _, bad := range []string{"../x", "/x", ".", "..", "a/b", "x.."} {
		if err := mk(bad).Validate(); err == nil {
			t.Errorf("extension %q should be rejected", bad)
		}
	}
	for _, ok := range []string{"yaml", "json", "tar.gz", "txt"} {
		if err := mk(ok).Validate(); err != nil {
			t.Errorf("extension %q should be accepted: %v", ok, err)
		}
	}
}

func TestValidateAnonymousReplacesAuthorizedKeys(t *testing.T) {
	// No authorizedKeys and no allowAnonymous: must fail.
	s := &Server{SSHListen: ":1"}
	if err := s.Validate(); err == nil {
		t.Fatalf("server without authorizedKeys or allowAnonymous must fail")
	}
	// allowAnonymous alone satisfies the auth requirement.
	s.AllowAnonymous = true
	if err := s.Validate(); err != nil {
		t.Fatalf("allowAnonymous-only server should validate: %v", err)
	}
}

func TestValidateClientRequired(t *testing.T) {
	if err := (&Client{}).Validate(); err == nil {
		t.Fatalf("empty client config must fail")
	}
	if err := (&Client{Endpoints: []ClientEndpoint{{Host: "h"}}, TrustedKeys: []string{"k"}}).Validate(); err == nil {
		t.Fatalf("client config without sshPort must fail")
	}
	if err := (&Client{Endpoints: []ClientEndpoint{{Host: "h", SSHPort: 22}}}).Validate(); err == nil {
		t.Fatalf("client config without trustedKeys must fail")
	}
	c := &Client{Endpoints: []ClientEndpoint{{Host: "h", SSHPort: 22}}, TrustedKeys: []string{"k"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid client config failed: %v", err)
	}
	c.Endpoints[0].HTTPPort = 8080
	if err := c.Validate(); err != nil {
		t.Fatalf("client config with httpPort failed: %v", err)
	}
}

func TestValidateClientEndpoints(t *testing.T) {
	valid := func(endpoints ...ClientEndpoint) *Client {
		return &Client{Endpoints: endpoints, TrustedKeys: []string{"k"}}
	}
	tests := []struct {
		name string
		cfg  *Client
	}{
		{"blank host", valid(ClientEndpoint{Host: " \t", SSHPort: 22})},
		{"zero ssh port", valid(ClientEndpoint{Host: "h", SSHPort: 0})},
		{"negative ssh port", valid(ClientEndpoint{Host: "h", SSHPort: -1})},
		{"large ssh port", valid(ClientEndpoint{Host: "h", SSHPort: 65536})},
		{"negative http port", valid(ClientEndpoint{Host: "h", SSHPort: 22, HTTPPort: -1})},
		{"large http port", valid(ClientEndpoint{Host: "h", SSHPort: 22, HTTPPort: 65536})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.cfg.Validate(); err == nil {
				t.Fatalf("invalid client config passed validation: %+v", test.cfg)
			}
		})
	}

	if err := valid(
		ClientEndpoint{Host: "one.example", SSHPort: 22},
		ClientEndpoint{Host: "two.example", SSHPort: 2222, HTTPPort: 8080},
	).Validate(); err != nil {
		t.Fatalf("multiple valid endpoints failed validation: %v", err)
	}
}

func TestValidateClientRejectsDuplicateNormalizedEndpoints(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
	}{
		{"exact", "host.example", "host.example"},
		{"dns case and whitespace", "HOST.Example", " host.example "},
		{"IPv6 brackets and spelling", "[0:0:0:0:0:0:0:1]", "::1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &Client{
				Endpoints: []ClientEndpoint{
					{Host: test.a, SSHPort: 22},
					{Host: test.b, SSHPort: 22, HTTPPort: 8080},
				},
				TrustedKeys: []string{"k"},
			}
			if err := cfg.Validate(); err == nil {
				t.Fatalf("duplicate endpoints %q and %q passed validation", test.a, test.b)
			}
		})
	}

	cfg := &Client{
		Endpoints: []ClientEndpoint{
			{Host: "host.example", SSHPort: 22},
			{Host: "host.example", SSHPort: 2222},
		},
		TrustedKeys: []string{"k"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("same host on different SSH ports should be allowed: %v", err)
	}
}

func TestClientDialTimeout(t *testing.T) {
	if got := (&Client{}).EffectiveDialTimeout(); got != DefaultDialTimeout {
		t.Fatalf("omitted dialTimeout = %v, want %v", got, DefaultDialTimeout)
	}

	var decoded Client
	if err := decode(map[string]any{"dialTimeout": "10s"}, &decoded); err != nil {
		t.Fatalf("decode duration string: %v", err)
	}
	if decoded.DialTimeout == nil || *decoded.DialTimeout != 10*time.Second {
		t.Fatalf("decoded dialTimeout = %v, want 10s", decoded.DialTimeout)
	}
	if got := decoded.EffectiveDialTimeout(); got != 10*time.Second {
		t.Fatalf("EffectiveDialTimeout = %v, want 10s", got)
	}

	if err := decode(map[string]any{"dialTimeout": "soon"}, &decoded); err == nil {
		t.Fatalf("malformed dialTimeout should fail decoding")
	}
	for _, timeout := range []time.Duration{0, -time.Second} {
		cfg := &Client{
			Endpoints:   []ClientEndpoint{{Host: "h", SSHPort: 22}},
			DialTimeout: &timeout,
			TrustedKeys: []string{"k"},
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("explicit dialTimeout %v should fail validation", timeout)
		}
	}
}

func TestClientLegacyAddressFieldsAreRejected(t *testing.T) {
	var client Client
	if err := decode(map[string]any{
		"host":     "legacy.example",
		"sshPort":  22,
		"httpPort": 8080,
	}, &client); err == nil {
		t.Fatalf("legacy top-level client address fields should be unknown")
	}
}

func TestLoadClientUnvalidatedSkipsRequirements(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	dir := filepath.Join(xdg, "pds", "client")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// An endpoint-only config: no sshPort, no trustedKeys.
	body := "endpoints:\n  - host: mirror.example.com\n    httpPort: 8080\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	// Full load enforces the client contract and fails.
	if _, err := LoadClient(""); err == nil {
		t.Fatalf("LoadClient should fail without sshPort/trustedKeys")
	}
	// Unvalidated load succeeds for endpoint-only use.
	c, err := LoadClientUnvalidated("")
	if err != nil {
		t.Fatalf("LoadClientUnvalidated: %v", err)
	}
	if len(c.Endpoints) != 1 || c.Endpoints[0].Host != "mirror.example.com" || c.Endpoints[0].HTTPPort != 8080 {
		t.Errorf("decoded = %+v", c)
	}
	if got := c.EffectiveDialTimeout(); got != 10*time.Second {
		t.Errorf("default dial timeout = %v, want 10s", got)
	}
}

func TestValidateHTTPRequiresAnonymous(t *testing.T) {
	s := &Server{
		SSHListen:      ":1",
		HTTPListen:     ":8080",
		AuthorizedKeys: []ClientEntry{{Host: "h", Keys: []string{"k"}}},
	}
	if err := s.Validate(); err == nil {
		t.Fatalf("httpListen without allowAnonymous must fail")
	}
	s.AllowAnonymous = true
	if err := s.Validate(); err != nil {
		t.Fatalf("httpListen with allowAnonymous should validate: %v", err)
	}
}

func TestParseEndpoint(t *testing.T) {
	ok := []struct {
		in   string
		want EndpointSpec
	}{
		{":2222", EndpointSpec{Addr: ":2222"}},
		{"127.0.0.1:2222", EndpointSpec{Addr: "127.0.0.1:2222"}},
		{"[::1]:2222", EndpointSpec{Addr: "[::1]:2222"}},
		{"myhost.example:2222", EndpointSpec{Addr: "myhost.example:2222"}}, // hostname stays static
		{"iface:eth0:2222", EndpointSpec{Iface: "eth0", Port: "2222"}},
		{"iface:tailscale0:443", EndpointSpec{Iface: "tailscale0", Port: "443"}},
	}
	for _, c := range ok {
		got, err := parseEndpoint(c.in)
		if err != nil {
			t.Errorf("parseEndpoint(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseEndpoint(%q) = %+v, want %+v", c.in, got, c.want)
		}
		if got.Static() != (c.want.Iface == "") {
			t.Errorf("parseEndpoint(%q).Static() = %v", c.in, got.Static())
		}
	}

	bad := []string{
		"2222",            // no port separator
		":",               // missing port
		"iface:eth0",      // interface with no port
		"iface::2222",     // interface with no name
		"iface:",          // empty
		"iface:e:t:h0:22", // name with colons survives SplitHostPort oddly -> invalid
	}
	for _, in := range bad {
		if _, err := parseEndpoint(in); err == nil {
			t.Errorf("parseEndpoint(%q) should have errored", in)
		}
	}
}

func TestServerEndpointAccessors(t *testing.T) {
	s := &Server{SSHListen: "iface:eth0:2222", HTTPListen: ""}
	l, err := s.SSHEndpoint()
	if err != nil || l.Iface != "eth0" || l.Port != "2222" {
		t.Fatalf("SSHEndpoint = %+v, %v", l, err)
	}
	if _, ok, _ := s.HTTPEndpoint(); ok {
		t.Errorf("HTTPEndpoint should report not configured when httpListen is empty")
	}

	s.HTTPListen = "iface:eth0:8080"
	h, ok, err := s.HTTPEndpoint()
	if err != nil || !ok || h.Iface != "eth0" || h.Port != "8080" {
		t.Fatalf("HTTPEndpoint = %+v, ok=%v, err=%v", h, ok, err)
	}
}
