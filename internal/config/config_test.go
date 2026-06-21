package config

import (
	"os"
	"path/filepath"
	"testing"
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
listen: ":1"
authorizedKeys:
  - host: web01
    keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBASE base"]
buckets:
  scripts:
    path: /srv/scripts
    mode: ro
`)
	// Drop-in overrides listen and adds a bucket; lists union.
	write(filepath.Join(dir, "config.d", "10-extra.yaml"), `
listen: ":2222"
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
	if s.Listen != ":2222" {
		t.Errorf("drop-in should override listen, got %q", s.Listen)
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
listen: ":1"
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
		Listen:         ":1",
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
		Listen:         ":1",
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
			Listen:         ":1",
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

func TestValidateClientRequired(t *testing.T) {
	if err := (&Client{}).Validate(); err == nil {
		t.Fatalf("empty client config must fail")
	}
	c := &Client{Endpoint: "h:22", TrustedKeys: []string{"k"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid client config failed: %v", err)
	}
}
