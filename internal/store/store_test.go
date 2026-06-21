package store

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"petris.dev/pds/internal/config"
)

func TestCommitVersionedByHost(t *testing.T) {
	dir := t.TempDir()
	b := config.Bucket{Path: dir, Mode: "rw", Versioned: true, ByHost: true, Extension: "yaml", Validator: "yaml"}

	name, err := Commit(b, "web01", []byte("a: 1\n"))
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !strings.HasSuffix(name, ".yaml") || len(name) < len("20060102150405.yaml") {
		t.Fatalf("unexpected name %q", name)
	}
	hostDir := filepath.Join(dir, "web01")
	if _, err := os.Stat(filepath.Join(hostDir, name)); err != nil {
		t.Fatalf("dated file missing: %v", err)
	}
	link, err := os.Readlink(filepath.Join(hostDir, "latest.yaml"))
	if err != nil {
		t.Fatalf("latest symlink missing: %v", err)
	}
	if link != name {
		t.Fatalf("latest -> %q, want %q", link, name)
	}

	// Reading latest follows the symlink and confines to the bucket.
	f, err := Open(b, "web01/latest.yaml")
	if err != nil {
		t.Fatalf("open latest: %v", err)
	}
	data, _ := io.ReadAll(f)
	f.Close()
	if string(data) != "a: 1\n" {
		t.Fatalf("latest content = %q", data)
	}

	// Invalid content is rejected.
	if _, err := Commit(b, "web01", []byte("foo: [bar")); err == nil {
		t.Fatalf("invalid yaml should be rejected")
	}
}

func TestCommitArbitraryOverwrites(t *testing.T) {
	dir := t.TempDir()
	b := config.Bucket{Path: dir, Mode: "rw", Versioned: false, ByHost: false, Extension: "json", Validator: "json"}

	if _, err := Commit(b, "web01", []byte(`{"v":1}`)); err != nil {
		t.Fatalf("commit 1: %v", err)
	}
	if _, err := Commit(b, "web01", []byte(`{"v":2}`)); err != nil {
		t.Fatalf("commit 2: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	got := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("arbitrary bucket should hold a single file, got %d", got)
	}
	f, _ := Open(b, "latest.json")
	data, _ := io.ReadAll(f)
	f.Close()
	if string(data) != `{"v":2}` {
		t.Fatalf("latest.json = %q", data)
	}
}

func TestPusherRejectsBadOffsets(t *testing.T) {
	dir := t.TempDir()
	b := config.Bucket{Path: dir, Mode: "rw", Versioned: false, ByHost: false, Extension: "bin", Validator: "none"}

	// A negative offset must return an error, not panic (regression for the SFTP
	// uint64->int64 offset finding). No committer is needed: these never Finish.
	p, err := NewPusher(nil, b, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.WriteAt([]byte("x"), -1); err == nil {
		t.Errorf("negative offset should be rejected")
	}
	_ = p.Abort()

	// offset+len beyond the per-upload cap must be rejected.
	p2, err := NewPusher(nil, b, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.WriteAt([]byte("xxxx"), maxPush); err == nil {
		t.Errorf("oversize write should be rejected")
	}
	_ = p2.Abort()
}

func TestPusherStreamsChunks(t *testing.T) {
	dir := t.TempDir()
	c := NewCommitter()
	defer c.Stop()
	b := config.Bucket{Path: dir, Mode: "rw", Versioned: true, ByHost: true, Extension: "txt", Validator: "none"}
	p, err := NewPusher(c, b, "web01")
	if err != nil {
		t.Fatal(err)
	}
	// Write out of order to exercise offset handling.
	if _, err := p.WriteAt([]byte("world"), 6); err != nil {
		t.Fatal(err)
	}
	if _, err := p.WriteAt([]byte("hello "), 0); err != nil {
		t.Fatal(err)
	}
	name, err := p.Finish()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "web01", name))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Errorf("content = %q", got)
	}
	if _, err := os.Readlink(filepath.Join(dir, "web01", "latest.txt")); err != nil {
		t.Errorf("latest symlink missing: %v", err)
	}
}

func TestCommitterConcurrent(t *testing.T) {
	dir := t.TempDir()
	c := NewCommitter()
	defer c.Stop()
	b := config.Bucket{Path: dir, Mode: "rw", Versioned: true, ByHost: true, Extension: "yaml", Validator: "yaml"}

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := NewPusher(c, b, "web01")
			if err != nil {
				errs <- err
				return
			}
			if _, err := p.WriteAt([]byte("a: 1\n"), 0); err != nil {
				errs <- err
				return
			}
			if _, err := p.Finish(); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent push failed: %v", err)
	}
	// Serialized commits should yield n distinct dated files plus latest.yaml.
	entries, _ := os.ReadDir(filepath.Join(dir, "web01"))
	files := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			files++
		}
	}
	if files != n+1 {
		t.Errorf("expected %d entries (n dated + latest), got %d", n+1, files)
	}
}

func TestSafeResolveSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink inside the bucket pointing outside must not be traversable.
	if err := os.Symlink(outside, filepath.Join(base, "evil")); err != nil {
		t.Fatal(err)
	}
	if _, err := safeResolve(base, "evil/secret"); err == nil {
		t.Fatalf("expected escape via symlink to be rejected")
	}
	// A leading .. is neutralized to the bucket root, not an escape.
	full, err := safeResolve(base, "../etc/passwd")
	if err != nil {
		t.Fatalf("leading .. should resolve within bucket: %v", err)
	}
	if !strings.HasPrefix(full, base) {
		t.Fatalf("resolved %q not under base %q", full, base)
	}
}

func TestMeta(t *testing.T) {
	rw := config.Bucket{Path: "/x", Mode: "rw", Versioned: true, ByHost: true, Extension: "yaml", Validator: "yaml"}
	b, _ := Meta(rw)
	s := string(b)
	for _, want := range []string{"mode: rw", "versioned: true", "byHost: true", "extension: yaml", "validator: yaml"} {
		if !strings.Contains(s, want) {
			t.Errorf("meta missing %q in:\n%s", want, s)
		}
	}
	ro := config.Bucket{Path: "/x", Mode: "ro"}
	b, _ = Meta(ro)
	s = string(b)
	if !strings.Contains(s, "mode: ro") || strings.Contains(s, "extension:") {
		t.Errorf("ro meta unexpected:\n%s", s)
	}
}
