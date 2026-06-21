package main

import (
	"io/fs"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// fakeInfo is a minimal os.FileInfo for completion tests.
type fakeInfo struct {
	name string
	dir  bool
}

func (f fakeInfo) Name() string { return f.name }
func (f fakeInfo) Size() int64  { return 0 }
func (f fakeInfo) Mode() fs.FileMode {
	if f.dir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.dir }
func (f fakeInfo) Sys() any           { return nil }

// fakeDir is a dirReader backed by a static map keyed by cleaned absolute path,
// mirroring how the real client normalizes remote paths before ReadDir.
type fakeDir map[string][]os.FileInfo

func (d fakeDir) ReadDir(remote string) ([]os.FileInfo, error) {
	if entries, ok := d[path.Join("/", remote)]; ok {
		return entries, nil
	}
	return nil, os.ErrNotExist
}

func dirs(names ...string) []os.FileInfo {
	out := make([]os.FileInfo, len(names))
	for i, n := range names {
		out[i] = fakeInfo{name: n, dir: true}
	}
	return out
}

func files(names ...string) []os.FileInfo {
	out := make([]os.FileInfo, len(names))
	for i, n := range names {
		out[i] = fakeInfo{name: n, dir: false}
	}
	return out
}

func TestCompleteBucket(t *testing.T) {
	root := fakeDir{"/": append(dirs("scripts", "metrics", ".pds"), files("README")...)}

	got, dir := completeBucket(root, "")
	if want := []string{"scripts", "metrics"}; !reflect.DeepEqual(got, want) {
		t.Errorf("completeBucket(\"\") = %v, want %v (dotdirs and files hidden)", got, want)
	}
	if dir != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("directive = %v, want NoFileComp", dir)
	}

	got, _ = completeBucket(root, "scr")
	if want := []string{"scripts"}; !reflect.DeepEqual(got, want) {
		t.Errorf("completeBucket(\"scr\") = %v, want %v", got, want)
	}
}

func TestCompletePath(t *testing.T) {
	d := fakeDir{
		"/":        append(dirs("scripts", "metrics"), files("top.txt")...),
		"/scripts": append(dirs("sub"), files("hello.sh", "bye.sh")...),
	}

	// Top level: full paths, dirs get a trailing slash, NoSpace so descent continues.
	got, dirv := completePath(d, "")
	want := []string{"scripts/", "metrics/", "top.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("completePath(\"\") = %v, want %v", got, want)
	}
	if dirv != (cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace) {
		t.Errorf("directive = %v, want NoFileComp|NoSpace", dirv)
	}

	// Descending into a directory uses the parent for ReadDir and filters by prefix.
	got, _ = completePath(d, "scripts/h")
	if want := []string{"scripts/hello.sh"}; !reflect.DeepEqual(got, want) {
		t.Errorf("completePath(\"scripts/h\") = %v, want %v", got, want)
	}
}

func TestCompleteExec(t *testing.T) {
	d := fakeDir{"/.pds/exec": append(files("deploy.sh", "backup.sh", ".meta"), dirs("nested")...)}

	got, dirv := completeExec(d, "")
	if want := []string{"deploy.sh", "backup.sh"}; !reflect.DeepEqual(got, want) {
		t.Errorf("completeExec(\"\") = %v, want %v (dirs and dot-entries excluded)", got, want)
	}
	if dirv != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("directive = %v, want NoFileComp", dirv)
	}

	got, _ = completeExec(d, "dep")
	if want := []string{"deploy.sh"}; !reflect.DeepEqual(got, want) {
		t.Errorf("completeExec(\"dep\") = %v, want %v", got, want)
	}
}

// exec uses DisableFlagParsing, so completion receives raw args; these helpers
// recover the --config value and count true positionals.
func TestConfigFromArgs(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--config", "/c.yaml"}, "/c.yaml"},
		{[]string{"-c", "/c.yaml"}, "/c.yaml"},
		{[]string{"--config=/c.yaml"}, "/c.yaml"},
		{[]string{"-c=/c.yaml"}, "/c.yaml"},
		{[]string{"--config", "/c.yaml", "script", "-x"}, "/c.yaml"},
		{[]string{"script", "-x"}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := configFromArgs(c.args); got != c.want {
			t.Errorf("configFromArgs(%v) = %q, want %q", c.args, got, c.want)
		}
	}
}

func TestExecPositionals(t *testing.T) {
	cases := []struct {
		args []string
		want []string
	}{
		{[]string{"--config", "/c.yaml"}, nil}, // only the flag+value
		{[]string{"--config", "/c.yaml", "deploy.sh"}, []string{"deploy.sh"}},
		{[]string{"deploy.sh", "-x", "--flag"}, []string{"deploy.sh"}}, // script flags ignored
		{[]string{"-c=/c.yaml"}, nil},
	}
	for _, c := range cases {
		if got := execPositionals(c.args); !reflect.DeepEqual(got, c.want) {
			t.Errorf("execPositionals(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

func TestCompleteReadError(t *testing.T) {
	empty := fakeDir{}
	if got, dirv := completeBucket(empty, ""); got != nil || dirv != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("on read error want (nil, NoFileComp), got (%v, %v)", got, dirv)
	}
}
