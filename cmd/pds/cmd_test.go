package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// runRoot executes a freshly-built root command with the given args, discarding
// output, and returns the Execute error.
func runRoot(args ...string) error {
	_, err := runRootOutput(args...)
	return err
}

// runRootOutput executes a fresh root command and captures command output.
func runRootOutput(args ...string) (string, error) {
	var out bytes.Buffer
	root := newRootCmd(&app{})
	root.SetArgs(args)
	root.SetOut(&out)
	root.SetErr(io.Discard)
	err := root.Execute()
	return out.String(), err
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExitCodeFor(t *testing.T) {
	if got := exitCodeFor(errNoCommand); got != 2 {
		t.Errorf("exitCodeFor(errNoCommand) = %d, want 2", got)
	}
	if got := exitCodeFor(errors.New("boom")); got != 1 {
		t.Errorf("exitCodeFor(other) = %d, want 1", got)
	}
}

func TestBareCommandIsErrNoCommand(t *testing.T) {
	if err := runRoot(); !errors.Is(err, errNoCommand) {
		t.Errorf("bare pds error = %v, want errNoCommand", err)
	}
}

// endpoint must succeed without a server: it loads config unvalidated and never
// dials. A config with host/ports but no listener proves the no-dial path.
func TestEndpointDoesNotDial(t *testing.T) {
	t.Setenv("PDS_ENDPOINT", "")
	cfg := writeConfig(t, `endpoints:
  - host: primary.example.com
    sshPort: 22
    httpPort: 8080
  - host: backup.example.com
    sshPort: 2222
    httpPort: 8081
`)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--config", cfg, "endpoint"}, "primary.example.com:22\nbackup.example.com:2222\n"},
		{[]string{"--config", cfg, "endpoint", "--ssh"}, "primary.example.com:22\nbackup.example.com:2222\n"},
		{[]string{"--config", cfg, "endpoint", "--http"}, "http://primary.example.com:8080\nhttp://backup.example.com:8081\n"},
	} {
		got, err := runRootOutput(tc.args...)
		if err != nil {
			t.Errorf("runRoot(%v) = %v, want nil", tc.args, err)
		} else if got != tc.want {
			t.Errorf("runRoot(%v) output = %q, want %q", tc.args, got, tc.want)
		}
	}
}

func TestEndpointEnvironmentOverride(t *testing.T) {
	cfg := writeConfig(t, `endpoints:
  - host: primary.example.com
    sshPort: 22
    httpPort: 8080
  - host: backup.example.com
    sshPort: 2222
    httpPort: 8081
`)
	t.Setenv("PDS_ENDPOINT", "backup.example.com:2222")
	got, err := runRootOutput("--config", cfg, "endpoint")
	if err != nil {
		t.Fatal(err)
	}
	if want := "backup.example.com:2222\n"; got != want {
		t.Fatalf("endpoint override output = %q, want %q", got, want)
	}
	got, err = runRootOutput("--config", cfg, "endpoint", "--http")
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://backup.example.com:8081\n"; got != want {
		t.Fatalf("HTTP endpoint override output = %q, want %q", got, want)
	}
}

func TestEndpointSSHHTTPMutuallyExclusive(t *testing.T) {
	cfg := writeConfig(t, "endpoints:\n  - host: example.com\n    sshPort: 22\n    httpPort: 8080\n")
	if err := runRoot("--config", cfg, "endpoint", "--ssh", "--http"); err == nil {
		t.Error("endpoint --ssh --http should error")
	}
}

// exec validates that a script name is present before dialing, so this needs no
// server.
func TestExecRequiresName(t *testing.T) {
	if err := runRoot("exec"); err == nil {
		t.Error("exec with no name should error")
	}
}
