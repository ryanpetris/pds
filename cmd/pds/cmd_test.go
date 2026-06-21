package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// runRoot executes a freshly-built root command with the given args, discarding
// output, and returns the Execute error.
func runRoot(args ...string) error {
	root := newRootCmd(&app{})
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	return root.Execute()
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
	cfg := writeConfig(t, "host: example.com\nsshPort: 22\nhttpPort: 8080\n")
	for _, args := range [][]string{
		{"--config", cfg, "endpoint"},
		{"--config", cfg, "endpoint", "--ssh"},
		{"--config", cfg, "endpoint", "--http"},
	} {
		if err := runRoot(args...); err != nil {
			t.Errorf("runRoot(%v) = %v, want nil", args, err)
		}
	}
}

func TestEndpointSSHHTTPMutuallyExclusive(t *testing.T) {
	cfg := writeConfig(t, "host: example.com\nsshPort: 22\nhttpPort: 8080\n")
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
