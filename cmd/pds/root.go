package main

import (
	"errors"

	"github.com/spf13/cobra"

	"petris.dev/pds/internal/client"
	"petris.dev/pds/internal/config"
)

// app holds shared CLI state: the resolved config path and a lazily-dialed
// client. ensureClient is the single place that loads config and dials, so both
// command RunE bodies and completion functions share one connection.
type app struct {
	configPath string
	cfg        *config.Client
	client     *client.Client
}

// ensureClient loads the client config and dials the server on first use,
// caching the connection so repeated calls (e.g. a command plus its completion
// function) reuse it.
func (a *app) ensureClient() (*client.Client, error) {
	if a.client != nil {
		return a.client, nil
	}
	cfg, err := config.LoadClient(a.configPath)
	if err != nil {
		return nil, err
	}
	c, err := client.Dial(cfg)
	if err != nil {
		return nil, err
	}
	a.cfg = cfg
	a.client = c
	return c, nil
}

// close shuts down a dialed connection, if any. It is safe to call when nothing
// was dialed (e.g. the endpoint command, which never connects).
func (a *app) close() {
	if a.client != nil {
		a.client.Close()
		a.client = nil
	}
}

// errNoCommand is returned when pds is invoked with no subcommand; main maps it
// to exit code 2, matching the previous hand-rolled parser.
var errNoCommand = errors.New("no command given")

// exitCodeFor maps an Execute error to a process exit code: 2 for a missing
// subcommand, 1 otherwise.
func exitCodeFor(err error) int {
	if errors.Is(err, errNoCommand) {
		return 2
	}
	return 1
}

func newRootCmd(a *app) *cobra.Command {
	root := &cobra.Command{
		Use:   "pds",
		Short: "Petris Distribution System client",
		Long: `pds is the Petris Distribution System client.

Paths are bucket-first: the first segment names a bucket (or the .pds
namespace). Authenticity comes from the SSH transport — the client pins the
server's host key and authenticates by public key.`,
		// main owns error reporting (the "pds: <msg>" prefix and exit codes), so
		// cobra must not print errors or usage on RunE failures itself.
		SilenceUsage:  true,
		SilenceErrors: true,
		// Bare `pds` printed usage to stderr and exited 2; preserve that. No
		// connection is dialed here because there is no persistent pre-run hook.
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Usage()
			return errNoCommand
		},
	}
	root.PersistentFlags().StringVarP(&a.configPath, "config", "c", "", "config file, merged at highest precedence")

	root.AddCommand(
		newPullCmd(a),
		newLsCmd(a),
		newPushCmd(a),
		newMetaCmd(a),
		newExecCmd(a),
		newEndpointCmd(a),
	)
	return root
}
