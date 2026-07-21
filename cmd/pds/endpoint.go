package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"petris.dev/pds/internal/client"
	"petris.dev/pds/internal/config"
)

func newEndpointCmd(a *app) *cobra.Command {
	var wantSSH, wantHTTP bool
	cmd := &cobra.Command{
		Use:   "endpoint [--ssh|--http]",
		Short: "Print the ordered server endpoints (SSH host:port, or HTTP URLs)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// endpoint only prints an address: it must not open a connection and
			// needs only the fields it prints, so it loads without the full
			// client validation (e.g. trustedKeys).
			cfg, err := config.LoadClientUnvalidated(a.configPath)
			if err != nil {
				return err
			}
			var endpoints []string
			if wantHTTP {
				endpoints, err = client.ResolveHTTPURLs(cfg)
			} else {
				// The default and --ssh both print protocolless SSH endpoints;
				// --ssh is the explicit counterpart to --http.
				endpoints, err = client.ResolveEndpoints(cfg)
			}
			if err != nil {
				return err
			}
			for _, endpoint := range endpoints {
				fmt.Fprintln(cmd.OutOrStdout(), endpoint)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&wantSSH, "ssh", false, "print the SSH endpoint (host:port; default)")
	cmd.Flags().BoolVar(&wantHTTP, "http", false, "print the read-only HTTP URL")
	cmd.MarkFlagsMutuallyExclusive("ssh", "http")
	return cmd
}
