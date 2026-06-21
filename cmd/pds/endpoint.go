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
		Short: "Print the server endpoint (SSH host:port, or HTTP URL)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// endpoint only prints an address: it must not open a connection and
			// needs only the fields it prints, so it loads without the full
			// client validation (e.g. trustedKeys).
			cfg, err := config.LoadClientUnvalidated(a.configPath)
			if err != nil {
				return err
			}
			if wantHTTP {
				u, err := client.ResolveHTTPURL(cfg)
				if err != nil {
					return err
				}
				fmt.Println(u)
				return nil
			}
			// The default and --ssh both print the protocolless SSH endpoint;
			// --ssh is the explicit counterpart to --http.
			ep, err := client.ResolveEndpoint(cfg)
			if err != nil {
				return err
			}
			fmt.Println(ep)
			return nil
		},
	}
	cmd.Flags().BoolVar(&wantSSH, "ssh", false, "print the SSH endpoint (host:port; default)")
	cmd.Flags().BoolVar(&wantHTTP, "http", false, "print the read-only HTTP URL")
	cmd.MarkFlagsMutuallyExclusive("ssh", "http")
	return cmd
}
