package main

import (
	"os"

	"github.com/spf13/cobra"
)

func newPullCmd(a *app) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:               "pull <path> [-o FILE]",
		Short:             "Copy a file from the server (default: stdout)",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completePathArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.ensureClient()
			if err != nil {
				return err
			}
			if output == "" {
				return c.Pull(args[0], os.Stdout)
			}
			return c.PullToFile(args[0], output)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to FILE instead of stdout")
	return cmd
}
