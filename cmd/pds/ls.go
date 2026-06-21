package main

import (
	"os"

	"github.com/spf13/cobra"
)

func newLsCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:               "ls [path]",
		Short:             "List a directory (default: root)",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: a.completePathArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.ensureClient()
			if err != nil {
				return err
			}
			target := "/"
			if len(args) == 1 {
				target = args[0]
			}
			return c.Ls(target, os.Stdout)
		},
	}
}
