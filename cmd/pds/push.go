package main

import (
	"os"

	"github.com/spf13/cobra"
)

func newPushCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:               "push <bucket> [FILE|-]",
		Short:             "Upload data to a bucket (default: stdin)",
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: a.completePushArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.ensureClient()
			if err != nil {
				return err
			}
			in := os.Stdin
			if len(args) == 2 && args[1] != "-" {
				f, err := os.Open(args[1])
				if err != nil {
					return err
				}
				defer f.Close()
				in = f
			}
			return c.Push(args[0], in)
		},
	}
}
