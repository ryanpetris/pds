package main

import (
	"os"

	"github.com/spf13/cobra"
)

func newMetaCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:               "meta <bucket>",
		Short:             "Print a bucket's .meta document",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeBucketArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.ensureClient()
			if err != nil {
				return err
			}
			return c.Meta(args[0], os.Stdout)
		},
	}
}
