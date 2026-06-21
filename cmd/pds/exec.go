package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newExecCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "exec <name> [args...]",
		Short: "Run a script from .pds/exec",
		// DisableFlagParsing passes every token after `exec` through untouched,
		// including flags meant for the script. As a result cobra's Args
		// validation is bypassed, so the count is checked manually below; global
		// flags must precede `exec` (as with the previous parser).
		DisableFlagParsing: true,
		ValidArgsFunction:  a.completeExecArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("usage: pds exec <name> [args...]")
			}
			c, err := a.ensureClient()
			if err != nil {
				return err
			}
			code, err := c.Exec(args[0], args[1:])
			if err != nil {
				return err
			}
			// Mirror the previous behavior: exit directly with the script's exit
			// code. This intentionally skips deferred cleanup (the OS reclaims
			// the connection).
			os.Exit(code)
			return nil
		},
	}
}
