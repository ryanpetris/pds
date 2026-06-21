// Command pdsd is the PDS server daemon. It serves buckets and accepts validated
// pushes over an SSH/SFTP endpoint, authenticating clients by public key. It runs
// as a normal user; host keys are taken from ~/.ssh/id_*.
package main

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"

	"petris.dev/pds/internal/config"
	"petris.dev/pds/internal/server"
	"petris.dev/pds/internal/sshkeys"
)

func main() {
	log.SetFlags(log.LstdFlags)
	if err := newRootCmd().Execute(); err != nil {
		log.Fatalf("pdsd: %v", err)
	}
}

func newRootCmd() *cobra.Command {
	var configPath, sshDir string
	cmd := &cobra.Command{
		Use:           "pdsd",
		Short:         "Petris Distribution System server daemon",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(configPath, sshDir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "extra config file merged at highest precedence")
	cmd.Flags().StringVar(&sshDir, "ssh-dir", sshkeys.DefaultSSHDir(), "directory holding id_* host keys")
	return cmd
}

func run(configPath, sshDir string) error {
	cfg, err := config.LoadServer(configPath)
	if err != nil {
		return err
	}

	signers, skipped, err := sshkeys.LoadSigners(sshDir)
	if err != nil {
		return fmt.Errorf("loading host keys from %s: %w", sshDir, err)
	}
	for _, s := range skipped {
		log.Printf("pdsd: skipping host key %s", s)
	}
	if len(signers) == 0 {
		return fmt.Errorf("no usable host keys in %s (need an unencrypted id_* private key)", sshDir)
	}
	log.Printf("pdsd: loaded %d host key(s)", len(signers))

	srv, err := server.New(cfg, signers)
	if err != nil {
		return err
	}
	return srv.ListenAndServe()
}
