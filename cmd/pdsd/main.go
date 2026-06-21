// Command pdsd is the PDS server daemon. It serves buckets and accepts validated
// pushes over an SSH/SFTP endpoint, authenticating clients by public key. It runs
// as a normal user; host keys are taken from ~/.ssh/id_*.
package main

import (
	"flag"
	"log"
	"os"

	"petris.net/pds/internal/config"
	"petris.net/pds/internal/server"
	"petris.net/pds/internal/sshkeys"
)

func main() {
	log.SetFlags(log.LstdFlags)
	configPath := flag.String("config", "", "extra config file merged at highest precedence")
	sshDir := flag.String("ssh-dir", sshkeys.DefaultSSHDir(), "directory holding id_* host keys")
	flag.Parse()

	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		log.Fatalf("pdsd: %v", err)
	}

	signers, skipped, err := sshkeys.LoadSigners(*sshDir)
	if err != nil {
		log.Fatalf("pdsd: loading host keys from %s: %v", *sshDir, err)
	}
	for _, s := range skipped {
		log.Printf("pdsd: skipping host key %s", s)
	}
	if len(signers) == 0 {
		log.Fatalf("pdsd: no usable host keys in %s (need an unencrypted id_* private key)", *sshDir)
	}
	log.Printf("pdsd: loaded %d host key(s)", len(signers))

	srv, err := server.New(cfg, signers)
	if err != nil {
		log.Fatalf("pdsd: %v", err)
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("pdsd: %v", err)
		os.Exit(1)
	}
}
