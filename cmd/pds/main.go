// Command pds is the PDS client. Paths are bucket-first: the first segment names a
// bucket (or the .pds namespace). Usage:
//
//	pds [-config FILE] pull  <path> [-o FILE]   # default: write to stdout
//	pds [-config FILE] ls    [path]             # default: root
//	pds [-config FILE] push  <bucket> [FILE|-]  # default: stdin
//	pds [-config FILE] meta  <bucket>
//	pds [-config FILE] exec  <name> [args...]
package main

import (
	"fmt"
	"os"
	"strings"

	"petris.net/pds/internal/client"
	"petris.net/pds/internal/config"
)

func main() {
	args := os.Args[1:]
	configPath := ""

	// Leading global flags (kept minimal so `exec` args pass through untouched).
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		a := args[0]
		switch {
		case a == "-config" || a == "--config":
			if len(args) < 2 {
				fatal("missing value for -config")
			}
			configPath, args = args[1], args[2:]
		case strings.HasPrefix(a, "-config="):
			configPath, args = strings.TrimPrefix(a, "-config="), args[1:]
		case strings.HasPrefix(a, "--config="):
			configPath, args = strings.TrimPrefix(a, "--config="), args[1:]
		case a == "-h" || a == "--help":
			usage()
			return
		default:
			fatal("unknown global flag %q", a)
		}
	}
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	cmd, rest := args[0], args[1:]

	cfg, err := config.LoadClient(configPath)
	if err != nil {
		fatal("%v", err)
	}
	c, err := client.Dial(cfg)
	if err != nil {
		fatal("%v", err)
	}
	defer c.Close()

	switch cmd {
	case "pull":
		runPull(c, rest)
	case "ls":
		runLs(c, rest)
	case "push":
		runPush(c, rest)
	case "meta":
		runMeta(c, rest)
	case "exec":
		runExec(c, rest)
	default:
		fatal("unknown command %q", cmd)
	}
}

func runPull(c *client.Client, args []string) {
	var out string
	var pathArg string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o":
			if i+1 >= len(args) {
				fatal("missing value for -o")
			}
			out = args[i+1]
			i++
		default:
			if pathArg != "" {
				fatal("pull takes a single path")
			}
			pathArg = args[i]
		}
	}
	if pathArg == "" {
		fatal("usage: pds pull <path> [-o FILE]")
	}
	if out == "" {
		if err := c.Pull(pathArg, os.Stdout); err != nil {
			fatal("%v", err)
		}
		return
	}
	if err := c.PullToFile(pathArg, out); err != nil {
		fatal("%v", err)
	}
}

func runLs(c *client.Client, args []string) {
	target := "/"
	if len(args) == 1 {
		target = args[0]
	} else if len(args) > 1 {
		fatal("usage: pds ls [path]")
	}
	if err := c.Ls(target, os.Stdout); err != nil {
		fatal("%v", err)
	}
}

func runPush(c *client.Client, args []string) {
	if len(args) < 1 || len(args) > 2 {
		fatal("usage: pds push <bucket> [FILE|-]")
	}
	bucket := args[0]
	in := os.Stdin
	if len(args) == 2 && args[1] != "-" {
		f, err := os.Open(args[1])
		if err != nil {
			fatal("%v", err)
		}
		defer f.Close()
		in = f
	}
	if err := c.Push(bucket, in); err != nil {
		fatal("%v", err)
	}
}

func runMeta(c *client.Client, args []string) {
	if len(args) != 1 {
		fatal("usage: pds meta <bucket>")
	}
	if err := c.Meta(args[0], os.Stdout); err != nil {
		fatal("%v", err)
	}
}

func runExec(c *client.Client, args []string) {
	if len(args) < 1 {
		fatal("usage: pds exec <name> [args...]")
	}
	code, err := c.Exec(args[0], args[1:])
	if err != nil {
		fatal("%v", err)
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprint(os.Stderr, `pds — Petris Distribution System client

usage:
  pds [-config FILE] pull  <path> [-o FILE]   # default: stdout
  pds [-config FILE] ls    [path]             # default: root
  pds [-config FILE] push  <bucket> [FILE|-]  # default: stdin
  pds [-config FILE] meta  <bucket>
  pds [-config FILE] exec  <name> [args...]
`)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "pds: "+format+"\n", a...)
	os.Exit(1)
}
