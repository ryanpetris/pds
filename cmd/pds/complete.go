package main

import (
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"

	"petris.dev/pds/internal/config"
)

// dirReader is the subset of *client.Client that completion needs. Taking an
// interface lets the helpers be unit-tested without a live connection.
type dirReader interface {
	ReadDir(remote string) ([]os.FileInfo, error)
}

// The complete* helpers are pure functions of a directory reader and the partial
// word being completed. The complete*Arg methods wrap them with connection setup
// and positional-index rules for use as cobra ValidArgsFunctions.

// completeBucket returns bucket-name candidates matching toComplete. Buckets are
// the top-level directories; reserved dot-entries (.pds, .meta, …) are hidden,
// matching the rule that bucket names may not begin with '.'.
func completeBucket(c dirReader, toComplete string) ([]string, cobra.ShellCompDirective) {
	infos, err := c.ReadDir("/")
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, fi := range infos {
		name := fi.Name()
		if !fi.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if strings.HasPrefix(name, toComplete) {
			out = append(out, name)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completePath returns path candidates under the directory portion of
// toComplete. Candidates are full paths (cobra replaces the whole word);
// directories get a trailing slash so the user can keep descending.
func completePath(c dirReader, toComplete string) ([]string, cobra.ShellCompDirective) {
	// Split off the directory portion (through the last slash); the rest is the
	// prefix to match. An empty parent means the root, which ReadDir normalizes.
	// Candidates are parent+name so they carry no leading slash unless the user
	// typed one, matching how paths are written (bucket-first, e.g. scripts/x).
	parent := ""
	prefix := toComplete
	if i := strings.LastIndex(toComplete, "/"); i >= 0 {
		parent = toComplete[:i+1]
		prefix = toComplete[i+1:]
	}
	infos, err := c.ReadDir(parent)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, fi := range infos {
		name := fi.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		full := parent + name
		if fi.IsDir() {
			full += "/"
		}
		out = append(out, full)
	}
	// NoSpace keeps directory completions open so the user can descend; NoFileComp
	// stops the shell from falling back to local filenames.
	return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
}

// completeExec returns script-name candidates from the .pds/exec directory.
func completeExec(c dirReader, toComplete string) ([]string, cobra.ShellCompDirective) {
	infos, err := c.ReadDir(path.Join("/", config.NamePDS, config.NameExec))
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, fi := range infos {
		name := fi.Name()
		// Skip subdirectories and reserved entries like .meta; only scripts run.
		if fi.IsDir() || strings.HasPrefix(name, ".") || !strings.HasPrefix(name, toComplete) {
			continue
		}
		out = append(out, name)
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completePathArg completes the single path positional of pull/ls.
func (a *app) completePathArg(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	c, err := a.ensureClient()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return completePath(c, toComplete)
}

// completeBucketArg completes the single bucket positional of meta.
func (a *app) completeBucketArg(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	c, err := a.ensureClient()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return completeBucket(c, toComplete)
}

// completePushArg completes push's bucket (first positional) and defers to local
// filename completion for the optional FILE (second positional).
func (a *app) completePushArg(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	switch len(args) {
	case 0:
		c, err := a.ensureClient()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return completeBucket(c, toComplete)
	case 1:
		// The second positional is a local FILE (or - for stdin); let the shell
		// complete filenames.
		return nil, cobra.ShellCompDirectiveDefault
	default:
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
}

// configFromArgs extracts a --config/-c value from raw args. exec uses
// DisableFlagParsing, so during completion cobra neither binds the persistent
// --config flag nor strips it from the args; completion must read it back out
// itself to know which config to dial with.
func configFromArgs(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "--config" || a == "-c") && i+1 < len(args):
			return args[i+1]
		case strings.HasPrefix(a, "--config="):
			return strings.TrimPrefix(a, "--config=")
		case strings.HasPrefix(a, "-c="):
			return strings.TrimPrefix(a, "-c=")
		}
	}
	return ""
}

// execPositionals extracts positional arguments from exec's raw args. exec uses
// DisableFlagParsing, so cobra hands completion the unparsed args, which include
// the global --config/-c flag and its value; skipping those leaves the script
// name and any arguments destined for it.
func execPositionals(args []string) []string {
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config" || a == "-c":
			i++ // skip the flag's separate value
		case strings.HasPrefix(a, "--config=") || strings.HasPrefix(a, "-c="):
			// value is attached to the flag; nothing positional here
		case strings.HasPrefix(a, "-"):
			// any other flag-looking token belongs to the script
		default:
			pos = append(pos, a)
		}
	}
	return pos
}

// completeExecArg completes exec's script name (first positional only); the
// script's own arguments are not completed.
func (a *app) completeExecArg(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// Recover --config from the raw args since DisableFlagParsing left it unbound.
	if a.configPath == "" {
		a.configPath = configFromArgs(args)
	}
	if len(execPositionals(args)) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	c, err := a.ensureClient()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return completeExec(c, toComplete)
}
