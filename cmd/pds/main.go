// Command pds is the PDS client. Paths are bucket-first: the first segment names a
// bucket (or the .pds namespace). Usage:
//
//	pds [--config FILE] pull  <path> [-o FILE]   # default: write to stdout
//	pds [--config FILE] ls    [path]             # default: root
//	pds [--config FILE] push  <bucket> [FILE|-]  # default: stdin
//	pds [--config FILE] meta  <bucket>
//	pds [--config FILE] exec  <name> [args...]
//	pds [--config FILE] endpoint [--ssh|--http]  # print <host>:<port> (or http URL)
package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	a := &app{}
	err := newRootCmd(a).Execute()
	// exec replaces this path with a direct os.Exit; for every other command we
	// close any dialed connection before reporting the result.
	a.close()
	if err == nil {
		return
	}
	// Bare `pds` already printed usage in its RunE; just exit 2 without an extra
	// error line, matching the previous parser.
	if !errors.Is(err, errNoCommand) {
		fmt.Fprintf(os.Stderr, "pds: %v\n", err)
	}
	os.Exit(exitCodeFor(err))
}
