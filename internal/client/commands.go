package client

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"

	"petris.dev/pds/internal/config"
)

// remotePath turns a user-supplied path into a cleaned absolute SFTP path.
func remotePath(p string) string { return path.Join("/", p) }

// Pull copies the file at remote to w (e.g. os.Stdout).
func (c *Client) Pull(remote string, w io.Writer) error {
	f, err := c.sftp.Open(remotePath(remote))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

// PullToFile copies the file at remote to a local path.
func (c *Client) PullToFile(remote, out string) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	return c.Pull(remote, f)
}

// Ls lists a directory, printing names (directories get a trailing slash).
func (c *Client) Ls(remote string, w io.Writer) error {
	infos, err := c.sftp.ReadDir(remotePath(remote))
	if err != nil {
		return err
	}
	for _, fi := range infos {
		name := fi.Name()
		if fi.IsDir() {
			name += "/"
		}
		fmt.Fprintln(w, name)
	}
	return nil
}

// Push uploads data to a bucket by writing its reserved .push file. The server
// validates and stores it; validation errors surface on Close.
func (c *Client) Push(bucket string, r io.Reader) error {
	target := path.Join("/", bucket, config.NamePush)
	f, err := c.sftp.Create(target)
	if err != nil {
		return err
	}
	// Stream the input straight to SFTP rather than buffering it all in memory.
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	// Close triggers server-side validation + commit; report its error.
	if err := f.Close(); err != nil {
		return fmt.Errorf("push rejected: %w", err)
	}
	return nil
}

// Meta writes a bucket's .meta document to w.
func (c *Client) Meta(bucket string, w io.Writer) error {
	return c.Pull(path.Join(bucket, config.NameMeta), w)
}

// Exec pulls a script from the .pds/exec alias, writes it to a temp file with the
// execute bit set, and runs it with argv[0]=name and the given args. PDS_ENDPOINT is
// exported so the script can re-invoke pds. It returns the script's exit code.
func (c *Client) Exec(name string, args []string) (int, error) {
	remote := path.Join("/", config.NamePDS, config.NameExec, name)
	src, err := c.sftp.Open(remote)
	if err != nil {
		return 1, err
	}
	defer src.Close()

	tmp, err := os.CreateTemp("", "pds-exec-*")
	if err != nil {
		return 1, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return 1, err
	}
	if err := tmp.Close(); err != nil {
		return 1, err
	}
	if err := os.Chmod(tmpName, 0o700); err != nil {
		return 1, err
	}

	cmd := exec.Command(tmpName)
	cmd.Args = append([]string{name}, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "PDS_ENDPOINT="+c.endpoint)

	err = cmd.Run()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 1, err
}
