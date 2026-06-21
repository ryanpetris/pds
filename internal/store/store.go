// Package store implements the on-disk operations behind a bucket: confined reads,
// directory listing, virtual .meta generation, and validated atomic pushes.
//
// All paths handed in here are bucket-relative subpaths that have already had
// reserved names (.self / .meta / .push / .pds) resolved by the caller. Every
// access is confined to the bucket's configured path.
package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"petris.dev/pds/internal/config"
	"petris.dev/pds/internal/validate"
)

// timeFormat is the versioned filename stamp: yyyyMMddHHmmss (UTC, server clock).
const timeFormat = "20060102150405"

// maxPush caps a single upload (enforced on the streamed temp file). PDS is meant
// for small files.
const maxPush = 5 << 20 // 5 MiB

// Open opens a file for reading at sub within the bucket, following symlinks (e.g.
// latest.<ext>) but never escaping the bucket root.
func Open(b config.Bucket, sub string) (*os.File, error) {
	full, err := safeResolve(b.Path, sub)
	if err != nil {
		return nil, err
	}
	return os.Open(full)
}

// Stat returns file info for sub within the bucket.
func Stat(b config.Bucket, sub string) (os.FileInfo, error) {
	full, err := safeResolve(b.Path, sub)
	if err != nil {
		return nil, err
	}
	return os.Stat(full)
}

// List returns the directory entries at sub within the bucket.
func List(b config.Bucket, sub string) ([]os.FileInfo, error) {
	full, err := safeResolve(b.Path, sub)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}
	out := make([]os.FileInfo, 0, len(entries))
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, fi)
	}
	return out, nil
}

// Meta returns the YAML metadata document for a bucket (served as .meta).
func Meta(b config.Bucket) ([]byte, error) {
	type meta struct {
		Mode      string `yaml:"mode"`
		Versioned bool   `yaml:"versioned"`
		ByHost    bool   `yaml:"byHost"`
		Extension string `yaml:"extension,omitempty"`
		Validator string `yaml:"validator,omitempty"`
	}
	mode := strings.ToLower(b.Mode)
	if mode == "" {
		mode = "ro"
	}
	m := meta{Mode: mode, Versioned: b.Versioned, ByHost: b.ByHost}
	if b.Writable() {
		m.Extension = b.Extension
		m.Validator = b.Validator
	}
	return yaml.Marshal(m)
}

// Committer serializes the validate-then-place step so only one upload is ever
// validated/committed at a time. Streaming uploads to temp files stays concurrent;
// this bounds peak validation memory to a single file regardless of how many
// connections are open. Trade-off: a flood of large pushes delays each other
// (throughput), but never multiplies validation memory.
type Committer struct {
	jobs chan commitJob
}

type commitJob struct {
	bucket  config.Bucket
	tmpName string
	result  chan commitResult
}

type commitResult struct {
	name string
	err  error
}

// NewCommitter starts the single worker goroutine and returns the committer.
func NewCommitter() *Committer {
	c := &Committer{jobs: make(chan commitJob)}
	go c.run()
	return c
}

func (c *Committer) run() {
	for j := range c.jobs {
		name, err := finalize(j.bucket, j.tmpName)
		j.result <- commitResult{name: name, err: err}
	}
}

// Submit queues a sealed temp file for validation and placement, blocking until the
// worker has processed it.
func (c *Committer) Submit(b config.Bucket, tmpName string) (string, error) {
	res := make(chan commitResult, 1)
	c.jobs <- commitJob{bucket: b, tmpName: tmpName, result: res}
	r := <-res
	return r.name, r.err
}

// Stop shuts the worker down. Only call when no pushes are in flight.
func (c *Committer) Stop() { close(c.jobs) }

// finalize validates a sealed temp file and atomically moves it into place, returning
// the stored base name. The temp file is removed on any failure. For byHost buckets
// the destination dir is the temp file's own directory (the temp was created there).
// Versioned buckets write a timestamped file and repoint latest.<ext>; arbitrary
// buckets overwrite latest.<ext>. Nothing is ever pruned.
func finalize(b config.Bucket, tmpName string) (string, error) {
	dir := filepath.Dir(tmpName)
	if b.Validator != "none" {
		f, err := os.Open(tmpName)
		if err != nil {
			os.Remove(tmpName)
			return "", err
		}
		verr := validate.Validate(b.Validator, f)
		f.Close()
		if verr != nil {
			os.Remove(tmpName)
			return "", verr
		}
	}
	ext := b.Extension
	latest := "latest." + ext
	if !b.Versioned {
		if err := os.Rename(tmpName, filepath.Join(dir, latest)); err != nil {
			os.Remove(tmpName)
			return "", err
		}
		return latest, nil
	}
	name, err := uniqueName(dir, ext)
	if err != nil {
		os.Remove(tmpName)
		return "", err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	if err := atomicSymlink(name, filepath.Join(dir, latest)); err != nil {
		return "", err
	}
	return name, nil
}

// Pusher streams one upload to a temp file in the destination directory; on Finish it
// seals the file and hands it to the Committer for validation and placement. It
// implements io.WriterAt and io.Closer so it can be returned directly to the SFTP
// request server, which calls Close when the file handle closes.
type Pusher struct {
	committer *Committer
	bucket    config.Bucket
	tmp       *os.File
	tmpName   string

	mu   sync.Mutex
	size int64
	err  error // sticky: a rejected/failed WriteAt
	done bool
}

// NewPusher prepares the destination directory and a temp file to stream into. The
// committer serializes the eventual validate/commit; it may be nil only for callers
// that do not call Finish (e.g. the synchronous Commit wrapper).
func NewPusher(c *Committer, b config.Bucket, host string) (*Pusher, error) {
	if !b.Writable() {
		return nil, fmt.Errorf("bucket is read-only")
	}
	dir := b.Path
	if b.ByHost {
		h, err := safeSegment(host)
		if err != nil {
			return nil, fmt.Errorf("invalid host %q: %w", host, err)
		}
		dir = filepath.Join(b.Path, h)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return nil, err
	}
	return &Pusher{committer: c, bucket: b, tmp: tmp, tmpName: tmp.Name()}, nil
}

// WriteAt streams a chunk to the temp file, guarding against malformed offsets and
// enforcing the per-upload size cap. Offsets are validated in int64 before any
// conversion so a hostile offset cannot overflow or index out of bounds.
func (p *Pusher) WriteAt(b []byte, off int64) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return 0, fmt.Errorf("write after close")
	}
	if off < 0 {
		p.err = fmt.Errorf("negative write offset")
		return 0, p.err
	}
	end := off + int64(len(b))
	if end < off || end > maxPush { // overflow or over the cap
		p.err = fmt.Errorf("upload exceeds %d bytes", maxPush)
		return 0, p.err
	}
	n, err := p.tmp.WriteAt(b, off)
	if err != nil {
		p.err = err
		return n, err
	}
	if end > p.size {
		p.size = end
	}
	return n, nil
}

// seal flushes and closes the temp file, returning its path ready for finalize. A
// prior WriteAt failure aborts instead.
func (p *Pusher) seal() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		if p.err != nil {
			return "", p.err
		}
		return "", fmt.Errorf("push already finished")
	}
	p.done = true
	if p.err != nil {
		p.abortLocked()
		return "", p.err
	}
	if err := p.tmp.Sync(); err != nil {
		p.abortLocked()
		return "", err
	}
	if err := p.tmp.Close(); err != nil {
		os.Remove(p.tmpName)
		return "", err
	}
	return p.tmpName, nil
}

// Finish seals the upload and submits it to the committer for validation and
// placement, returning the stored base name.
func (p *Pusher) Finish() (string, error) {
	tmpName, err := p.seal()
	if err != nil {
		return "", err
	}
	return p.committer.Submit(p.bucket, tmpName)
}

// Abort discards the temp file without committing. Idempotent.
func (p *Pusher) Abort() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return nil
	}
	p.done = true
	p.abortLocked()
	return nil
}

func (p *Pusher) abortLocked() {
	p.tmp.Close()
	os.Remove(p.tmpName)
}

// Close finalizes the push (io.Closer for the SFTP request server).
func (p *Pusher) Close() error {
	_, err := p.Finish()
	return err
}

// uniqueName returns a yyyyMMddHHmmss.<ext> name that does not yet exist in dir,
// appending -N on a same-second collision.
func uniqueName(dir, ext string) (string, error) {
	stamp := time.Now().UTC().Format(timeFormat)
	for i := 0; i < 1000; i++ {
		name := stamp + "." + ext
		if i > 0 {
			name = fmt.Sprintf("%s-%d.%s", stamp, i, ext)
		}
		if _, err := os.Lstat(filepath.Join(dir, name)); os.IsNotExist(err) {
			return name, nil
		}
	}
	return "", fmt.Errorf("could not allocate a unique name in %s", dir)
}

// atomicSymlink points dest at target via a temp symlink + rename so readers never
// observe a missing or half-written link.
func atomicSymlink(target, dest string) error {
	dir := filepath.Dir(dest)
	tmp := filepath.Join(dir, fmt.Sprintf(".latest-tmp-%d", time.Now().UnixNano()))
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// safeResolve joins sub onto base, confines it to base, then verifies the symlink-
// resolved path stays within base.
func safeResolve(base, sub string) (string, error) {
	clean := filepath.Clean("/" + sub)
	full := filepath.Join(base, clean)
	if !withinBase(base, full) {
		return "", fmt.Errorf("path escapes bucket")
	}
	// Defend against symlinks that point outside the bucket. Evaluate whatever
	// prefix already exists; non-existent tails are fine (the file may not exist).
	resolved, err := filepath.EvalSymlinks(full)
	if err == nil {
		realBase, berr := filepath.EvalSymlinks(base)
		if berr == nil && !withinBase(realBase, resolved) {
			return "", fmt.Errorf("path escapes bucket")
		}
	}
	return full, nil
}

func withinBase(base, full string) bool {
	rel, err := filepath.Rel(base, full)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

// safeSegment validates a single path segment (e.g. a host name): no separators,
// no "." / "..", non-empty.
func safeSegment(s string) (string, error) {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\") {
		return "", fmt.Errorf("not a valid path segment")
	}
	return s, nil
}
