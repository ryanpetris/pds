package server

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"petris.dev/pds/internal/config"
	"petris.dev/pds/internal/store"
)

// handlers implements sftp.FileReader/FileWriter/FileLister/FileCmder for one
// connection, carrying the authenticated host name.
type handlers struct {
	cfg       *config.Server
	host      string
	readOnly  bool // anonymous connection: reads only, no host identity
	committer *store.Committer
}

func newHandlers(cfg *config.Server, host string, readOnly bool, committer *store.Committer) *handlers {
	return &handlers{cfg: cfg, host: host, readOnly: readOnly, committer: committer}
}

// resolved is the outcome of mapping a virtual path to a bucket + subpath, with
// reserved names already interpreted.
type resolved struct {
	name   string        // bucket name
	bucket config.Bucket // bucket config
	sub    string        // bucket-relative subpath (.self already expanded)
	meta   bool          // path is <bucket>/.meta
	push   bool          // path is <bucket>/.push
}

// segments splits a cleaned absolute path into non-empty segments.
func segments(p string) []string {
	p = strings.Trim(path.Clean(p), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// resolve maps a path to a bucket and subpath, applying the .pds/exec alias and the
// .self / .meta / .push reserved names. Root and the .pds directory are not buckets
// and return errVirtualDir so listing/stat can handle them specially.
var errVirtualDir = fmt.Errorf("virtual directory")

func (h *handlers) resolve(p string) (resolved, error) {
	segs := segments(p)
	if len(segs) == 0 {
		return resolved{}, errVirtualDir // root
	}

	// .pds namespace.
	if segs[0] == config.NamePDS {
		if len(segs) == 1 {
			return resolved{}, errVirtualDir // /.pds
		}
		if segs[1] == config.NameExec {
			if h.cfg.ExecBucket == "" {
				return resolved{}, os.ErrNotExist
			}
			segs = append([]string{h.cfg.ExecBucket}, segs[2:]...)
		} else {
			return resolved{}, os.ErrNotExist
		}
	}

	name := segs[0]
	bucket, ok := h.cfg.Buckets[name]
	if !ok {
		return resolved{}, os.ErrNotExist
	}
	rest := segs[1:]
	r := resolved{name: name, bucket: bucket}

	if len(rest) == 1 {
		switch rest[0] {
		case config.NameMeta:
			r.meta = true
			return r, nil
		case config.NamePush:
			r.push = true
			return r, nil
		}
	}

	// .self -> caller's host dir (byHost buckets only; anonymous clients have no
	// host, so .self does not exist for them).
	if len(rest) > 0 && rest[0] == config.NameSelf {
		if !bucket.ByHost || h.host == "" {
			return resolved{}, os.ErrNotExist
		}
		rest = append([]string{h.host}, rest[1:]...)
	}
	r.sub = path.Join(rest...)
	return r, nil
}

// Fileread serves reads: .meta documents and ordinary bucket files. .push is
// write-only.
func (h *handlers) Fileread(req *sftp.Request) (io.ReaderAt, error) {
	r, err := h.resolve(req.Filepath)
	if err != nil {
		return nil, err
	}
	if r.push {
		return nil, os.ErrPermission
	}
	if r.meta {
		b, err := store.Meta(r.bucket)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(b), nil
	}
	return store.Open(r.bucket, r.sub)
}

// Filewrite accepts pushes: only <bucket>/.push on a writable bucket. It returns a
// buffering writer that validates and commits on Close.
func (h *handlers) Filewrite(req *sftp.Request) (io.WriterAt, error) {
	if h.readOnly {
		return nil, os.ErrPermission
	}
	r, err := h.resolve(req.Filepath)
	if err != nil {
		return nil, err
	}
	if !r.push {
		return nil, os.ErrPermission
	}
	if !r.bucket.Writable() {
		return nil, os.ErrPermission
	}
	return store.NewPusher(h.committer, r.bucket, h.host)
}

// Filecmd rejects all mutating operations; the store is otherwise read-only and
// pushes flow exclusively through .push.
func (h *handlers) Filecmd(req *sftp.Request) error {
	return os.ErrPermission
}

// Filelist serves List, Stat, and Readlink.
func (h *handlers) Filelist(req *sftp.Request) (sftp.ListerAt, error) {
	switch req.Method {
	case "List":
		return h.list(req.Filepath)
	case "Stat":
		fi, err := h.stat(req.Filepath)
		if err != nil {
			return nil, err
		}
		return listerat{fi}, nil
	case "Readlink":
		// Reads follow symlinks server-side; explicit readlink is unnecessary.
		return nil, os.ErrInvalid
	default:
		return nil, os.ErrInvalid
	}
}

func (h *handlers) list(p string) (sftp.ListerAt, error) {
	r, err := h.resolve(p)
	if err == errVirtualDir {
		return h.listVirtual(p)
	}
	if err != nil {
		return nil, err
	}
	if r.meta || r.push {
		return nil, os.ErrInvalid // not directories
	}
	infos, err := store.List(r.bucket, r.sub)
	if err != nil {
		return nil, err
	}
	// At the bucket root, surface the readable virtual entries.
	if r.sub == "" || r.sub == "." {
		mb, _ := store.Meta(r.bucket)
		infos = append(infos, vinfo{name: config.NameMeta, size: int64(len(mb)), mode: 0o444})
		if r.bucket.ByHost && h.host != "" {
			infos = append(infos, vinfo{name: config.NameSelf, mode: os.ModeDir | 0o555})
		}
	}
	return listerat(infos), nil
}

// listVirtual lists the synthetic directories: root (buckets + .pds) and /.pds.
func (h *handlers) listVirtual(p string) (sftp.ListerAt, error) {
	segs := segments(p)
	if len(segs) == 0 { // root
		var infos []os.FileInfo
		for name := range h.cfg.Buckets {
			infos = append(infos, vinfo{name: name, mode: os.ModeDir | 0o555})
		}
		infos = append(infos, vinfo{name: config.NamePDS, mode: os.ModeDir | 0o555})
		return listerat(infos), nil
	}
	// /.pds
	var infos []os.FileInfo
	if h.cfg.ExecBucket != "" {
		infos = append(infos, vinfo{name: config.NameExec, mode: os.ModeDir | 0o555})
	}
	return listerat(infos), nil
}

func (h *handlers) stat(p string) (os.FileInfo, error) {
	r, err := h.resolve(p)
	if err == errVirtualDir {
		return vinfo{name: lastSeg(p), mode: os.ModeDir | 0o555}, nil
	}
	if err != nil {
		return nil, err
	}
	if r.meta {
		b, _ := store.Meta(r.bucket)
		return vinfo{name: config.NameMeta, size: int64(len(b)), mode: 0o444}, nil
	}
	if r.push {
		// Write-only target; report a plausible regular file so Create succeeds.
		return vinfo{name: config.NamePush, mode: 0o200}, nil
	}
	if r.sub == "" || r.sub == "." {
		if fi, err := store.Stat(r.bucket, ""); err == nil {
			return fi, nil
		}
		return vinfo{name: r.name, mode: os.ModeDir | 0o555}, nil
	}
	return store.Stat(r.bucket, r.sub)
}

func lastSeg(p string) string {
	segs := segments(p)
	if len(segs) == 0 {
		return "/"
	}
	return segs[len(segs)-1]
}

// listerat adapts a slice of FileInfo to sftp.ListerAt.
type listerat []os.FileInfo

func (l listerat) ListAt(f []os.FileInfo, off int64) (int, error) {
	if off < 0 {
		return 0, os.ErrInvalid
	}
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(f, l[off:])
	if int(off)+n >= len(l) {
		return n, io.EOF
	}
	return n, nil
}

// vinfo is a synthetic os.FileInfo for virtual entries.
type vinfo struct {
	name string
	size int64
	mode os.FileMode
}

func (v vinfo) Name() string       { return v.name }
func (v vinfo) Size() int64        { return v.size }
func (v vinfo) Mode() os.FileMode  { return v.mode }
func (v vinfo) ModTime() time.Time { return time.Unix(0, 0) }
func (v vinfo) IsDir() bool        { return v.mode.IsDir() }
func (v vinfo) Sys() any           { return nil }
