package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"petris.net/pds/internal/config"
	"petris.net/pds/internal/store"
)

// httpHandler serves bucket contents read-only over HTTP, behaving as an anonymous
// client (no host identity). It reuses the SFTP path resolution and the store reads, so
// HTTP exposes exactly what an anonymous SSH reader sees.
type httpHandler struct {
	cfg *config.Server
	h   *handlers
}

func newHTTPHandler(cfg *config.Server) http.Handler {
	return &httpHandler{cfg: cfg, h: newHandlers(cfg, "", true, nil)}
}

// httpEntry is one element of a JSON directory listing.
type httpEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"isDir"`
	ModTime string `json:"modTime"`
}

// epoch is the modTime reported for synthetic entries (mirrors vinfo's zero time).
var epoch = time.Unix(0, 0).UTC().Format(time.RFC3339)

func (hh *httpHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
		return
	}

	r, err := hh.h.resolve(req.URL.Path)
	if err == errVirtualDir {
		hh.writeJSON(w, hh.virtualEntries(req.URL.Path))
		return
	}
	if err != nil {
		httpError(w, err)
		return
	}
	if r.push { // write-only target: not readable
		http.NotFound(w, req)
		return
	}
	if r.meta {
		b, err := store.Meta(r.bucket)
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(b)
		return
	}

	fi, err := store.Stat(r.bucket, r.sub)
	if err != nil {
		httpError(w, err)
		return
	}
	if fi.IsDir() {
		hh.writeJSON(w, hh.dirEntries(w, r))
		return
	}
	f, err := store.Open(r.bucket, r.sub)
	if err != nil {
		httpError(w, err)
		return
	}
	defer f.Close()
	http.ServeContent(w, req, fi.Name(), fi.ModTime(), f)
}

// virtualEntries lists the synthetic directories: root (buckets + .pds) and /.pds.
func (hh *httpHandler) virtualEntries(p string) []httpEntry {
	out := []httpEntry{}
	if len(segments(p)) == 0 { // root
		for name := range hh.cfg.Buckets {
			out = append(out, dirEntry(name))
		}
		out = append(out, dirEntry(config.NamePDS))
		return out
	}
	// /.pds
	if hh.cfg.ExecBucket != "" {
		out = append(out, dirEntry(config.NameExec))
	}
	return out
}

// dirEntries lists a bucket subdirectory, surfacing the virtual .meta entry at the bucket
// root (but not .self — anonymous HTTP has no host). On a read error it writes the HTTP
// error and returns nil.
func (hh *httpHandler) dirEntries(w http.ResponseWriter, r resolved) []httpEntry {
	infos, err := store.List(r.bucket, r.sub)
	if err != nil {
		httpError(w, err)
		return nil
	}
	out := make([]httpEntry, 0, len(infos)+1)
	for _, fi := range infos {
		out = append(out, fileEntry(fi))
	}
	if r.sub == "" || r.sub == "." {
		mb, _ := store.Meta(r.bucket)
		out = append(out, httpEntry{Name: config.NameMeta, Size: int64(len(mb)), ModTime: epoch})
	}
	return out
}

func (hh *httpHandler) writeJSON(w http.ResponseWriter, entries []httpEntry) {
	if entries == nil {
		return // an error was already written
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

func dirEntry(name string) httpEntry {
	return httpEntry{Name: name, IsDir: true, ModTime: epoch}
}

func fileEntry(fi os.FileInfo) httpEntry {
	return httpEntry{
		Name:    fi.Name(),
		Size:    fi.Size(),
		IsDir:   fi.IsDir(),
		ModTime: fi.ModTime().UTC().Format(time.RFC3339),
	}
}

// httpError maps store/resolve errors to HTTP status codes.
func httpError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, os.ErrPermission):
		http.Error(w, "forbidden", http.StatusForbidden)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
