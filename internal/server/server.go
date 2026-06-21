// Package server implements pdsd: an SSH server presenting an SFTP subsystem backed
// by the PDS bucket store. It authenticates clients by public key (mapping each key
// to a host name) and serves a custom virtual filesystem via sftp.RequestServer. When
// allowAnonymous is set it also accepts keyless clients (SSH user "anonymous"), which
// get read-only access with no host identity.
package server

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"petris.net/pds/internal/config"
	"petris.net/pds/internal/sshkeys"
	"petris.net/pds/internal/store"
)

// Connection limits guarding against pre-auth resource exhaustion.
const (
	handshakeTimeout = 30 * time.Second // max time to complete the SSH handshake
	maxConns         = 256              // max concurrent connections
)

// Server holds the SSH configuration and bucket config for pdsd.
type Server struct {
	cfg       *config.Server
	sshCfg    *ssh.ServerConfig
	sem       chan struct{}    // bounds concurrent connections
	committer *store.Committer // serializes push validation/commit
}

// SSH permission extensions carrying the outcome of authentication to the session:
// the authenticated host name, or a marker that the connection is anonymous (and
// therefore read-only).
const (
	extHost = "pds-host"
	extAnon = "pds-anon"
)

// New builds a Server from config and the loaded host-key signers.
func New(cfg *config.Server, signers []ssh.Signer) (*Server, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("no host keys: place at least one private key in ~/.ssh/id_*")
	}
	sshCfg := &ssh.ServerConfig{}
	if len(cfg.AuthorizedKeys) > 0 {
		hostMap, err := sshkeys.ClientHostMap(cfg.AuthorizedKeys)
		if err != nil {
			return nil, err
		}
		sshCfg.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			host, ok := sshkeys.HostFor(hostMap, key)
			if !ok {
				return nil, fmt.Errorf("unauthorized public key %s", ssh.FingerprintSHA256(key))
			}
			return &ssh.Permissions{Extensions: map[string]string{extHost: host}}, nil
		}
	}
	if cfg.AllowAnonymous {
		// Accept the "none" auth method, but only for the reserved anonymous user.
		// Authenticated clients use a different user name, so their "none" attempt
		// fails and they fall through to public-key auth.
		sshCfg.NoClientAuth = true
		sshCfg.NoClientAuthCallback = func(meta ssh.ConnMetadata) (*ssh.Permissions, error) {
			if meta.User() != config.AnonymousUser {
				return nil, fmt.Errorf("anonymous access requires user %q", config.AnonymousUser)
			}
			return &ssh.Permissions{Extensions: map[string]string{extAnon: "1"}}, nil
		}
	}
	for _, s := range signers {
		sshCfg.AddHostKey(s)
	}
	return &Server{
		cfg:       cfg,
		sshCfg:    sshCfg,
		sem:       make(chan struct{}, maxConns),
		committer: store.NewCommitter(),
	}, nil
}

// ListenAndServe serves connections on the configured SSH/SFTP endpoint and, when
// httpListen is set, the read-only HTTP endpoint concurrently. Either endpoint may
// bind a fixed address/hostname (bound once, fatal on failure) or track a network
// interface's addresses over time (see iface: in the config). Either endpoint
// failing tears down the other and returns.
func (s *Server) ListenAndServe() error {
	var groups []*listenGroup
	var ticks []<-chan time.Time
	var stops []func()
	defer func() {
		for _, stop := range stops {
			stop()
		}
	}()

	add := func(spec config.EndpointSpec, prepare func(net.Listener) (func() error, func())) {
		g := &listenGroup{
			name:    spec.Iface, // "" for a static endpoint
			listen:  func(addr string) (net.Listener, error) { return net.Listen("tcp", addr) },
			prepare: prepare,
			now:     time.Now,
		}
		var tick <-chan time.Time
		if spec.Static() {
			g.src = func() ([]string, error) { return []string{spec.Addr}, nil }
		} else {
			g.src = interfaceAddrs(spec.Iface, spec.Port, usable)
			g.grace = ifaceGrace
			t := time.NewTicker(ifacePollInterval)
			stops = append(stops, t.Stop)
			tick = t.C
		}
		groups = append(groups, g)
		ticks = append(ticks, tick)
	}

	lspec, err := s.cfg.ListenEndpoint()
	if err != nil {
		return err
	}
	// SSH/SFTP: serve the accept loop; teardown just closes the listener.
	add(lspec, func(ln net.Listener) (func() error, func()) {
		return func() error { return s.Serve(ln) }, func() { _ = ln.Close() }
	})

	hspec, ok, err := s.cfg.HTTPEndpoint()
	if err != nil {
		return err
	}
	if ok {
		add(hspec, s.httpPrepare)
	}

	return runGroups(groups, ticks)
}

// httpPrepare gives one HTTP listener its own read-only http.Server. The returned
// serve runs that server; the returned close shuts it down, ending its active
// connections (a plain listener Close would leave accepted requests running). The
// server is built here, synchronously, so tearing a listener down — an address
// removed, or the whole endpoint stopping — never races server registration, and
// each address's connections are closed without disturbing the others.
func (s *Server) httpPrepare(ln net.Listener) (serve func() error, closeFn func()) {
	srv := &http.Server{Handler: s.HTTPHandler(), ReadHeaderTimeout: handshakeTimeout}
	return func() error { return srv.Serve(ln) }, func() { _ = srv.Close() }
}

// HTTPHandler returns the read-only HTTP handler that serves bucket contents as an
// anonymous client. Exposed so it can be mounted on a listener directly (e.g. in tests).
func (s *Server) HTTPHandler() http.Handler {
	return newHTTPHandler(s.cfg)
}

// Serve accepts and handles connections on ln.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		// Non-blocking acquire: at capacity, drop the new connection immediately
		// rather than hold a deadline-less accepted socket.
		select {
		case s.sem <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-s.sem }()
				s.handleConn(c)
			}(conn)
		default:
			log.Printf("at capacity (%d conns); rejecting %s", maxConns, conn.RemoteAddr())
			conn.Close()
		}
	}
}

func (s *Server) handleConn(nConn net.Conn) {
	defer nConn.Close()
	// Bound the time a half-open connection can tie up resources before auth.
	_ = nConn.SetDeadline(time.Now().Add(handshakeTimeout))
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, s.sshCfg)
	if err != nil {
		log.Printf("handshake failed from %s: %v", nConn.RemoteAddr(), err)
		return
	}
	defer sconn.Close()
	// Clear the deadline so long SFTP transfers aren't interrupted.
	_ = nConn.SetDeadline(time.Time{})
	host := sconn.Permissions.Extensions[extHost]
	anon := sconn.Permissions.Extensions[extAnon] == "1"
	if anon {
		log.Printf("anonymous (read-only) connection from %s", nConn.RemoteAddr())
	} else {
		log.Printf("connection from %s as host %q", nConn.RemoteAddr(), host)
	}

	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		ch, requests, err := newChan.Accept()
		if err != nil {
			log.Printf("channel accept failed: %v", err)
			continue
		}
		go s.handleSession(ch, requests, host, anon)
	}
}

func (s *Server) handleSession(ch ssh.Channel, in <-chan *ssh.Request, host string, readOnly bool) {
	defer ch.Close()
	for req := range in {
		if req.Type == "subsystem" && isSFTP(req.Payload) {
			_ = req.Reply(true, nil)
			h := newHandlers(s.cfg, host, readOnly, s.committer)
			srv := sftp.NewRequestServer(ch, sftp.Handlers{
				FileGet:  h,
				FilePut:  h,
				FileList: h,
				FileCmd:  h,
			})
			if err := srv.Serve(); err != nil && !errors.Is(err, io.EOF) {
				log.Printf("sftp session (host %q) ended: %v", host, err)
			}
			_ = srv.Close()
			return
		}
		_ = req.Reply(false, nil)
	}
}

// isSFTP reports whether a subsystem request payload names the sftp subsystem. The
// payload is an SSH string: a 4-byte big-endian length followed by the name.
func isSFTP(payload []byte) bool {
	return len(payload) >= 4 && string(payload[4:]) == "sftp"
}
