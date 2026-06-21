package server

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ifaceHarness drives a listenGroup deterministically: the test mutates the
// reported address set and the clock, sends explicit ticks, and reads one signal
// per completed reconcile. Listeners are real loopback sockets so open/close is
// observed honestly.
type ifaceHarness struct {
	mu     sync.Mutex
	addrs  []string
	fatal  error
	now    time.Time
	opened map[string]net.Listener

	tick       chan time.Time
	reconciled chan struct{}
	serveErr   func(addr string) error // optional: makes serve return this error
}

func newIfaceHarness(grace time.Duration) (*ifaceHarness, *listenGroup) {
	h := &ifaceHarness{
		now:        time.Unix(1_000_000, 0),
		opened:     map[string]net.Listener{},
		tick:       make(chan time.Time),
		reconciled: make(chan struct{}, 64),
	}
	g := &listenGroup{
		name:           "test0",
		src:            h.src,
		listen:         h.listen,
		prepare:        h.prepare,
		grace:          grace,
		now:            h.clock,
		afterReconcile: func() { h.reconciled <- struct{}{} },
	}
	return h, g
}

// prepare is the harness's default: serve via h.serve, tear down by closing the
// listener. Tests that need to observe teardown override g.prepare directly.
func (h *ifaceHarness) prepare(ln net.Listener) (func() error, func()) {
	return func() error { return h.serve(ln) }, func() { _ = ln.Close() }
}

func (h *ifaceHarness) src() ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.addrs...), h.fatal
}

func (h *ifaceHarness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *ifaceHarness) setAddrs(addrs ...string) {
	h.mu.Lock()
	h.addrs = addrs
	h.mu.Unlock()
}

func (h *ifaceHarness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func (h *ifaceHarness) listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.opened[addr] = ln
	h.mu.Unlock()
	return ln, nil
}

func (h *ifaceHarness) serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		if h.serveErr != nil {
			c.Close()
			return h.serveErr(ln.Addr().String())
		}
		c.Close()
	}
}

// pump sends one tick and waits for the reconcile it triggers to finish.
func (h *ifaceHarness) pump(t *testing.T) {
	t.Helper()
	select {
	case h.tick <- time.Time{}:
	case <-time.After(2 * time.Second):
		t.Fatal("tick was not consumed (Run not reconciling?)")
	}
	h.waitReconcile(t)
}

func (h *ifaceHarness) waitReconcile(t *testing.T) {
	t.Helper()
	select {
	case <-h.reconciled:
	case <-time.After(2 * time.Second):
		t.Fatal("reconcile did not complete")
	}
}

func (h *ifaceHarness) listenerFor(addr string) net.Listener {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.opened[addr]
}

// start runs g.Run in a goroutine and waits for the initial reconcile.
func startGroup(t *testing.T, h *ifaceHarness, g *listenGroup) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx, h.tick) }()
	h.waitReconcile(t) // initial reconcile before the select loop
	return cancel, done
}

func assertRunning(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("Run returned unexpectedly: %v", err)
	default:
	}
}

func canDial(ln net.Listener) bool {
	c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func TestGroupOpensAndClosesListeners(t *testing.T) {
	h, g := newIfaceHarness(time.Minute)
	h.setAddrs("127.0.0.1:0", "127.0.0.2:0")
	cancel, done := startGroup(t, h, g)
	defer cancel()

	a := h.listenerFor("127.0.0.1:0")
	b := h.listenerFor("127.0.0.2:0")
	if a == nil || b == nil {
		t.Fatal("expected both listeners open after first reconcile")
	}
	if !canDial(a) || !canDial(b) {
		t.Fatal("both listeners should accept connections")
	}

	// Drop one address; its listener must close, the other keep serving.
	h.setAddrs("127.0.0.2:0")
	h.pump(t)
	assertRunning(t, done)

	if _, err := a.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("dropped listener should be closed, got %v", err)
	}
	if !canDial(b) {
		t.Error("kept listener should still accept connections")
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("clean cancel should return nil, got %v", err)
	}
	if _, err := b.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("remaining listener should be closed after cancel, got %v", err)
	}
}

func TestGroupClosesViaPreparedCloser(t *testing.T) {
	h, g := newIfaceHarness(time.Minute)
	var mu sync.Mutex
	var closed []string
	// Override prepare so teardown is observable: record the close, then actually
	// close the listener (as http.Server.Close would).
	g.prepare = func(ln net.Listener) (func() error, func()) {
		addr := ln.Addr().String()
		return func() error { return h.serve(ln) }, func() {
			mu.Lock()
			closed = append(closed, addr)
			mu.Unlock()
			_ = ln.Close()
		}
	}

	h.setAddrs("127.0.0.1:0", "127.0.0.2:0")
	cancel, done := startGroup(t, h, g)
	defer cancel()

	aAddr := h.listenerFor("127.0.0.1:0").Addr().String()

	// Removing an address must tear it down through the hook, not a raw ln.Close.
	h.setAddrs("127.0.0.2:0")
	h.pump(t)
	assertRunning(t, done)

	mu.Lock()
	got := append([]string(nil), closed...)
	mu.Unlock()
	if len(got) != 1 || got[0] != aAddr {
		t.Fatalf("address removal should close via hook, got %v (want [%s])", got, aAddr)
	}

	// Full teardown routes the remaining listener through the hook too.
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("clean cancel returned: %v", err)
	}
	mu.Lock()
	total := len(closed)
	mu.Unlock()
	if total != 2 {
		t.Errorf("both listeners should be closed via the hook, got %d: %v", total, closed)
	}
}

func TestGroupServeErrorIsFatal(t *testing.T) {
	h, g := newIfaceHarness(time.Minute)
	boom := errors.New("accept exploded")
	h.serveErr = func(string) error { return boom }
	h.setAddrs("127.0.0.1:0")
	cancel, done := startGroup(t, h, g)
	defer cancel()

	// Trigger the serve error by connecting once.
	ln := h.listenerFor("127.0.0.1:0")
	if c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		c.Close()
	}

	select {
	case err := <-done:
		if !errors.Is(err, boom) {
			t.Fatalf("expected fatal serve error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after a real serve error")
	}
}

func TestGroupGraceStartupRecovers(t *testing.T) {
	h, g := newIfaceHarness(time.Minute)
	// Empty at startup: grace arms.
	cancel, done := startGroup(t, h, g)
	defer cancel()
	assertRunning(t, done)

	// Still empty, but before the deadline: keeps waiting.
	h.advance(59 * time.Second)
	h.pump(t)
	assertRunning(t, done)

	// Address appears before expiry: cancels the grace window and serves.
	h.setAddrs("127.0.0.1:0")
	h.pump(t)
	assertRunning(t, done)
	if ln := h.listenerFor("127.0.0.1:0"); ln == nil || !canDial(ln) {
		t.Fatal("listener should be open after the address appeared")
	}

	// Going far past the original deadline is fine now that it is serving.
	h.advance(10 * time.Minute)
	h.pump(t)
	assertRunning(t, done)
}

func TestGroupGraceExpires(t *testing.T) {
	h, g := newIfaceHarness(time.Minute)
	cancel, done := startGroup(t, h, g) // empty: arms at t0
	defer cancel()
	assertRunning(t, done)

	h.advance(time.Minute) // reach the deadline exactly
	h.pump(t)

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "no usable address") {
			t.Fatalf("expected grace-expiry error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not die after the grace window elapsed")
	}
}

func TestGroupGraceFlapResets(t *testing.T) {
	h, g := newIfaceHarness(time.Minute)
	cancel, done := startGroup(t, h, g) // empty: arm at t0 (deadline t0+60)
	defer cancel()

	h.advance(30 * time.Second) // t0+30
	h.setAddrs("127.0.0.1:0")   // address appears: clears the window
	h.pump(t)
	assertRunning(t, done)

	h.advance(10 * time.Second) // t0+40
	h.setAddrs()                // empty again: re-arm fresh (deadline t0+100)
	h.pump(t)
	assertRunning(t, done)

	// t0+95: past the ORIGINAL t0+60 deadline but before the re-armed t0+100.
	h.advance(55 * time.Second)
	h.setAddrs("127.0.0.1:0")
	h.pump(t)
	assertRunning(t, done) // must not have fired off the stale deadline
}

func TestUsable(t *testing.T) {
	up := net.FlagUp
	cases := []struct {
		ip   string
		fl   net.Flags
		want bool
	}{
		{"192.0.2.10", up, true},   // global v4
		{"2001:db8::1", up, true},  // global v6
		{"fd00::1", up, true},      // ULA v6
		{"127.0.0.1", up, true},    // loopback kept (supports iface:lo)
		{"169.254.1.1", up, false}, // v4 link-local
		{"fe80::1", up, false},     // v6 link-local
		{"224.0.0.1", up, false},   // multicast
		{"0.0.0.0", up, false},     // unspecified
		{"192.0.2.10", 0, false},   // interface down
	}
	for _, c := range cases {
		if got := usable(net.ParseIP(c.ip), c.fl); got != c.want {
			t.Errorf("usable(%s, up=%v) = %v, want %v", c.ip, c.fl&net.FlagUp != 0, got, c.want)
		}
	}
}

func TestInterfaceAddrs(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("192.0.2.5")},   // kept
		&net.IPNet{IP: net.ParseIP("fe80::1")},     // skipped (link-local)
		&net.IPNet{IP: net.ParseIP("224.0.0.1")},   // skipped (multicast)
		&net.IPNet{IP: net.ParseIP("2001:db8::9")}, // kept (bracketed)
	}

	found := interfaceAddrsWith(
		func(string) (net.Flags, []net.Addr, bool, error) { return net.FlagUp, addrs, true, nil },
		"eth0", "2222", usable)
	got, err := found()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.0.2.5:2222", "[2001:db8::9]:2222"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}

	// Missing interface => empty set, not an error.
	missing := interfaceAddrsWith(
		func(string) (net.Flags, []net.Addr, bool, error) { return 0, nil, false, nil },
		"eth0", "2222", usable)
	if got, err := missing(); err != nil || got != nil {
		t.Errorf("missing interface: got (%v, %v), want (nil, nil)", got, err)
	}

	// Enumeration failure => fatal error mentioning the likely cause.
	boom := errors.New("operation not permitted")
	failed := interfaceAddrsWith(
		func(string) (net.Flags, []net.Addr, bool, error) { return 0, nil, false, boom },
		"eth0", "2222", usable)
	if _, err := failed(); err == nil || !strings.Contains(err.Error(), "AF_NETLINK") {
		t.Errorf("enumeration failure should be fatal and mention AF_NETLINK, got %v", err)
	}
}

func TestStaticGroupBindOnceError(t *testing.T) {
	// grace=0 static group whose bind fails must return that error (bind-once-or-die).
	g := &listenGroup{
		src:    func() ([]string, error) { return []string{"203.0.113.1:9"}, nil },
		listen: func(string) (net.Listener, error) { return nil, errors.New("cannot assign requested address") },
		prepare: func(ln net.Listener) (func() error, func()) {
			return func() error { return nil }, func() { _ = ln.Close() }
		},
		now: time.Now,
	}
	err := g.Run(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "cannot assign") {
		t.Fatalf("static bind failure should be fatal, got %v", err)
	}
}

// The shipped system unit must allow AF_NETLINK, or interface-tracking endpoints
// die at startup when enumerating addresses under the hardened sandbox.
func TestSystemdUnitAllowsNetlink(t *testing.T) {
	b, err := os.ReadFile("../../packaging/systemd/pdsd@.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "RestrictAddressFamilies=") {
			if !strings.Contains(line, "AF_NETLINK") {
				t.Errorf("pdsd@.service RestrictAddressFamilies must include AF_NETLINK: %q", line)
			}
			return
		}
	}
	t.Error("no RestrictAddressFamilies line found in pdsd@.service")
}
