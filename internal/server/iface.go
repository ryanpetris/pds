package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Interface-tracking listeners. A listenGroup keeps a set of open listeners
// reconciled to the addresses an addrSource reports, serving each connection via
// a supplied serve function. Static endpoints (a fixed address or hostname) use
// the same machinery with a constant source and no grace window, so the accept
// path is identical for both modes.

const (
	// ifacePollInterval is how often an interface endpoint re-enumerates its
	// addresses. Reconcile-to-current-truth makes the exact cadence uncritical.
	ifacePollInterval = 2 * time.Second
	// ifaceGrace is how long an interface endpoint tolerates having no usable
	// address (including at startup) before pdsd treats it as fatal.
	ifaceGrace = 60 * time.Second
)

// addrSource reports the bind strings an endpoint should currently be listening
// on. A non-nil fatalErr means enumeration itself failed unrecoverably (e.g. the
// netlink socket used to list interface addresses was blocked), so the group must
// die immediately rather than wait out the grace window.
type addrSource func() (addrs []string, fatalErr error)

// managedListener is one open listener owned by a listenGroup's reconcile loop.
// The reconcile loop is the sole mutator of the group's listener map; a serve
// goroutine only flips intentional (before its listener is closed on purpose) and
// closes done when it exits, so no mutex is needed on the hot path.
type managedListener struct {
	closeFn     func()        // tears the listener down (and its http.Server, for HTTP)
	intentional atomic.Bool   // set before closeFn() so the serve goroutine stays quiet
	done        chan struct{} // closed when the serve goroutine returns
}

// listenGroup keeps a set of listeners reconciled to the addresses reported by
// src. With grace>0 (an interface endpoint) it tolerates the address set being
// empty for up to grace before returning a fatal error; with grace==0 (a static
// endpoint) src returns one fixed address and the empty path is never
// legitimately reached.
type listenGroup struct {
	name   string                                  // interface name for logs; "" for static
	src    addrSource                              // address provider (interface poll, or constant)
	listen func(addr string) (net.Listener, error) // net.Listen, injectable for tests
	grace  time.Duration                           // empty-set tolerance; 0 disables the grace path
	now    func() time.Time                        // clock, injectable for tests

	// prepare turns a freshly opened listener into the function that serves it
	// (run in a goroutine) and the function that tears it down (run synchronously
	// during reconcile/teardown). Returning both from one synchronous call lets a
	// serve and its teardown share per-listener state — e.g. the HTTP endpoint's
	// http.Server, whose Close ends active connections — with no map and no race
	// between registration and teardown.
	prepare func(ln net.Listener) (serve func() error, closeFn func())

	afterReconcile func() // test hook: invoked at the end of every reconcile; nil in production
}

// Run reconciles listeners on each tick until ctx is cancelled or a fatal
// condition occurs (an unexpected serve error, grace expiry, or an enumeration
// failure from src). It always closes every listener and waits for its serve
// goroutines before returning, so teardown is deterministic. It returns nil on a
// clean ctx cancel and the fatal error otherwise.
func (g *listenGroup) Run(ctx context.Context, tick <-chan time.Time) error {
	active := map[string]*managedListener{}
	errc := make(chan error, 1)
	defer g.closeAll(active)

	var (
		armed    bool      // whether the empty-set grace deadline is running
		deadline time.Time // when the grace window expires (valid while armed)
	)

	reconcile := func() error {
		if g.afterReconcile != nil {
			defer g.afterReconcile()
		}
		addrs, fatal := g.src()
		if fatal != nil {
			return fatal
		}
		desired := make(map[string]struct{}, len(addrs))
		for _, a := range addrs {
			desired[a] = struct{}{}
		}
		// Drop listeners whose address is no longer present.
		for a, ml := range active {
			if _, ok := desired[a]; ok {
				continue
			}
			g.stop(ml)
			delete(active, a)
			if g.name != "" {
				log.Printf("pdsd: interface %q lost %s, stopped listening", g.name, a)
			}
		}
		// Open listeners for newly present addresses.
		for a := range desired {
			if _, ok := active[a]; ok {
				continue
			}
			ln, err := g.listen(a)
			if err != nil {
				// Static: the bind-once-or-die failure. Interface: an address we
				// were told about but could not bind; surfacing it as fatal beats
				// silently serving a subset.
				return fmt.Errorf("listen %s: %w", a, err)
			}
			// Build the serve and close functions synchronously, before the serve
			// goroutine starts, so teardown can never race server registration.
			serve, closeFn := g.prepare(ln)
			ml := &managedListener{closeFn: closeFn, done: make(chan struct{})}
			active[a] = ml
			go g.serveOne(ml, serve, a, errc)
			if g.name != "" {
				log.Printf("pdsd: interface %q listening on %s", g.name, ln.Addr())
			} else {
				log.Printf("pdsd: listening on %s", ln.Addr())
			}
		}
		return g.checkGrace(len(active) > 0, &armed, &deadline)
	}

	if err := reconcile(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			return err
		case <-tick:
			if err := reconcile(); err != nil {
				return err
			}
		}
	}
}

// checkGrace advances the empty-set grace state machine. The deadline is armed on
// the edge into the empty state (or at startup) and cleared the moment an address
// returns; it is never re-armed while already empty, so the window actually
// expires. It returns a fatal error once an interface has been empty for grace.
func (g *listenGroup) checkGrace(serving bool, armed *bool, deadline *time.Time) error {
	if serving {
		*armed = false
		return nil
	}
	if g.grace <= 0 {
		// A static endpoint's constant source never legitimately goes empty;
		// treat it defensively as fatal rather than spin.
		return fmt.Errorf("no address to listen on")
	}
	now := g.now()
	if !*armed {
		*armed = true
		*deadline = now.Add(g.grace)
		log.Printf("pdsd: interface %q has no usable address; waiting up to %s", g.name, g.grace)
		return nil
	}
	if !now.Before(*deadline) {
		return fmt.Errorf("interface %q had no usable address for %s", g.name, g.grace)
	}
	return nil
}

// serveOne runs a listener's serve function. A return after an intentional close
// is silent; any other return is an unexpected failure reported once to errc.
func (g *listenGroup) serveOne(ml *managedListener, serve func() error, addr string, errc chan<- error) {
	defer close(ml.done)
	err := serve()
	if ml.intentional.Load() {
		return
	}
	select {
	case errc <- fmt.Errorf("serve %s: %w", addr, err):
	default:
	}
}

// stop marks a listener's close as intentional and tears it down, then waits for
// its serve goroutine to exit. Setting intentional before closeFn happens-before
// the goroutine observes the resulting serve error, so the close is never
// mistaken for a failure.
func (g *listenGroup) stop(ml *managedListener) {
	ml.intentional.Store(true)
	ml.closeFn()
	<-ml.done
}

// closeAll stops every active listener and waits for their serve goroutines.
func (g *listenGroup) closeAll(active map[string]*managedListener) {
	for a, ml := range active {
		g.stop(ml)
		delete(active, a)
	}
}

// runGroups runs each group concurrently, returning the error from the first to
// stop. A shared context is cancelled as soon as any group returns, so a failure
// in one endpoint tears down the others (keeping the SSH and HTTP endpoints'
// lifetimes coupled). It waits for every group to finish closing before returning.
func runGroups(groups []*listenGroup, ticks []<-chan time.Time) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error, len(groups))
	var wg sync.WaitGroup
	for i, g := range groups {
		wg.Add(1)
		go func(g *listenGroup, tick <-chan time.Time) {
			defer wg.Done()
			errc <- g.Run(ctx, tick)
		}(g, ticks[i])
	}

	err := <-errc // first group to stop
	cancel()      // tear down the rest
	wg.Wait()
	return err
}

// usable reports whether an interface address should be bound. It accepts global
// unicast (including ULA) and loopback addresses and skips link-local, multicast,
// and unspecified addresses, none of which make useful service endpoints. An
// interface that is not up contributes no addresses. An interface that has only
// link-local addresses therefore counts as empty (relevant at boot before SLAAC/
// DHCP assigns a routable address).
func usable(ip net.IP, fl net.Flags) bool {
	if fl&net.FlagUp == 0 {
		return false
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

// ifaceLookup returns an interface's flags and addresses by name. found is false
// when no interface by that name exists (a transient, non-fatal condition); a
// non-nil error means enumeration itself failed (fatal). Injected so tests can
// simulate both without real interfaces.
type ifaceLookup func(name string) (flags net.Flags, addrs []net.Addr, found bool, err error)

// netInterfaceLookup enumerates interfaces via the kernel (netlink on Linux). A
// missing interface is reported as found=false, not an error, so it is told apart
// from an enumeration failure such as a blocked AF_NETLINK socket.
func netInterfaceLookup(name string) (net.Flags, []net.Addr, bool, error) {
	ifis, err := net.Interfaces()
	if err != nil {
		return 0, nil, false, err
	}
	for i := range ifis {
		if ifis[i].Name != name {
			continue
		}
		addrs, err := ifis[i].Addrs()
		if err != nil {
			return 0, nil, false, err
		}
		return ifis[i].Flags, addrs, true, nil
	}
	return 0, nil, false, nil
}

// interfaceAddrs builds an addrSource that resolves name's current usable bind
// strings on each call, joining each accepted address with port.
func interfaceAddrs(name, port string, filter func(net.IP, net.Flags) bool) addrSource {
	return interfaceAddrsWith(netInterfaceLookup, name, port, filter)
}

// interfaceAddrsWith is interfaceAddrs with an injectable lookup. A missing
// interface yields an empty set (feeding the grace window); any lookup error is
// fatal and names the likely cause so a hardening misconfig is not mistaken for a
// 60s-delayed "no address" death.
func interfaceAddrsWith(lookup ifaceLookup, name, port string, filter func(net.IP, net.Flags) bool) addrSource {
	return func() ([]string, error) {
		fl, addrs, found, err := lookup(name)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w (is AF_NETLINK allowed? see RestrictAddressFamilies)", name, err)
		}
		if !found {
			return nil, nil
		}
		var out []string
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if filter(ip, fl) {
				out = append(out, net.JoinHostPort(ip.String(), port))
			}
		}
		return out, nil
	}
}
