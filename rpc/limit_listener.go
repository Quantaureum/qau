// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"errors"
	"net"
	"sync"
)

// limitListener wraps a net.Listener with a semaphore that bounds the
// number of simultaneously accepted connections. RPC-R13-H02 (2026-07-21):
// the standard library http.Server imposes no cap on the number of in-flight
// connections, so an attacker could open thousands of idle keep-alive
// sockets and exhaust the process file-descriptor table. This wrapper
// mirrors the behavior of golang.org/x/net/netutil.LimitListener without
// introducing that dependency (the project's go.mod does not currently
// require golang.org/x/net).
//
// When the connection limit is reached, Accept blocks until an existing
// connection is released — callers that hit the limit see a delayed Accept
// rather than an error. This matches netutil's semantics and gives the
// server a natural backpressure signal: clients perceive rising latency
// before being rejected outright. The alternative (return an error when
// the semaphore is full) would cause http.Server to log errors on every
// rejected connection, producing log noise during legitimate traffic bursts.
//
// RPC-R14-CRIT-003 (2026-07-21): the previous Accept() blocked on
// `l.sem <- struct{}{}` without any way to be woken up when Close() was
// called. If all semaphore slots were occupied (e.g., 1024 idle
// keep-alive connections holding the limit), Accept() would block
// forever, and Close() on the underlying listener could not interrupt
// it — the server could not perform a graceful shutdown. We now select
// on a `closed` channel that is closed by Close(), so a blocked Accept
// returns immediately with net.ErrClosed when the listener is shut down.
type limitListener struct {
	net.Listener
	sem       chan struct{}
	closeOnce sync.Once
	closed    chan struct{}
}

// newLimitListener returns a listener that admits at most n concurrent
// connections. n must be > 0; callers should validate this before invoking.
func newLimitListener(l net.Listener, n int) net.Listener {
	if n <= 0 {
		// Defensive: a non-positive limit would deadlock the listener.
		// Fall back to the raw listener rather than panicking.
		return l
	}
	return &limitListener{
		Listener: l,
		sem:      make(chan struct{}, n),
		closed:   make(chan struct{}),
	}
}

// Accept waits for the semaphore to have a free slot, then accepts a
// connection from the underlying listener. The returned connection is
// wrapped so that Close releases the semaphore slot.
//
// RPC-R14-CRIT-003 (2026-07-21): if the semaphore is full, Accept now
// also selects on the `closed` channel so a Close() call during
// graceful shutdown can interrupt the blocked Accept and return
// net.ErrClosed. Without this, an attacker holding maxHTTPConns idle
// connections could prevent the node from shutting down cleanly.
func (l *limitListener) Accept() (net.Conn, error) {
	// Acquire a slot before accepting. If the semaphore is full this
	// blocks, providing natural backpressure to the http.Server. We
	// also select on `l.closed` so Close() can interrupt us.
	select {
	case l.sem <- struct{}{}:
		// Slot acquired.
	case <-l.closed:
		return nil, errors.New("rpc: limitListener closed")
	}

	c, err := l.Listener.Accept()
	if err != nil {
		// Accept failed (listener closed or transient error): release
		// the slot we just acquired so future Accept calls can proceed
		// once the listener is reopened (e.g. during graceful shutdown).
		<-l.sem
		return nil, err
	}
	return &limitListenerConn{Conn: c, sem: l.sem}, nil
}

// Close closes the underlying listener. It is idempotent.
//
// RPC-R14-CRIT-003 (2026-07-21): closing the `closed` channel wakes up
// any Accept() callers that are currently blocked waiting for a free
// semaphore slot, allowing graceful shutdown even when the connection
// limit is exhausted.
func (l *limitListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		err = l.Listener.Close()
		// Signal any blocked Accept callers to return immediately.
		// Done after Listener.Close() so they observe the closed
		// listener state.
		close(l.closed)
	})
	return err
}

// limitListenerConn wraps a net.Conn and releases the semaphore slot
// when the connection is closed. This ensures that abandoned keep-alive
// connections (which never read another request but stay open) eventually
// free their slot once the underlying socket is torn down by either side.
type limitListenerConn struct {
	net.Conn
	sem       chan struct{}
	closeOnce sync.Once
}

func (c *limitListenerConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		<-c.sem
	})
	return err
}
