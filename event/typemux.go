// Quantaureum Node source, version 1.0.0.
package event

// L14-040 SECURITY NOTE: Event ordering is NOT guaranteed across different
// event types. Events of the same type are delivered in subscription order
// (FIFO within a single subscriber's channel), but events of different
// types may be interleaved. Subscribers that require strict ordering
// across multiple event types must implement their own ordering layer
// using sequence numbers or timestamps. The event mux uses buffered
// channels to prevent slow subscribers from blocking the event source.

import (
	"errors"
	"reflect"
	"sync"
	"time"
)

// TypeMux is a type-based event multiplexer.
// It dispatches events to subscribers based on the event's type.
// This is provided for backward compatibility with older code.
type TypeMux struct {
	mu       sync.RWMutex
	subs     map[reflect.Type][]*TypeMuxSubscription
	stopped  bool
	maxSubs  int // audit-fix ROUND4-M1: max subscriptions to prevent DoS
	subCount int // total subscription count
}

// ErrTooManyMuxSubscriptions is returned when max subscription limit is reached
var ErrTooManyMuxSubscriptions = errors.New("too many mux subscriptions")

// NewTypeMux creates a new TypeMux.
func NewTypeMux() *TypeMux {
	return &TypeMux{
		subs:     make(map[reflect.Type][]*TypeMuxSubscription),
		maxSubs:  defaultMaxSubscriptions,
		subCount: 0,
	}
}

// TypeMuxEvent is a wrapper for events posted through TypeMux.
type TypeMuxEvent struct {
	Time int64 // Unix timestamp when the event was posted
	Data any   // The actual event data
}

// TypeMuxSubscription is a subscription to one or more event types.
type TypeMuxSubscription struct {
	mux     *TypeMux
	created int64
	closeMu sync.Mutex
	closing chan struct{}
	closed  bool

	// postMu protects postC
	postMu sync.RWMutex
	postC  chan *TypeMuxEvent

	// readC is the channel returned to the subscriber
	readC <-chan *TypeMuxEvent
}

// ErrMuxClosed is returned when posting to a stopped TypeMux.
var ErrMuxClosed = errors.New("event: mux closed")

// Subscribe creates a subscription for the given event types.
// Events will be delivered on the returned subscription's channel.
// Returns ErrMuxClosed if the mux has been stopped.
//
// audit-fix ROUND4-M1: returns nil when max subscription limit is reached
// L10-015 FIX: returns ErrMuxClosed when subscribing to a closed mux.
func (mux *TypeMux) Subscribe(types ...any) (*TypeMuxSubscription, error) {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	// L10-015 FIX: Check if mux is closed before creating a subscription.
	if mux.stopped {
		return nil, ErrMuxClosed
	}

	// Check max subscription limit to prevent DoS
	if mux.subCount >= mux.maxSubs {
		return nil, ErrTooManyMuxSubscriptions
	}

	sub := &TypeMuxSubscription{
		mux:     mux,
		created: timeNow(),
		closing: make(chan struct{}),
	}
	// Create buffered channel
	postC := make(chan *TypeMuxEvent, 200)
	sub.postC = postC
	sub.readC = postC

	mux.subCount++
	for _, t := range types {
		rtyp := reflect.TypeOf(t)
		mux.subs[rtyp] = append(mux.subs[rtyp], sub)
	}
	return sub, nil
}

// Post sends an event to all subscribers of the event's type.
// It returns ErrMuxClosed if the mux has been stopped.
func (mux *TypeMux) Post(ev any) error {
	event := &TypeMuxEvent{
		Time: timeNow(),
		Data: ev,
	}
	rtyp := reflect.TypeOf(ev)

	mux.mu.RLock()
	if mux.stopped {
		mux.mu.RUnlock()
		return ErrMuxClosed
	}
	subs := mux.subs[rtyp]
	mux.mu.RUnlock()

	for _, sub := range subs {
		sub.deliver(event)
	}
	return nil
}

// Stop closes the mux. All subscriptions are closed and
// future Post calls will return ErrMuxClosed.
func (mux *TypeMux) Stop() {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	if mux.stopped {
		return
	}
	mux.stopped = true

	// Close all subscriptions
	for _, subs := range mux.subs {
		for _, sub := range subs {
			sub.closeLocked()
		}
	}
	mux.subs = nil
	// L7-017 FIX: reset the subscription counter so a stopped mux reports
	// an accurate count; subsequent Subscribe attempts return a closed sub
	// without incrementing subCount.
	mux.subCount = 0
	// L8-014 CONFIRMED FIXED: subCount is reset to 0 in Stop() (L7-017 FIX).
	// This prevents a stopped-then-restarted mux from carrying over stale
	// subscription counts, which could cause false DoS-limit rejections.
}

// deliver sends an event to the subscription's channel.
func (sub *TypeMuxSubscription) deliver(event *TypeMuxEvent) {
	sub.postMu.RLock()
	defer sub.postMu.RUnlock()

	select {
	case sub.postC <- event:
	case <-sub.closing:
	default:
		// Channel full, drop the event (as per requirement 7.5)
	}
}

// Chan returns the channel that receives events.
func (sub *TypeMuxSubscription) Chan() <-chan *TypeMuxEvent {
	return sub.readC
}

// Unsubscribe closes the subscription.
func (sub *TypeMuxSubscription) Unsubscribe() {
	sub.mux.del(sub)
	sub.closeLocked()
}

// Closed returns whether the subscription is closed.
func (sub *TypeMuxSubscription) Closed() bool {
	sub.closeMu.Lock()
	defer sub.closeMu.Unlock()
	return sub.closed
}

// closeLocked closes the subscription without removing it from the mux.
func (sub *TypeMuxSubscription) closeLocked() {
	sub.closeMu.Lock()
	defer sub.closeMu.Unlock()

	if sub.closed {
		return
	}
	sub.closed = true
	close(sub.closing)

	sub.postMu.Lock()
	close(sub.postC)
	sub.postC = nil
	sub.postMu.Unlock()
}

// del removes a subscription from the mux.
func (mux *TypeMux) del(sub *TypeMuxSubscription) {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	// EVENT-01 FIX (deep-audit 2026-07-12): remove the subscription from every
	// type slice it appears in, but decrement subCount AT MOST ONCE. The inner
	// break only exits the inner loop, so a subscription registered under
	// multiple event types (Subscribe(TypeA, TypeB)) was previously matched once
	// per type and decremented subCount once per type — while Subscribe
	// increments it only once. That drove subCount below the true count and
	// progressively weakened the maxSubs DoS cap.
	removed := false
	for typ, subs := range mux.subs {
		for i, s := range subs {
			if s == sub {
				mux.subs[typ] = append(subs[:i], subs[i+1:]...)
				removed = true
				break
			}
		}
	}
	if removed && mux.subCount > 0 {
		mux.subCount--
	}
}

// timeNow returns the current Unix timestamp in nanoseconds.
func timeNow() int64 {
	return timeNowFunc()
}

// timeNowFunc is a variable for testing purposes.
var timeNowFunc = defaultTimeNow

func defaultTimeNow() int64 {
	return time.Now().UnixNano()
}
