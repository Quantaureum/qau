// Quantaureum Node source, version 1.0.0.
package event

import (
	"errors"
	"reflect"
	"sync"
)

// Feed implements a one-to-many subscription model.
// Values sent to a Feed are delivered to all subscribed channels.
type Feed struct {
	mu         sync.RWMutex
	subs       map[*subscription]reflect.Value // subscription -> channel
	sendLock   chan struct{}                   // ensures only one sender at a time
	bufferSize int                             // buffer size for subscriber channels
	maxSubs    int                             // audit-fix ROUND4-M1: max subscriptions to prevent DoS
}

// ErrTooManySubscriptions is returned when max subscription limit is reached
var ErrTooManySubscriptions = errors.New("too many subscriptions")

// ErrNotAChannel is returned when Subscribe argument is not a channel
var ErrNotAChannel = errors.New("event: Subscribe argument must be a channel")

// ErrNotSendable is returned when Subscribe argument is not a sendable channel
var ErrNotSendable = errors.New("event: Subscribe argument must be a sendable channel")

// Default max subscriptions to prevent DoS
const defaultMaxSubscriptions = 1024

// NewFeed creates a new Feed with default buffer size.
func NewFeed() *Feed {
	return NewFeedWithBuffer(100)
}

// NewFeedWithBuffer creates a new Feed with specified buffer size.
func NewFeedWithBuffer(bufferSize int) *Feed {
	return &Feed{
		subs:       make(map[*subscription]reflect.Value),
		sendLock:   make(chan struct{}, 1),
		bufferSize: bufferSize,
		maxSubs:    defaultMaxSubscriptions,
	}
}

// Subscribe adds a channel to the feed. The channel must be a sendable channel.
// The type of values sent through the feed is determined by the channel's element type.
//
// The channel should have sufficient buffer to avoid blocking the sender.
// If the channel blocks, the event may be dropped.
//
// audit-fix ROUND4-M1: returns ErrTooManySubscriptions if max subscription limit is reached
func (f *Feed) Subscribe(channel any) (Subscription, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check max subscription limit to prevent DoS
	if len(f.subs) >= f.maxSubs {
		return nil, ErrTooManySubscriptions
	}

	chanVal := reflect.ValueOf(channel)
	if chanVal.Kind() != reflect.Chan {
		return nil, ErrNotAChannel
	}
	if chanVal.Type().ChanDir()&reflect.SendDir == 0 {
		return nil, ErrNotSendable
	}

	sub := &subscription{
		feed:    f,
		channel: channel,
		err:     make(chan error, 1),
	}
	f.subs[sub] = chanVal
	return sub, nil
}

// Send delivers a value to all subscribed channels.
// It returns the number of subscribers that received the value.
//
// Send blocks until all subscribers have received the value or their
// channels are full (in which case the value is dropped for that subscriber).
//
// L18-041 VERIFIED: The TOCTOU race between isClosed() and the actual send
// is fully mitigated by trySend's defer recover(). All send paths go through
// trySend, so a channel closed between the isClosed() check and reflect.Select
// will cause a panic that is safely caught, returning false (send dropped).
// No additional fix needed - the existing recover() covers all paths.
func (f *Feed) Send(value any) int {
	// Acquire send lock to ensure only one sender at a time
	f.sendLock <- struct{}{}
	defer func() { <-f.sendLock }()

	f.mu.RLock()
	// Make a copy of subscribers to avoid holding lock during send
	subs := make(map[*subscription]reflect.Value, len(f.subs))
	for sub, ch := range f.subs {
		subs[sub] = ch
	}
	f.mu.RUnlock()

	if len(subs) == 0 {
		return 0
	}

	rval := reflect.ValueOf(value)
	sent := 0

	for sub, chanVal := range subs {
		if sub.isClosed() {
			continue
		}

		// Use reflection-based send for all channels
		if f.trySend(chanVal, rval) {
			sent++
		}
	}

	return sent
}

// trySend attempts to send a value to a channel using reflection.
// Returns true if the send was successful.
// L18-041 FIX: Use recover() to safely handle panics from sending to
// closed channels. Between the subscriber snapshot (taken under RLock) and
// the actual send, a subscriber's channel may be closed by the user or by
// a race with Unsubscribe. reflect.Select with SelectSend panics on a
// closed channel; recover() catches this and returns false instead.
func (f *Feed) trySend(chanVal, value reflect.Value) (sent bool) {
	defer func() {
		if r := recover(); r != nil {
			sent = false
		}
	}()

	// Convert value to channel's element type if needed
	chanType := chanVal.Type().Elem()
	if !value.Type().AssignableTo(chanType) {
		if value.Type().ConvertibleTo(chanType) {
			value = value.Convert(chanType)
		} else {
			return false
		}
	}

	// Non-blocking send
	chosen, _, _ := reflect.Select([]reflect.SelectCase{
		{
			Dir:  reflect.SelectSend,
			Chan: chanVal,
			Send: value,
		},
		{
			Dir: reflect.SelectDefault,
		},
	})
	return chosen == 0
}

// remove removes a subscription from the feed.
func (f *Feed) remove(sub *subscription) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.subs, sub)
}

// Len returns the number of active subscriptions.
func (f *Feed) Len() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.subs)
}
