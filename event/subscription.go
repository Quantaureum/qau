// Quantaureum Node source, version 1.0.0.
// Package event provides event subscription and publishing functionality.
package event

import (
	"errors"
	"sync"
)

// Subscription represents an event subscription that can be canceled.
type Subscription interface {
	// Unsubscribe cancels the subscription and closes the error channel.
	Unsubscribe()
	// Err returns a channel that receives an error when the subscription ends.
	// The channel is closed when Unsubscribe is called.
	Err() <-chan error
}

// ErrSubscriptionClosed is returned when operations are attempted on a closed subscription.
var ErrSubscriptionClosed = errors.New("subscription closed")

// subscription is the internal implementation of Subscription.
type subscription struct {
	feed      *Feed
	channel   any
	err       chan error
	unsubOnce sync.Once
	closed    bool
	mu        sync.Mutex
}

// Unsubscribe cancels the subscription.
func (s *subscription) Unsubscribe() {
	s.unsubOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()

		if s.feed != nil {
			s.feed.remove(s)
		}
		close(s.err)
	})
}

// Err returns the error channel.
func (s *subscription) Err() <-chan error {
	return s.err
}

// isClosed returns whether the subscription is closed.
func (s *subscription) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
