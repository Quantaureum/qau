// Quantaureum Go SDK source, version 1.0.0.
// Package contracts provides smart contract interaction functionality for the Quantaureum Go SDK.
package contracts

import (
	"context"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"github.com/quantaureum/qau/sdks/go-sdk/errors"
	"github.com/quantaureum/qau/sdks/go-sdk/types"
)

// FilterQuery represents a filter query for logs.
type FilterQuery struct {
	BlockHash *common.Hash     // Block hash (mutually exclusive with FromBlock/ToBlock)
	FromBlock *big.Int         // Start block (nil = latest)
	ToBlock   *big.Int         // End block (nil = latest)
	Addresses []common.Address // Contract addresses to filter
	Topics    [][]common.Hash  // Topics to filter
}

// LogFilterer defines the interface for filtering logs.
type LogFilterer interface {
	// FilterLogs returns logs matching the given filter query.
	FilterLogs(ctx context.Context, q FilterQuery) ([]*types.Log, error)
}

// LogSubscriber defines the interface for subscribing to logs.
type LogSubscriber interface {
	// SubscribeFilterLogs subscribes to logs matching the given filter query.
	SubscribeFilterLogs(ctx context.Context, q FilterQuery, ch chan<- *types.Log) (Subscription, error)
}

// Subscription represents an event subscription.
type Subscription interface {
	// Unsubscribe cancels the subscription.
	Unsubscribe()
	// Err returns the subscription error channel.
	Err() <-chan error
}

// EventFilterer provides event filtering functionality for a bound contract.
type EventFilterer struct {
	contract *BoundContract
	filterer LogFilterer
}

// NewEventFilterer creates a new event filterer for the given contract.
func NewEventFilterer(contract *BoundContract, filterer LogFilterer) *EventFilterer {
	return &EventFilterer{
		contract: contract,
		filterer: filterer,
	}
}

// FilterLogs filters logs for a specific event.
func (f *EventFilterer) FilterLogs(ctx context.Context, eventName string, opts *FilterOpts) ([]*types.Log, error) {
	if f.filterer == nil {
		return nil, errors.NewValidationError("filterer", "log filterer not set")
	}

	// Get event ID
	eventID, err := f.contract.abi.EventID(eventName)
	if err != nil {
		return nil, fmt.Errorf("failed to get event ID: %w", err)
	}

	// Build filter query
	query := FilterQuery{
		Addresses: []common.Address{f.contract.address},
		Topics:    [][]common.Hash{{eventID}},
	}

	if opts != nil {
		query.FromBlock = opts.Start
		query.ToBlock = opts.End
		query.BlockHash = opts.BlockHash

		// Add additional topic filters
		if len(opts.Topics) > 0 {
			query.Topics = append(query.Topics, opts.Topics...)
		}
	}

	return f.filterer.FilterLogs(ctx, query)
}

// FilterOpts represents options for filtering logs.
type FilterOpts struct {
	Start     *big.Int        // Start block (nil = genesis)
	End       *big.Int        // End block (nil = latest)
	BlockHash *common.Hash    // Specific block hash (mutually exclusive with Start/End)
	Topics    [][]common.Hash // Additional topic filters
	Context   context.Context // Context for the filter
}

// ParseLog parses a log entry into event arguments.
func (f *EventFilterer) ParseLog(eventName string, log *types.Log) ([]any, error) {
	if log == nil {
		return nil, errors.NewValidationError("log", "log cannot be nil")
	}

	return f.contract.abi.UnpackEvent(eventName, log.Data, log.Topics)
}

// EventSubscriber provides event subscription functionality for a bound contract.
type EventSubscriber struct {
	contract   *BoundContract
	subscriber LogSubscriber
}

// NewEventSubscriber creates a new event subscriber for the given contract.
func NewEventSubscriber(contract *BoundContract, subscriber LogSubscriber) *EventSubscriber {
	return &EventSubscriber{
		contract:   contract,
		subscriber: subscriber,
	}
}

// SubscribeFilterLogs subscribes to logs for a specific event.
func (s *EventSubscriber) SubscribeFilterLogs(ctx context.Context, eventName string, ch chan<- *types.Log, opts *FilterOpts) (Subscription, error) {
	if s.subscriber == nil {
		return nil, errors.NewValidationError("subscriber", "log subscriber not set")
	}

	// Get event ID
	eventID, err := s.contract.abi.EventID(eventName)
	if err != nil {
		return nil, fmt.Errorf("failed to get event ID: %w", err)
	}

	// Build filter query
	query := FilterQuery{
		Addresses: []common.Address{s.contract.address},
		Topics:    [][]common.Hash{{eventID}},
	}

	if opts != nil {
		query.FromBlock = opts.Start
		query.ToBlock = opts.End

		// Add additional topic filters
		if len(opts.Topics) > 0 {
			query.Topics = append(query.Topics, opts.Topics...)
		}
	}

	return s.subscriber.SubscribeFilterLogs(ctx, query, ch)
}

// BoundContractFilterer extends BoundContract with event filtering capabilities.
type BoundContractFilterer struct {
	*BoundContract
	filterer LogFilterer
}

// NewBoundContractFilterer creates a bound contract with filtering capabilities.
func NewBoundContractFilterer(address common.Address, abi ABI, backend interface {
	ContractBackend
	LogFilterer
}) *BoundContractFilterer {
	return &BoundContractFilterer{
		BoundContract: NewBoundContract(address, abi, backend),
		filterer:      backend,
	}
}

// FilterLogs filters logs for a specific event on this contract.
func (c *BoundContractFilterer) FilterLogs(ctx context.Context, eventName string, opts *FilterOpts) ([]*types.Log, error) {
	filterer := NewEventFilterer(c.BoundContract, c.filterer)
	return filterer.FilterLogs(ctx, eventName, opts)
}

// ParseLog parses a log entry into event arguments.
func (c *BoundContractFilterer) ParseLog(eventName string, log *types.Log) ([]any, error) {
	return c.abi.UnpackEvent(eventName, log.Data, log.Topics)
}

// BoundContractWithEvents extends BoundContract with full event capabilities.
type BoundContractWithEvents struct {
	*BoundContractFilterer
	subscriber LogSubscriber
}

// NewBoundContractWithEvents creates a bound contract with full event capabilities.
func NewBoundContractWithEvents(address common.Address, abi ABI, backend interface {
	ContractBackend
	LogFilterer
	LogSubscriber
}) *BoundContractWithEvents {
	return &BoundContractWithEvents{
		BoundContractFilterer: NewBoundContractFilterer(address, abi, backend),
		subscriber:            backend,
	}
}

// SubscribeFilterLogs subscribes to logs for a specific event on this contract.
func (c *BoundContractWithEvents) SubscribeFilterLogs(ctx context.Context, eventName string, ch chan<- *types.Log, opts *FilterOpts) (Subscription, error) {
	subscriber := NewEventSubscriber(c.BoundContract, c.subscriber)
	return subscriber.SubscribeFilterLogs(ctx, eventName, ch, opts)
}

// WatchLogs is a convenience method that creates a channel and subscribes to logs.
func (c *BoundContractWithEvents) WatchLogs(ctx context.Context, eventName string, opts *FilterOpts) (<-chan *types.Log, Subscription, error) {
	ch := make(chan *types.Log)
	sub, err := c.SubscribeFilterLogs(ctx, eventName, ch, opts)
	if err != nil {
		close(ch)
		return nil, nil, err
	}
	return ch, sub, nil
}

// EventIterator iterates over logs for a specific event.
type EventIterator struct {
	logs    []*types.Log
	index   int
	event   string
	abi     ABI
	current *types.Log
	err     error
}

// NewEventIterator creates a new event iterator.
func NewEventIterator(logs []*types.Log, eventName string, abi ABI) *EventIterator {
	return &EventIterator{
		logs:  logs,
		index: -1,
		event: eventName,
		abi:   abi,
	}
}

// Next advances the iterator to the next log.
func (it *EventIterator) Next() bool {
	it.index++
	if it.index >= len(it.logs) {
		return false
	}
	it.current = it.logs[it.index]
	return true
}

// Log returns the current log.
func (it *EventIterator) Log() *types.Log {
	return it.current
}

// Event returns the parsed event arguments for the current log.
func (it *EventIterator) Event() ([]any, error) {
	if it.current == nil {
		return nil, errors.NewValidationError("current", "no current log")
	}
	return it.abi.UnpackEvent(it.event, it.current.Data, it.current.Topics)
}

// Error returns any error that occurred during iteration.
func (it *EventIterator) Error() error {
	return it.err
}

// Close closes the iterator.
func (it *EventIterator) Close() error {
	it.logs = nil
	it.current = nil
	return nil
}

// FilterLogsIterator filters logs and returns an iterator.
func (c *BoundContractFilterer) FilterLogsIterator(ctx context.Context, eventName string, opts *FilterOpts) (*EventIterator, error) {
	logs, err := c.FilterLogs(ctx, eventName, opts)
	if err != nil {
		return nil, err
	}
	return NewEventIterator(logs, eventName, c.abi), nil
}

// TopicHash returns the topic hash for an event name.
func TopicHash(abi ABI, eventName string) (common.Hash, error) {
	return abi.EventID(eventName)
}

// EncodeTopics encodes indexed event parameters as topics.
func EncodeTopics(values ...any) ([]common.Hash, error) {
	topics := make([]common.Hash, len(values))
	for i, v := range values {
		encoded, _, err := encodeValue(getTypeName(v), v)
		if err != nil {
			return nil, fmt.Errorf("failed to encode topic %d: %w", i, err)
		}
		topics[i] = common.BytesToHash(encoded)
	}
	return topics, nil
}

// getTypeName returns the ABI type name for a Go value.
func getTypeName(v any) string {
	switch v.(type) {
	case common.Address, *common.Address:
		return "address"
	case common.Hash:
		return "bytes32"
	case *big.Int:
		return "uint256"
	case bool:
		return "bool"
	case string:
		return "string"
	case []byte:
		return "bytes"
	case uint8:
		return "uint8"
	case uint16:
		return "uint16"
	case uint32:
		return "uint32"
	case uint64:
		return "uint64"
	case int8:
		return "int8"
	case int16:
		return "int16"
	case int32:
		return "int32"
	case int64:
		return "int64"
	default:
		return "bytes32"
	}
}
