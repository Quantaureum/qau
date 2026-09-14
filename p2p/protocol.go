// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

const (
	ProtocolBase       = "qau"
	ProtocolBlockchain = "qau_blockchain"
	ProtocolConsensus  = "qau_consensus"
	ProtocolSnapSync   = "qau_snap"
	ProtocolDiscovery  = "qau_discovery"
	ProtocolExpert     = "qau_expert"
	ProtocolTSS        = "qau_tss"
	ProtocolDAS        = "qau_das"
	ProtocolShard      = "qau_shard" // P1-1: shard block/cross-shard message propagation
)

const (
	ProtocolBaseVersion       = 1
	ProtocolBlockchainVersion = 1
	ProtocolConsensusVersion  = 1
	ProtocolSnapSyncVersion   = 1
	ProtocolDiscoveryVersion  = 1
	ProtocolExpertVersion     = 1
	ProtocolTSSVersion        = 1
	ProtocolDASVersion        = 1
	ProtocolShardVersion      = 1
)

var (
	ErrProtocolNotSupported      = errors.New("protocol not supported")
	ErrProtocolVersionMismatch   = errors.New("protocol version mismatch")
	ErrProtocolAlreadyRegistered = errors.New("protocol already registered")
)

type ProtocolHandler func(msg *Message) error

type ProtocolSpec struct {
	Name     string
	Version  uint
	MsgTypes map[uint8]bool
	Handler  ProtocolHandler
}

type Protocol struct {
	Spec    ProtocolSpec
	Enabled bool
}

type ProtocolRegistry struct {
	mu        sync.RWMutex
	protocols map[string]*Protocol
	msgRoutes map[uint8]string
}

func NewProtocolRegistry() *ProtocolRegistry {
	return &ProtocolRegistry{
		protocols: make(map[string]*Protocol),
		msgRoutes: make(map[uint8]string),
	}
}

func (r *ProtocolRegistry) Register(spec ProtocolSpec) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := strings.ToLower(spec.Name)
	if _, exists := r.protocols[name]; exists {
		return fmt.Errorf("%w: %s", ErrProtocolAlreadyRegistered, name)
	}

	for msgType := range spec.MsgTypes {
		if existing, ok := r.msgRoutes[msgType]; ok {
			return fmt.Errorf("message type %d already registered by protocol %s", msgType, existing)
		}
	}

	r.protocols[name] = &Protocol{
		Spec:    spec,
		Enabled: true,
	}

	for msgType := range spec.MsgTypes {
		r.msgRoutes[msgType] = name
	}

	return nil
}

func (r *ProtocolRegistry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	name = strings.ToLower(name)
	proto, exists := r.protocols[name]
	if !exists {
		return
	}

	for msgType := range proto.Spec.MsgTypes {
		delete(r.msgRoutes, msgType)
	}

	delete(r.protocols, name)
}

func (r *ProtocolRegistry) GetProtocol(name string) *Protocol {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.protocols[strings.ToLower(name)]
}

func (r *ProtocolRegistry) RouteMessage(msg *Message) error {
	// R33 P2P-12 FIX (2026-07-28): Previously this function read
	// `proto.Enabled` and `proto.Spec.Handler` AFTER releasing r.mu.
	// EnableProtocol/DisableProtocol modify `proto.Enabled` under r.mu,
	// so reading it without the lock is a data race (Go race detector
	// flags this; in practice it can tear reads on multi-word fields
	// and cause RouteMessage to dispatch to a handler for a protocol
	// that was just disabled, or vice versa). More subtly, Unregister
	// could delete the map entry while RouteMessage is mid-flight; the
	// *Protocol pointer is still valid, but its fields may be in flux.
	//
	// Fix: snapshot the enabled flag and handler pointer while holding
	// the read lock, then release the lock before invoking the handler
	// (handlers may block, and we don't want to hold the registry lock
	// during application-layer processing). The handler pointer itself
	// is immutable after Register (Register stores a *Protocol with a
	// fixed Spec.Handler; no API mutates Spec.Handler), so reading it
	// under the lock and invoking it later is safe.
	r.mu.RLock()
	protoName, ok := r.msgRoutes[msg.Type]
	if !ok {
		r.mu.RUnlock()
		return fmt.Errorf("%w: message type %d", ErrProtocolNotSupported, msg.Type)
	}

	proto := r.protocols[protoName]
	if proto == nil {
		r.mu.RUnlock()
		return fmt.Errorf("%w: %s registered but protocol nil", ErrProtocolNotSupported, protoName)
	}

	enabled := proto.Enabled
	handler := proto.Spec.Handler
	r.mu.RUnlock()

	if !enabled {
		return fmt.Errorf("%w: %s is disabled", ErrProtocolNotSupported, protoName)
	}

	if handler != nil {
		return handler(msg)
	}

	return nil
}

func (r *ProtocolRegistry) SupportedProtocols() []ProtocolSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var specs []ProtocolSpec
	for _, p := range r.protocols {
		if p.Enabled {
			specs = append(specs, p.Spec)
		}
	}

	sort.Slice(specs, func(i, j int) bool {
		return specs[i].Name < specs[j].Name
	})

	return specs
}

func (r *ProtocolRegistry) Negotiate(peerProtocols []ProtocolSpec) []ProtocolSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var common []ProtocolSpec
	for _, pp := range peerProtocols {
		name := strings.ToLower(pp.Name)
		if local, ok := r.protocols[name]; ok && local.Enabled {
			if pp.Version == local.Spec.Version {
				common = append(common, local.Spec)
			}
		}
	}

	sort.Slice(common, func(i, j int) bool {
		return common[i].Name < common[j].Name
	})

	return common
}

func (r *ProtocolRegistry) EnableProtocol(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name = strings.ToLower(name)
	proto, ok := r.protocols[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrProtocolNotSupported, name)
	}

	proto.Enabled = true
	return nil
}

func (r *ProtocolRegistry) DisableProtocol(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name = strings.ToLower(name)
	proto, ok := r.protocols[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrProtocolNotSupported, name)
	}

	proto.Enabled = false
	return nil
}

func (r *ProtocolRegistry) IsProtocolEnabled(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	proto, ok := r.protocols[strings.ToLower(name)]
	return ok && proto.Enabled
}

func (r *ProtocolRegistry) ProtocolCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.protocols)
}

func (r *ProtocolRegistry) EnabledProtocolCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, p := range r.protocols {
		if p.Enabled {
			count++
		}
	}
	return count
}

func (r *ProtocolRegistry) GetMessageProtocol(msgType uint8) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.msgRoutes[msgType]
}

func (r *ProtocolRegistry) IsMessageSupported(msgType uint8) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.msgRoutes[msgType]
	return ok
}
