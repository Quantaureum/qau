// Quantaureum Node source, version 1.0.0.
package miner

import (
	"fmt"
	"sync"

	"github.com/quantaureum/qau/types"
)

var (
	ErrBuilderNotRegistered = fmt.Errorf("builder not registered")
	ErrBuilderAlreadyExists = fmt.Errorf("builder already registered")
	ErrBuilderSuspended     = fmt.Errorf("builder is suspended")
	// L6-021: builder signature proof is missing or invalid
	ErrBuilderSigInvalid = fmt.Errorf("builder signature proof invalid")
)

type BuilderStatus int

const (
	BuilderActive BuilderStatus = iota
	BuilderSuspended
	BuilderRevoked
)

type BuilderInfo struct {
	Address    types.Address
	PublicKey  []byte
	Status     BuilderStatus
	Registered int64
	Updated    int64
}

type BuilderRegistry struct {
	mu       sync.RWMutex
	builders map[types.Address]*BuilderInfo
	verifier SignatureVerifier
}

func NewBuilderRegistry(verifier SignatureVerifier) *BuilderRegistry {
	return &BuilderRegistry{
		builders: make(map[types.Address]*BuilderInfo),
		verifier: verifier,
	}
}

// RegisterBuilder registers a builder without verifying private key ownership.
//
// L6-021 SECURITY WARNING: This method does NOT verify that the caller actually
// possesses the private key corresponding to pubKey. Anyone could register an
// arbitrary address with someone else's public key. In production, use
// RegisterBuilderWithProof instead, which requires a signature proof proving
// private key ownership. This method is retained for backwards compatibility and
// testing only.
func (r *BuilderRegistry) RegisterBuilder(addr types.Address, pubKey []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.builders[addr]; exists {
		return ErrBuilderAlreadyExists
	}

	r.builders[addr] = &BuilderInfo{
		Address:   addr,
		PublicKey: pubKey,
		Status:    BuilderActive,
	}

	return nil
}

// RegisterBuilderWithProof registers a builder after verifying that the caller
// possesses the private key corresponding to pubKey. The signature must be over
// a challenge message (e.g. the builder address) to prove key ownership.
// L6-021 SECURITY FIX: prevents registering someone else's public key.
func (r *BuilderRegistry) RegisterBuilderWithProof(addr types.Address, pubKey []byte, challenge, signature []byte) error {
	if r.verifier == nil {
		return fmt.Errorf("no signature verifier configured")
	}
	if len(pubKey) == 0 {
		return fmt.Errorf("public key is empty")
	}
	if len(signature) == 0 {
		return ErrBuilderSigInvalid
	}
	if err := r.verifier.Verify(pubKey, challenge, signature); err != nil {
		return fmt.Errorf("%w: %v", ErrBuilderSigInvalid, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.builders[addr]; exists {
		return ErrBuilderAlreadyExists
	}

	r.builders[addr] = &BuilderInfo{
		Address:   addr,
		PublicKey: pubKey,
		Status:    BuilderActive,
	}

	return nil
}

func (r *BuilderRegistry) UnregisterBuilder(addr types.Address) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.builders[addr]; !exists {
		return ErrBuilderNotRegistered
	}

	delete(r.builders, addr)
	return nil
}

func (r *BuilderRegistry) SuspendBuilder(addr types.Address) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	info, exists := r.builders[addr]
	if !exists {
		return ErrBuilderNotRegistered
	}

	info.Status = BuilderSuspended
	return nil
}

func (r *BuilderRegistry) RevokeBuilder(addr types.Address) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	info, exists := r.builders[addr]
	if !exists {
		return ErrBuilderNotRegistered
	}

	info.Status = BuilderRevoked
	return nil
}

func (r *BuilderRegistry) IsRegistered(addr types.Address) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, exists := r.builders[addr]
	return exists && info.Status == BuilderActive
}

func (r *BuilderRegistry) GetBuilder(addr types.Address) (*BuilderInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, exists := r.builders[addr]
	if !exists {
		return nil, ErrBuilderNotRegistered
	}

	// R11-MIN-002 FIX: Return a copy to prevent callers from mutating internal state.
	cp := *info
	return &cp, nil
}

func (r *BuilderRegistry) VerifyBid(bid *BuilderBid) error {
	r.mu.RLock()
	info, exists := r.builders[bid.BuilderAddress]
	// R11-MIN-002 FIX: Copy needed fields under lock to prevent TOCTOU.
	var status BuilderStatus
	var publicKey []byte
	if exists {
		status = info.Status
		publicKey = make([]byte, len(info.PublicKey))
		copy(publicKey, info.PublicKey)
	}
	r.mu.RUnlock()

	if !exists {
		return ErrBuilderNotRegistered
	}

	if status != BuilderActive {
		if status == BuilderSuspended {
			return ErrBuilderSuspended
		}
		return ErrBuilderNotRegistered
	}

	if r.verifier == nil {
		return fmt.Errorf("signature verifier not configured")
	}

	return bid.VerifySignature(r.verifier, publicKey)
}

func (r *BuilderRegistry) ListBuilders() []*BuilderInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*BuilderInfo, 0, len(r.builders))
	for _, info := range r.builders {
		// R11-MIN-002 FIX: Return copies to prevent callers from mutating internal state.
		cp := *info
		result = append(result, &cp)
	}
	return result
}

func (r *BuilderRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.builders)
}
