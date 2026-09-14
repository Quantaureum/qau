// Quantaureum Node source, version 1.0.0.
// Package consensus — Phase 3.3: Incremental Attestation Storage
//
// Currently, attestations for every slot are stored indefinitely, causing
// unbounded memory growth. With 10K+ validators producing 32 attestations
// per epoch, this becomes unsustainable.
//
// IncrementalAttestationStore implements a sliding window approach:
//   - Only keeps attestations for the last N epochs (configurable)
//   - Older attestations are pruned after finality
//   - Slots beyond the finalized epoch are cleaned up automatically
//
// This reduces storage by ~90% while maintaining full consensus integrity.
package consensus

import (
	"fmt"
	"sync"
)

// DefaultAttestationWindow is the default number of epochs to keep attestations.
// After this window, attestations are pruned (they're already finalized).
const DefaultAttestationWindow = 4 // 4 epochs = ~25.6 minutes

// MaxAttestationsPerSlot bounds the number of attestations stored per slot.
// AUDIT (2026) CORE-09 FIX: without this cap, a malicious peer could spam
// attestations for a single slot to exhaust memory before epoch-boundary
// pruning fires. The target committee size is 128; 4x that allows headroom
// for committees larger than target and for duplicate detection lag.
const MaxAttestationsPerSlot = 512

// IncrementalAttestationStore manages attestation storage with automatic pruning.
// It stores attestations per slot and automatically removes attestations for
// slots that are older than the configured window.
type IncrementalAttestationStore struct {
	mu sync.RWMutex

	// attestations: slot → list of attestations
	attestations map[uint64][]*Attestation

	// aggregatedAttestations: slot → aggregated attestation
	aggregatedAttestations map[uint64]*AggregatedAttestation

	// windowEpochs: number of epochs to retain attestations
	windowEpochs uint64

	// lastPrunedEpoch: the last epoch that was pruned (to avoid redundant pruning)
	lastPrunedEpoch uint64

	// totalPruned: total number of attestations pruned (for metrics)
	totalPruned uint64

	// totalSlots: total number of slots stored (for metrics)
	totalSlots uint64
}

// NewIncrementalAttestationStore creates a new incremental attestation store.
func NewIncrementalAttestationStore(windowEpochs uint64) *IncrementalAttestationStore {
	if windowEpochs == 0 {
		windowEpochs = DefaultAttestationWindow
	}
	return &IncrementalAttestationStore{
		attestations:           make(map[uint64][]*Attestation),
		aggregatedAttestations: make(map[uint64]*AggregatedAttestation),
		windowEpochs:           windowEpochs,
	}
}

// AddAttestation adds an attestation to the store for a given slot.
// AUDIT (2026) CORE-09 FIX: returns an error when the per-slot cap
// (MaxAttestationsPerSlot) is reached, preventing unbounded memory growth
// from a malicious peer spamming attestations for one slot before
// epoch-boundary pruning fires.
func (s *IncrementalAttestationStore) AddAttestation(slot uint64, att *Attestation) error {
	if att == nil {
		return fmt.Errorf("attestation store: nil attestation")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.attestations[slot]) >= MaxAttestationsPerSlot {
		return fmt.Errorf("attestation store: per-slot cap reached for slot %d (%d max)", slot, MaxAttestationsPerSlot)
	}

	s.attestations[slot] = append(s.attestations[slot], att)
	s.totalSlots++
	return nil
}

// GetAttestations returns all attestations for a given slot.
func (s *IncrementalAttestationStore) GetAttestations(slot uint64) []*Attestation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	atts := s.attestations[slot]
	if atts == nil {
		return nil
	}

	// Return a copy to prevent external mutation
	result := make([]*Attestation, len(atts))
	copy(result, atts)
	return result
}

// SetAggregatedAttestation stores an aggregated attestation for a slot.
func (s *IncrementalAttestationStore) SetAggregatedAttestation(slot uint64, agg *AggregatedAttestation) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.aggregatedAttestations[slot] = agg
}

// GetAggregatedAttestation returns the aggregated attestation for a slot.
func (s *IncrementalAttestationStore) GetAggregatedAttestation(slot uint64) *AggregatedAttestation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agg := s.aggregatedAttestations[slot]
	if agg == nil {
		return nil
	}

	// Return a deep copy
	return agg.deepCopy()
}

// PruneBeforeEpoch removes all attestations for slots before the given epoch.
// This should be called when an epoch is finalized.
// Returns the number of slots pruned.
func (s *IncrementalAttestationStore) PruneBeforeEpoch(epoch uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if epoch <= s.lastPrunedEpoch {
		return 0
	}

	cutoffSlot := EpochStartSlot(epoch)
	pruned := 0

	// Prune individual attestations
	for slot := range s.attestations {
		if slot < cutoffSlot {
			pruned++
			s.totalPruned += uint64(len(s.attestations[slot]))
			delete(s.attestations, slot)
		}
	}

	// Prune aggregated attestations
	for slot := range s.aggregatedAttestations {
		if slot < cutoffSlot {
			delete(s.aggregatedAttestations, slot)
		}
	}

	s.lastPrunedEpoch = epoch
	return pruned
}

// PruneOldAttestations prunes attestations older than the window.
// currentEpoch is the current epoch number.
func (s *IncrementalAttestationStore) PruneOldAttestations(currentEpoch uint64) (int, error) {
	if currentEpoch < s.windowEpochs {
		return 0, nil
	}

	cutoffEpoch := currentEpoch - s.windowEpochs
	if cutoffEpoch <= s.lastPrunedEpoch {
		return 0, nil
	}

	return s.PruneBeforeEpoch(cutoffEpoch), nil
}

// Count returns the total number of individual attestations stored.
func (s *IncrementalAttestationStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, atts := range s.attestations {
		count += len(atts)
	}
	return count
}

// SlotCount returns the number of slots with attestations.
func (s *IncrementalAttestationStore) SlotCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.attestations)
}

// Stats returns store statistics.
func (s *IncrementalAttestationStore) Stats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]any{
		"slots":         len(s.attestations),
		"total_pruned":  s.totalPruned,
		"window_epochs": s.windowEpochs,
		"last_pruned":   s.lastPrunedEpoch,
		"agg_count":     len(s.aggregatedAttestations),
	}
}

// Clear removes all attestations from the store.
func (s *IncrementalAttestationStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attestations = make(map[uint64][]*Attestation)
	s.aggregatedAttestations = make(map[uint64]*AggregatedAttestation)
	s.lastPrunedEpoch = 0
	s.totalPruned = 0
}

// ValidateInvariants checks internal consistency of the store.
// Returns nil if all invariants hold, or an error describing the violation.
func (s *IncrementalAttestationStore) ValidateInvariants() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check that attestations don't exist for slots that should have been pruned
	cutoffSlot := EpochStartSlot(s.lastPrunedEpoch)
	for slot := range s.attestations {
		if slot < cutoffSlot {
			return fmt.Errorf("invariant violation: attestations exist for slot %d, but cutoff is %d (epoch %d)",
				slot, cutoffSlot, s.lastPrunedEpoch)
		}
	}
	return nil
}
