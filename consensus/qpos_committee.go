// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"github.com/quantaureum/qau/types"
)

func (q *QPOS) GetCommitteeForSlot(slot uint64) ([]*Validator, error) {
	// R37-P3-25 FIX (2026-07-31): Capture q.validators under read lock to
	// prevent TOCTOU race with updateValidatorSet. Previously the first
	// access was unlocked, so a concurrent validator set update could swap
	// the pointer between the nil check and the Size() call, causing
	// inconsistent reads or nil-pointer dereference.
	q.mu.RLock()
	vs := q.validators
	if vs == nil || vs.Size() == 0 {
		q.mu.RUnlock()
		return nil, ErrNotInCommittee
	}

	n := vs.ValidatorCount()
	if n == 0 {
		q.mu.RUnlock()
		return nil, ErrNotInCommittee
	}

	if n <= int(SlotsPerEpoch) {
		result := vs.Validators()
		q.mu.RUnlock()
		return result, nil
	}

	if cached, ok := q.committeeCache[slot]; ok {
		q.mu.RUnlock()
		result := make([]*Validator, len(cached))
		copy(result, cached)
		return result, nil
	}
	q.mu.RUnlock()

	epoch := SlotToEpoch(slot)
	slotInEpoch := slot % SlotsPerEpoch

	q.mu.Lock()
	shuffled := q.shuffleCache[epoch]
	if shuffled == nil {
		var coldStart bool
		shuffled, coldStart = q.computeDeterministicShuffleForEpoch(epoch, n)
		q.shuffleCache[epoch] = shuffled
		q.evictStaleShuffleCacheLocked()
		// R88-B: mark cold-start epochs under the write lock (the compute
		// function no longer writes coldStartEpochs itself — see its doc
		// comment for the data-race rationale).
		if coldStart {
			q.coldStartEpochs[epoch] = struct{}{}
		}
	}
	shuffledCopy := make([]int, len(shuffled))
	copy(shuffledCopy, shuffled)
	// R103-COMMITTEE-PARTITION: capture the cutover while we hold the lock
	// (the partition branch below runs lock-free on the copied shuffle).
	partitionCutover := q.weightedProposerCutover
	q.mu.Unlock()

	if len(shuffledCopy) == 0 {
		q.mu.RLock()
		result := vs.Validators()
		q.mu.RUnlock()
		return result, nil
	}

	// R103-COMMITTEE-PARTITION (2026-08-30): replace capacity-capped PER-SLOT
	// SAMPLING with an epoch-wide PARTITION when the validator set exceeds
	// the BFT floor and the weighted-consensus cutover is active.
	// Why: sampling caps distinct attesters per epoch at 4096 while the
	// finality numerator divides weight by TOTAL stake — at n>6144 the 2/3
	// supermajority is mathematically unreachable (measured: 20.5% at
	// n=20000) and finality becomes impossible by construction. Ethereum
	// partitions shuffled indices across slots*committees so every validator
	// attests exactly once per epoch; we adopt that here (design doc §R103).
	// Guard: n<=32 returns the full set above; 33..96 would slice below the
	// BFT floor of 3 — legacy sampling is kept for that range. Gated on the
	// same cutover as R102 so mainnet behavior is unchanged until flip.
	var committee []*Validator
	if epoch >= partitionCutover && n > int(SlotsPerEpoch)*3 {
		committee = r103SlotCommittee(vs, shuffledCopy, n, slotInEpoch)
	} else {
		committee = legacySampledCommittee(vs, shuffledCopy, n, slotInEpoch)
	}

	if len(committee) == 0 {
		q.mu.RLock()
		result := vs.Validators()
		q.mu.RUnlock()
		return result, nil
	}

	q.mu.Lock()
	// R38-P1-10 FIX (2026-08-01): Guard with pointer-equality check so we
	// don't cache a committee computed for a validator set that has since
	// been replaced by updateValidatorSet / AddStakingValidator (which clear
	// the cache). Without this guard, a concurrent validator set swap could
	// leave a committee computed from the OLD validator set pinned in the
	// cache after the swap, causing GetCommitteeForSlot to return stale
	// membership on subsequent calls until the slot is evicted by TTL.
	// Mirrors the pointer-equality guard in qpos_proposer.go:225-237.
	if q.validators == vs {
		q.committeeCache[slot] = committee
		q.evictStaleCommitteeCacheLocked()
	}
	q.mu.Unlock()

	result := make([]*Validator, len(committee))
	copy(result, committee)
	return result, nil
}

// legacySampledCommittee is the pre-R103 per-slot sampling path, extracted
// verbatim (behavior preserved): a capacity-capped, overlapping window of
// the epoch shuffle per slot.
func legacySampledCommittee(vs *ValidatorSet, shuffledCopy []int, n int, slotInEpoch uint64) []*Validator {
	committeeSize := TargetCommitteeSize
	if committeeSize > n {
		committeeSize = n
	}

	validatorsPerCommittee := n / int(SlotsPerEpoch)
	if validatorsPerCommittee < 1 {
		validatorsPerCommittee = 1
	}
	// CS-03 FIX (R45): Enforce BFT-safe minimum committee size of 3.
	// A committee of 1 has no Byzantine fault tolerance. With n > SlotsPerEpoch,
	// n/SlotsPerEpoch can round down to 1 (e.g. n=33, SlotsPerEpoch=32 → 1).
	// Floor at 3 to ensure at least 2-of-3 threshold for safety.
	if validatorsPerCommittee < 3 {
		validatorsPerCommittee = 3
	}
	if validatorsPerCommittee > committeeSize {
		validatorsPerCommittee = committeeSize
	}

	startIdx := (int(slotInEpoch) * validatorsPerCommittee) % len(shuffledCopy) // #nosec G115

	committee := make([]*Validator, 0, validatorsPerCommittee)
	for i := 0; i < validatorsPerCommittee; i++ {
		idx := shuffledCopy[(startIdx+i)%len(shuffledCopy)]
		if idx >= 0 && idx < n {
			v := vs.GetValidatorByIndex(idx)
			if v != nil {
				committee = append(committee, v)
			}
		}
	}

	if len(committee) == 0 {
		return nil
	}
	return committee
}

// r103SlotCommittee returns the committee for a slot as the union of the
// epoch's PARTITION slices assigned to that slot:
//
//	committeesPerSlot = ceil(n / (SlotsPerEpoch * TargetCommitteeSize))  (>=1)
//	total slices = committeesPerSlot * SlotsPerEpoch     (partition of n)
//	slice sizes  = n/total (+1 for the first n%total slices)
//	slot s       = union of slices [s*committeesPerSlot, (s+1)*committeesPerSlot)
//
// Every validator index in the epoch shuffle appears in EXACTLY ONE slice →
// every validator attests exactly once per epoch → attestedWeight/total can
// reach ~100% at any n (finality solvable beyond n=6144).
func r103SlotCommittee(vs *ValidatorSet, shuffledCopy []int, n int, slotInEpoch uint64) []*Validator {
	span := int(SlotsPerEpoch) * TargetCommitteeSize // 32*128 = 4096
	committeesPerSlot := (n + span - 1) / span
	total := committeesPerSlot * int(SlotsPerEpoch)
	base := n / total
	rem := n % total // first `rem` slices get base+1 members

	first := int(slotInEpoch) * committeesPerSlot
	committee := make([]*Validator, 0, (base+1)*committeesPerSlot)
	off := 0 // running start offset of slice i in the shuffle
	for i := 0; i < first+committeesPerSlot; i++ {
		sz := base
		if i < rem {
			sz++
		}
		start := off
		off += sz
		if i < first {
			continue
		}
		for j := start; j < start+sz && j < len(shuffledCopy); j++ {
			idx := shuffledCopy[j]
			if idx >= 0 && idx < n {
				if v := vs.GetValidatorByIndex(idx); v != nil {
					committee = append(committee, v)
				}
			}
		}
	}
	return committee
}

func (q *QPOS) evictStaleCommitteeCacheLocked() {
	if len(q.committeeCache) <= MaxCommitteeCacheSize {
		return
	}
	currentSlot := q.currentSlot
	for s := range q.committeeCache {
		if s+uint64(MaxCommitteeCacheSize) <= currentSlot {
			delete(q.committeeCache, s)
		}
	}
	if len(q.committeeCache) > MaxCommitteeCacheSize*2 {
		var oldestSlot uint64 = ^uint64(0)
		for s := range q.committeeCache {
			if s < oldestSlot {
				oldestSlot = s
			}
		}
		if oldestSlot != ^uint64(0) {
			delete(q.committeeCache, oldestSlot)
		}
	}
}

func (q *QPOS) IsInCommittee(slot uint64, validatorAddr types.Address) bool {
	// R37-P3-25 FIX (2026-07-31): Capture q.validators under read lock to
	// prevent TOCTOU race with updateValidatorSet, matching the fix in
	// GetCommitteeForSlot. Previously the first access was unlocked, so a
	// concurrent validator set update could swap the pointer between the nil
	// check and the Size() call.
	q.mu.RLock()
	vs := q.validators
	if vs == nil || vs.Size() == 0 {
		q.mu.RUnlock()
		return false
	}

	n := vs.ValidatorCount()

	if n <= int(SlotsPerEpoch) {
		idx := vs.GetValidatorIndex(validatorAddr)
		q.mu.RUnlock()
		return idx >= 0
	}
	q.mu.RUnlock()

	committee, err := q.GetCommitteeForSlot(slot)
	if err != nil {
		return false
	}

	for _, v := range committee {
		if v.Address == validatorAddr {
			return true
		}
	}
	return false
}

func (q *QPOS) isInCommitteeLocked(slot uint64, validatorAddr types.Address) bool {
	n := q.validators.ValidatorCount()

	if n <= int(SlotsPerEpoch) {
		idx := q.validators.GetValidatorIndex(validatorAddr)
		return idx >= 0
	}

	committee, err := q.getCommitteeForSlotLocked(slot)
	if err != nil {
		return false
	}

	for _, v := range committee {
		if v.Address == validatorAddr {
			return true
		}
	}
	return false
}

func (q *QPOS) getCommitteeForSlotLocked(slot uint64) ([]*Validator, error) {
	n := q.validators.ValidatorCount()
	if n == 0 {
		return nil, ErrNotInCommittee
	}

	if n <= int(SlotsPerEpoch) {
		return q.validators.Validators(), nil
	}

	epoch := SlotToEpoch(slot)
	slotInEpoch := slot % SlotsPerEpoch

	shuffled := q.shuffleCache[epoch]
	if shuffled == nil {
		var coldStart bool
		shuffled, coldStart = q.computeDeterministicShuffleForEpoch(epoch, n)
		q.shuffleCache[epoch] = shuffled

		q.evictStaleShuffleCacheLocked()
		// R88-B: mark cold-start epochs under the caller's write lock.
		if coldStart {
			q.coldStartEpochs[epoch] = struct{}{}
		}
	}

	if len(shuffled) == 0 {
		return q.validators.Validators(), nil
	}

	// R103-COMMITTEE-PARTITION: locked variant must agree BYTE-FOR-BYTE with
	// GetCommitteeForSlot (it gates ProcessAttestation / block_producer's own
	// attestation creation). Same cutover gate, same partition function.
	if epoch >= q.weightedProposerCutover && n > int(SlotsPerEpoch)*3 {
		shuffledCopy := make([]int, len(shuffled))
		copy(shuffledCopy, shuffled)
		return r103SlotCommittee(q.validators, shuffledCopy, n, slotInEpoch), nil
	}

	committeeSize := TargetCommitteeSize
	if committeeSize > n {
		committeeSize = n
	}

	validatorsPerCommittee := n / int(SlotsPerEpoch)
	if validatorsPerCommittee < 1 {
		validatorsPerCommittee = 1
	}
	// AUDIT (2026) GOV-02: Enforce BFT-safe minimum committee size of 3,
	// matching the non-locked GetCommitteeForSlot. A committee of 1 has no
	// Byzantine fault tolerance. With n > SlotsPerEpoch, n/SlotsPerEpoch can
	// round down to 1 (e.g. n=33, SlotsPerEpoch=32 → 1). Floor at 3 to ensure
	// at least 2-of-3 threshold for safety.
	if validatorsPerCommittee < 3 {
		validatorsPerCommittee = 3
	}
	if validatorsPerCommittee > committeeSize {
		validatorsPerCommittee = committeeSize
	}

	startIdx := (int(slotInEpoch) * validatorsPerCommittee) % len(shuffled) // #nosec G115

	committee := make([]*Validator, 0, validatorsPerCommittee)
	for i := 0; i < validatorsPerCommittee; i++ {
		idx := shuffled[(startIdx+i)%len(shuffled)]
		if idx >= 0 && idx < n {
			v := q.validators.GetValidatorByIndex(idx)
			if v != nil {
				committee = append(committee, v)
			}
		}
	}

	if len(committee) == 0 {
		return q.validators.Validators(), nil
	}

	return committee, nil
}
