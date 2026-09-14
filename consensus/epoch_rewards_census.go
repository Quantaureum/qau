// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
)

// ============================================================================
// ON-CHAIN ANCHORED REWARD PROOF (epoch reward census)
// ============================================================================
//
// ROOT-CAUSE FIX for chain forks caused by PATH-DEPENDENT epoch rewards:
//
// ProcessEpochRewards rewards validators based on attestations collected over
// P2P gossip (q.attestations). Different nodes receive DIFFERENT attestation
// sets, so they compute different rewards → different state roots → forks.
//
// The fix anchors the reward computation to an ON-CHAIN census: the epoch
// boundary block header carries the complete attestation set of the previous
// epoch. Every node (proposer AND syncers) derives rewards from that single
// chain-embedded census, so the result is identical everywhere.
//
// The shared core below (computeEpochRewardsUnlocked) is used by BOTH:
//   - ProcessEpochRewards ........ propagates q.attestations (local, legacy)
//   - ComputeEpochRewardsFromCensus ... propagates the on-chain census
//
// Any change to the reward formula MUST be made here so both paths stay in
// lockstep and can never diverge again.

// computeEpochRewardsUnlocked computes epoch rewards and penalties from an
// abstract attestation source. It is the single source of truth for the
// reward formula. MUST be called with q.mu held. It neither caches nor prunes;
// the caller handles caching (and ProcessEpochRewards handles pruning).
//
// ETHEREUM-ALIGNED PROPOSER DETERMINISM (R59-CENSUS-PROP, 2026-08-09):
// propSource returns the COMMITTED proposer index for a slot (read from the
// on-chain epoch census carried in the block header) — the direct analog of
// Ethereum's block.proposer_index field. When propSource is non-nil the
// reward formula credits the proposer index from the census and NEVER
// re-derives it from node-local state (q.epochVRFAccumulator + local shuffle).
// This makes proposer rewards a pure function of the on-chain census, so every
// node reproduces the identical map regardless of its local sync history —
// eliminating the last path-dependent input to epoch reward computation.
//
// When propSource is nil (legacy ProcessEpochRewards, local P2P attestations),
// the formula falls back to the local derivation for backward compatibility.
func (q *QPOS) computeEpochRewardsUnlocked(epoch uint64, attSource func(slot uint64) []*Attestation, propSource func(slot uint64) int) *EpochRewards {
	rewards := &EpochRewards{
		Epoch:              epoch,
		ProposerRewards:    make(map[int]*big.Int),
		AttesterRewards:    make(map[int]*big.Int),
		Penalties:          make(map[int]*big.Int),
		SlashingPenalties:  make(map[int]*big.Int),
		TotalRewards:       big.NewInt(0),
		TotalPenalties:     big.NewInt(0),
		ParticipatingStake: big.NewInt(0),
		TotalStake:         big.NewInt(0),
	}

	validators := q.validators.Validators()
	startSlot := EpochStartSlot(epoch)
	endSlot := startSlot + SlotsPerEpoch - 1

	// Calculate total stake
	// FIX: exclude slashed validators from totalStake. Slashed
	// validators have already had their stake reduced/penalized; including
	// them here would inflate the total stake baseline used for reward
	// calculations.
	for i, v := range validators {
		if v.Active {
			if _, slashed := q.slashedValidators[i]; slashed {
				continue
			}
			rewards.TotalStake.Add(rewards.TotalStake, v.Stake)
		}
	}

	// Track which validators participated.
	//  NOTE: This uses int indices into the validators slice rather than
	// addresses. This is safe as long as the validator set is immutable within
	// an epoch (validators are not removed mid-epoch). If validator removal
	// mid-epoch is ever introduced, indices would shift and this tracking would
	// break — switch to address-based keys at that point.
	participated := make(map[int]bool)

	// CONS- (R8 2026-07-19 FIX): Track which validators have already
	// received their attester reward this epoch. ProcessAttestation already
	// rejects duplicate attestations for the SAME slot, but nothing prevents
	// a single validator from appearing in multiple slots within one epoch
	// (e.g. via a committee-assignment bug or an attacker bypassing
	// isInCommitteeLocked). Without this dedup, every additional
	// attestation for the same validator grants another baseReward —
	// allowing a malicious validator to mint unbounded QAU and break the
	// emission schedule. We pay the attester reward exactly once per
	// validator per epoch, matching the design assumption "each validator
	// attests exactly once per epoch".
	rewarded := make(map[int]bool)

	// EM-2: the proposer pool accrues ProposerWeight/WeightDenominator of every
	// attesting validator's base reward and is distributed across the epoch's
	// actually-proposed slots after the attestation loop. Accumulating first and
	// distributing second is what makes total issuance independent of both the
	// validator count and the number of proposed slots.
	proposerPool := big.NewInt(0)

	// Process attestations in this epoch
	for slot := startSlot; slot <= endSlot; slot++ {
		for _, att := range attSource(slot) {
			// audit-fix  count participating stake only once per validator
			// to avoid inflating the metric when a validator attests in multiple slots.
			if !participated[att.ValidatorIndex] {
				participated[att.ValidatorIndex] = true
				if att.ValidatorIndex < len(validators) {
					rewards.ParticipatingStake.Add(
						rewards.ParticipatingStake, validators[att.ValidatorIndex].Stake)
				}
			}

			// CONS-FIX: skip reward for validators already rewarded
			// this epoch. Also skip slashed validators — they must not
			// receive any reward for the epoch in which they were slashed
			// (the slash penalty already reduced their stake).
			if rewarded[att.ValidatorIndex] {
				continue
			}
			if _, slashed := q.slashedValidators[att.ValidatorIndex]; slashed {
				rewarded[att.ValidatorIndex] = true // mark to avoid re-checking
				continue
			}
			rewarded[att.ValidatorIndex] = true

			// EM-2 attester reward: Altair weight split. The validator keeps
			// (WeightDenominator-ProposerWeight)/WeightDenominator = 56/64 of its
			// base reward and contributes ProposerWeight/WeightDenominator = 8/64
			// to the epoch's proposer pool, distributed after this loop.
			//
			// Both truncations are exact: base rewards are gwei-granular and 64
			// divides 1e9, so attesterShare + proposerContribution == baseReward
			// with no dust. economics/model.EpochIssuanceAttributed computes the
			// same decomposition and the parity test pins the two together.
			//
			// Before EM-2 the attester received the FULL base reward and the
			// proposer separately received one full base reward per proposed slot,
			// which coupled total issuance to the validator count and handed
			// proposers 32/(N+32) of everything (84.2% at N=6).
			baseReward := q.calculateBaseRewardUnlocked(att.ValidatorIndex)
			attesterShare := new(big.Int).Mul(baseReward, big.NewInt(WeightDenominator-ProposerWeight))
			attesterShare.Div(attesterShare, big.NewInt(WeightDenominator))
			proposerContribution := new(big.Int).Mul(baseReward, big.NewInt(ProposerWeight))
			proposerContribution.Div(proposerContribution, big.NewInt(WeightDenominator))

			if rewards.AttesterRewards[att.ValidatorIndex] == nil {
				rewards.AttesterRewards[att.ValidatorIndex] = big.NewInt(0)
			}
			rewards.AttesterRewards[att.ValidatorIndex].Add(
				rewards.AttesterRewards[att.ValidatorIndex], attesterShare)
			rewards.TotalRewards.Add(rewards.TotalRewards, attesterShare)
			proposerPool.Add(proposerPool, proposerContribution)
		}
	}

	// Calculate penalties for non-participating validators
	for i, v := range validators {
		if !v.Active {
			continue
		}

		if !participated[i] {
			// P3-CONS-001 NOTE (R30, 2026-07-27): Inactivity penalty — economic layer.
			//
			// This 2x baseReward penalty is the ECONOMIC incentive-layer penalty
			// for non-participation in a single epoch. It is intentionally
			// smaller and softer than SlashingManager's DowntimePenalty (1% of
			// stake, see slashing.go DowntimeSlashPercent) because they serve
			// different purposes:
			//
			//   - ProcessEpochRewards inactivity penalty (here): per-epoch
			//     opportunity-cost + small ding (2x baseReward) to discourage
			//     occasional missed attestations. Applied every epoch a
			//     validator is inactive but still Active.
			//   - SlashingManager downtime penalty (slashing.go): consensus-layer
			//     SLASH triggered ONLY after DowntimeThreshold consecutive
			//     missed blocks (DefaultDowntimeThreshold=100). Reduces stake
			//     by 1% AND jails the validator for DefaultJailDuration (1h).
			//
			// Design decision: the two penalties are NOT unified because they
			// operate on different triggers and at different severities. A
			// validator missing one epoch should NOT be slashed 1%+jailed —
			// that would be disproportionate. The economic penalty accumulates
			// gently; only sustained downtime (≥ threshold blocks) escalates
			// to a consensus slash. See SLASH-H2 test for the penalty-tier
			// invariant (DowntimePenalty=10x InactivityPenalty).
			baseReward := q.calculateBaseRewardUnlocked(i)
			penalty := new(big.Int).Mul(baseReward, big.NewInt(2)) // 2x base reward as penalty

			rewards.Penalties[i] = penalty
			rewards.TotalPenalties.Add(rewards.TotalPenalties, penalty)
		}
	}

	// EM-2 proposer rewards: distribute the accumulated proposer pool across the
	// slots that were actually proposed AND attested, instead of minting one full
	// base reward per such slot.
	//
	// Why the two-pass shape: the pool is a fixed fraction (8/64) of total
	// issuance, so it must be known in full before any of it is credited.
	// Crediting per slot as we go — the pre-EM-2 behavior — makes issuance a
	// function of how many slots happened to be proposed, which is exactly the
	// coupling EM-2 removes.
	//
	// A proposer that produced several slots in the epoch receives a
	// proportional multiple, so proposing more is still worth more.
	//
	// Slashed / inactive proposers are excluded — getProposerIndexForSlotUnlocked
	// already skips them and returns the first eligible alternative, but we
	// double-check before crediting to defend against edge cases (e.g. a
	// validator slashed mid-epoch after being scheduled).
	//
	// R59-CENSUS-PROP is preserved: the credited proposer comes from the
	// on-chain census (propSource) and is never re-derived from node-local
	// state, so every node computes the identical map.
	creditedSlots := make([]int, 0, SlotsPerEpoch)
	for slot := startSlot; slot <= endSlot; slot++ {
		// Skip slots with no attestations: block was either not proposed
		// or not attested → no proposer reward for that slot.
		if len(attSource(slot)) == 0 {
			continue
		}
		proposerIdx := -1
		if propSource != nil {
			proposerIdx = propSource(slot)
		}
		if proposerIdx < 0 {
			proposerIdx = q.getProposerIndexForSlotUnlocked(slot, q.validators)
		}
		if proposerIdx < 0 || proposerIdx >= len(validators) {
			continue
		}
		if _, slashed := q.slashedValidators[proposerIdx]; slashed {
			continue
		}
		if !validators[proposerIdx].Active {
			continue
		}
		creditedSlots = append(creditedSlots, proposerIdx)
	}

	// With no proposed-and-attested slot in the epoch the pool is NOT issued.
	// That is deliberate and consistent with the attester side: unearned
	// issuance is never created rather than being rolled forward or handed to
	// an arbitrary validator.
	if len(creditedSlots) > 0 && proposerPool.Sign() > 0 {
		numSlots := big.NewInt(int64(len(creditedSlots)))
		perSlot := new(big.Int).Div(proposerPool, numSlots)
		// Integer division leaves at most len(creditedSlots)-1 wei unassigned.
		// Give the remainder to the earliest credited slot so the pool is
		// distributed exactly and deterministically — dropping it would make
		// total issuance depend on the slot count again, in the last digit.
		remainder := new(big.Int).Sub(proposerPool, new(big.Int).Mul(perSlot, numSlots))

		for i, proposerIdx := range creditedSlots {
			amount := new(big.Int).Set(perSlot)
			if i == 0 {
				amount.Add(amount, remainder)
			}
			if amount.Sign() <= 0 {
				continue
			}
			if rewards.ProposerRewards[proposerIdx] == nil {
				rewards.ProposerRewards[proposerIdx] = big.NewInt(0)
			}
			rewards.ProposerRewards[proposerIdx].Add(
				rewards.ProposerRewards[proposerIdx], amount)
			rewards.TotalRewards.Add(rewards.TotalRewards, amount)
		}
	}

	// Process slashing penalties
	// CONS- slashedValidators is now map[int]*SlashedEntry.
	for validatorIdx, entry := range q.slashedValidators {
		if entry == nil {
			continue
		}
		if entry.Epoch == epoch {
			if validatorIdx < len(validators) {
				// FIX: All validators in q.slashedValidators were already
				// processed by SlashValidator (ReduceStake + DeactivateValidator)
				// or SlashingManager.slash() (SlashStake + SetActive), both of
				// which reduced the stake at slash time. Applying another 1/32
				// penalty here would double-charge the validator.
				//
				// The previous C21-002 fix only skipped validators with Active=false,
				// but SetActive can fail (error logged, non-fatal), leaving the
				// validator Active with already-reduced stake. Since being in
				// q.slashedValidators guarantees the stake was already reduced,
				// skip ALL slashed validators regardless of Active status.
				if validators[validatorIdx].Active {
					// The validator was slashed (stake reduced) but is still Active.
					// This indicates SetActive may have failed during slash().
					// Log for investigation — the validator should have been
					// deactivated but was not.
					qposAdvLogger.Warnf("validator %d slashed in epoch %d but still Active; stake already reduced by slash, skipping epoch penalty to avoid double-charge", validatorIdx, epoch)
				}
				continue
			}
		}
	}

	return rewards
}

// ComputeEpochRewardsFromCensus computes epoch rewards DETERMINISTICALLY from
// an on-chain attestation census carried in the epoch-boundary block header.
// This eliminates the path-dependence of locally P2P-collected attestations so
// that every node derives an IDENTICAL reward set and identical state root.
//
// ETHEREUM-ALIGNED (R59-CENSUS-PROP): proposers maps each slot in the rewarded
// epoch to its COMMITTED proposer index (carried in the census, the analog
// of Ethereum's block.proposer_index). The proposer reward is credited to the
// census-declared proposer, never re-derived from node-local state — so nodes
// with divergent local VRF-accumulator/shuffle history still converge on the
// same rewards. A nil/partial proposers map falls back to local derivation for
// the affected slots (safe, but only reachable on the legacy path).
//
// epoch must be > 0 (epoch 0 is genesis and has no rewards; callers should
// guard against it). The result is cached into q.epochRewards[epoch] so that
// GetEpochRewards returns the same (now deterministic) value.
func (q *QPOS) ComputeEpochRewardsFromCensus(epoch uint64, census []*Attestation, proposers map[uint64]int) *EpochRewards {
	q.mu.Lock()
	defer q.mu.Unlock()

	if epoch == 0 {
		genesisRewards := &EpochRewards{
			Epoch:              0,
			ProposerRewards:    make(map[int]*big.Int),
			AttesterRewards:    make(map[int]*big.Int),
			Penalties:          make(map[int]*big.Int),
			SlashingPenalties:  make(map[int]*big.Int),
			TotalRewards:       big.NewInt(0),
			TotalPenalties:     big.NewInt(0),
			ParticipatingStake: big.NewInt(0),
			TotalStake:         big.NewInt(0),
		}
		if q.epochRewards == nil {
			q.epochRewards = make(map[uint64]*EpochRewards)
		}
		q.epochRewards[0] = genesisRewards
		return genesisRewards
	}

	// Group the flat census by slot so the shared core can index it.
	bySlot := make(map[uint64][]*Attestation, len(census))
	for _, att := range census {
		if att == nil {
			continue
		}
		bySlot[att.Slot] = append(bySlot[att.Slot], att)
	}

	rewards := q.computeEpochRewardsUnlocked(epoch, func(slot uint64) []*Attestation {
		return bySlot[slot]
	}, func(slot uint64) int {
		if proposers == nil {
			return -1
		}
		return proposers[slot]
	})

	if q.epochRewards == nil {
		q.epochRewards = make(map[uint64]*EpochRewards)
	}
	q.epochRewards[epoch] = rewards
	return rewards
}

// GetAttestationsForEpoch returns deep copies of all attestations collected
// for every slot within the given epoch. Used by the block producer to build
// the on-chain census that is embedded in the epoch-boundary block header.
func (q *QPOS) GetAttestationsForEpoch(epoch uint64) []*Attestation {
	q.mu.RLock()
	defer q.mu.RUnlock()

	startSlot := EpochStartSlot(epoch)
	endSlot := startSlot + SlotsPerEpoch - 1

	var result []*Attestation
	for slot := startSlot; slot <= endSlot; slot++ {
		for _, att := range q.attestations[slot] {
			result = append(result, deepCopyAttestation(att))
		}
	}
	return result
}

// SerializeAttestationCensus serializes a list of consensus attestations plus
// the per-slot COMMITTED proposer table into the block-header census format.
// Wire format (BigEndian, matching block_producer.serializeAttestations):
//
//	proposerCount(4)
//	  + [ slot(8) + proposerIdx(4) ] * proposerCount   (sorted by slot)
//	  + attCount(4)
//	  + [ slot(8) + blockRoot(32) + sourceEpoch(8) + targetEpoch(8)
//	      + validatorIdx(4) + sigLen(2) + signature ] * attCount
//
// R59-CENSUS-PROP: the proposer table is the on-chain analog of Ethereum's
// block.proposer_index — it carries the committed proposer for each rewarded
// slot so every node reproduces identical proposer rewards without touching
// node-local VRF/shuffle state. Proposer slots are sorted for deterministic
// serialization (map iteration order is random).
func SerializeAttestationCensus(atts []*Attestation, proposers map[uint64]int) []byte {
	// Preserve nil-on-empty semantics: an epoch with no attestations carries
	// no census (and no rewarded slots → empty proposer table). Callers treat
	// a nil census as the identical "no rewards" state.
	if len(atts) == 0 && len(proposers) == 0 {
		return nil
	}

	// --- Proposer table (deterministic: sorted by slot) ---
	propSlots := make([]uint64, 0, len(proposers))
	for s := range proposers {
		propSlots = append(propSlots, s)
	}
	sort.Slice(propSlots, func(i, j int) bool { return propSlots[i] < propSlots[j] })

	var buf []byte
	pcBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(pcBytes, uint32(len(propSlots))) // #nosec G115 -- bounded by epoch slot count
	buf = append(buf, pcBytes...)
	for _, s := range propSlots {
		slotBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(slotBytes, s)
		buf = append(buf, slotBytes...)
		idxBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idxBytes, uint32(proposers[s])) // #nosec G115 -- validator index bounded
		buf = append(buf, idxBytes...)
	}

	// --- Attestation census ---
	countBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(countBytes, uint32(len(atts))) // #nosec G115 -- census size bounded by protocol
	buf = append(buf, countBytes...)

	for _, att := range atts {
		// Slot (8 bytes)
		slotBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(slotBytes, att.Slot)
		buf = append(buf, slotBytes...)

		// BeaconBlockRoot (32 bytes)
		buf = append(buf, att.BeaconBlockRoot[:]...)

		// SourceEpoch (8 bytes)
		sourceBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(sourceBytes, att.Source.Epoch)
		buf = append(buf, sourceBytes...)

		// TargetEpoch (8 bytes)
		targetBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(targetBytes, att.Target.Epoch)
		buf = append(buf, targetBytes...)

		// ValidatorIndex (4 bytes)
		idxBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idxBytes, uint32(att.ValidatorIndex)) // #nosec G115 -- ValidatorIndex bounded by protocol
		buf = append(buf, idxBytes...)

		// Signature length (2 bytes) + signature
		sigLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(sigLenBytes, uint16(len(att.Signature))) // #nosec G115 -- signature length bounded
		buf = append(buf, sigLenBytes...)
		buf = append(buf, att.Signature...)
	}

	return buf
}

// DeserializeAttestationCensus parses the block-header census format produced
// by SerializeAttestationCensus back into consensus attestations plus the
// per-slot committed proposer table. Bounds-checked so malformed/truncated
// payloads return an error instead of panicking.
func DeserializeAttestationCensus(data []byte) ([]*Attestation, map[uint64]int, error) {
	// A nil census (header carries no attestation data) is a valid empty set:
	// epochs with no attestations produce no rewards. Do not fail on it.
	if data == nil {
		return []*Attestation{}, nil, nil
	}
	// A non-nil but truncated payload (< 8 bytes: propCount(4) + attCount(4))
	// is malformed.
	if len(data) < 8 {
		return nil, nil, fmt.Errorf("attestation census too short: %d bytes", len(data))
	}

	// --- Proposer table ---
	proposerCount := int(binary.BigEndian.Uint32(data[:4]))
	proposers := make(map[uint64]int, proposerCount)
	offset := 4
	for i := 0; i < proposerCount; i++ {
		if offset+12 > len(data) {
			return nil, nil, fmt.Errorf("attestation census: proposer entry %d truncated", i)
		}
		slot := binary.BigEndian.Uint64(data[offset : offset+8])
		rawIdx := binary.BigEndian.Uint32(data[offset+8 : offset+12])
		if rawIdx > 0x7FFFFFFF {
			return nil, nil, fmt.Errorf("attestation census: proposer index %d exceeds max int32", rawIdx)
		}
		proposers[slot] = int(rawIdx)
		offset += 12
	}

	// --- Attestation list ---
	if offset+4 > len(data) {
		return nil, nil, fmt.Errorf("attestation census: attestation count truncated")
	}
	count := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4
	// Defensive upper bound: each attestation is at least 60 fixed bytes plus
	// 2-byte sigLen. A count that would exceed the buffer is malformed.
	if count < 0 || 4+count*62 > len(data) {
		return nil, nil, fmt.Errorf("attestation census count %d inconsistent with payload length %d", count, len(data))
	}

	atts := make([]*Attestation, 0, count)
	for i := 0; i < count; i++ {
		if offset+60 > len(data) {
			return nil, nil, fmt.Errorf("attestation census: attestation %d truncated", i)
		}
		att := &Attestation{
			Slot: binary.BigEndian.Uint64(data[offset : offset+8]),
			Source: AttestationCheckpoint{
				Epoch: binary.BigEndian.Uint64(data[offset+40 : offset+48]),
			},
			Target: AttestationCheckpoint{
				Epoch: binary.BigEndian.Uint64(data[offset+48 : offset+56]),
			},
		}
		copy(att.BeaconBlockRoot[:], data[offset+8:offset+40])

		rawIdx := binary.BigEndian.Uint32(data[offset+56 : offset+60])
		if rawIdx > 0x7FFFFFFF {
			return nil, nil, fmt.Errorf("attestation census: validator index %d exceeds max int32", rawIdx)
		}
		att.ValidatorIndex = int(rawIdx)
		offset += 60

		if offset+2 > len(data) {
			return nil, nil, fmt.Errorf("attestation census: attestation %d signature length truncated", i)
		}
		sigLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+sigLen > len(data) {
			return nil, nil, fmt.Errorf("attestation census: attestation %d signature truncated", i)
		}
		att.Signature = make([]byte, sigLen)
		copy(att.Signature, data[offset:offset+sigLen])
		offset += sigLen

		atts = append(atts, att)
	}

	return atts, proposers, nil
}
