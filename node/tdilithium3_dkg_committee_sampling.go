// Quantaureum Node source, version 1.0.0.
package node

import (
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"

	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// D1 committee sampling accessor (dynamic-committee spec, section D1/D7, and
// the follow-up R76b note in that document). The v1 committee is a
// deterministic, finality-anchored function of the epoch roster: for n <= 7
// the committee is the whole roster (every chain today), and for n > 7 it is
// a fixed-size stake-weighted sample seeded by the VRF accumulator recorded
// with the roster (two epochs before it, the R88-F anti-grinding convention).
//
// The sample target is the largest pinned signing row, not the family ceiling
// 12: the signing MPC only has operational parameter rows at C=6 and C=7
// (R76b pinned rows; the C=8 row was measured non-operational and C>=9 is
// provably degenerate). A chain that grows past 7 validators therefore keeps
// a working seven-member chamber instead of topping out at an unsignable C=8.
//
// Fail-closed rules, mirroring R88-F: a roster whose entries carry no stake
// weights (pre-accessor sidecar) or whose sampling seed was not recorded
// (cold start) refuses to produce a committee for n > 7 rather than guessing;
// the n <= 7 path never consults the sampling fields at all.

// tdilithium3DKGCommitteeSampleTarget is the pinned committee size the sampler
// picks for rosters larger than it. It is the largest pinned signing row; the
// threshold follows the family rule t = ceil(2C/3) = 5.
const tdilithium3DKGCommitteeSampleTarget = 7

// tdilithium3DKGSampleDomain is the domain separation tag of the sampling
// hash. The construction follows SelectExecutiveForEpoch (sequential
// proportional-without-replacement draws over remaining stake, seeded per
// round from (domain, epoch, accumulator, round)).
const tdilithium3DKGSampleDomain = "QAU-TDILITHIUM3-V1-COMMITTEE-SAMPLE"

// errTDilithium3DKGSamplingUnavailable is the fail-closed error for a roster
// that the D1 sampler cannot sample: oversized roster with missing stakes or
// a missing sampling seed.
var errTDilithium3DKGSamplingUnavailable = fmt.Errorf("Dilithium3 v1 committee sample unavailable")

// tdilithium3DKGCommitteeSelection returns the roster indices that make up the
// epoch committee, in ascending roster order: every index when the roster fits
// the pinned committee row, otherwise a stake-weighted sample of
// tdilithium3DKGCommitteeSampleTarget indices drawn without replacement using
// the recorded sampling seed. The output is a pure function of the captured
// record, so every node derives the identical committee.
func tdilithium3DKGCommitteeSelection(roster *tdilithium3DKGEpochRoster) ([]int, error) {
	if roster == nil {
		return nil, fmt.Errorf("%w: roster is missing", errTDilithium3DKGEpochRosterUnavailable)
	}
	n := len(roster.Entries)
	if n == 0 {
		return nil, fmt.Errorf("%w: roster is empty", errTDilithium3DKGEpochRosterUnavailable)
	}
	if n <= tdilithium3DKGCommitteeSampleTarget {
		indices := make([]int, n)
		for i := range indices {
			indices[i] = i
		}
		return indices, nil
	}
	if !roster.SampleSeedSet {
		return nil, fmt.Errorf("%w: epoch %d roster (n=%d) has no recorded sampling seed",
			errTDilithium3DKGSamplingUnavailable, roster.Epoch, n)
	}
	// Every sampled entry must carry a real stake; guessing around a missing
	// weight would break the one-committee-per-roster invariant.
	type candidate struct {
		index int
		stake *big.Int
	}
	remaining := make([]candidate, 0, n)
	for index, entry := range roster.Entries {
		if entry.Stake == nil || entry.Stake.Sign() <= 0 {
			return nil, fmt.Errorf("%w: epoch %d roster entry %d has no usable stake",
				errTDilithium3DKGSamplingUnavailable, roster.Epoch, index)
		}
		remaining = append(remaining, candidate{index: index, stake: new(big.Int).Set(entry.Stake)})
	}
	selected := make([]int, 0, tdilithium3DKGCommitteeSampleTarget)
	pool := remaining
	for round := 0; round < tdilithium3DKGCommitteeSampleTarget; round++ {
		total := new(big.Int)
		for _, c := range pool {
			total.Add(total, c.stake)
		}
		if total.Sign() <= 0 {
			return nil, fmt.Errorf("%w: epoch %d sample round %d has no remaining stake",
				errTDilithium3DKGSamplingUnavailable, roster.Epoch, round)
		}
		// sha3(domain ‖ epoch ‖ seed ‖ round) mod totalStake picks the draw;
		// the 256-bit space dwarfs any realistic total stake so the modulo
		// bias is negligible, same argument as SelectExecutiveForEpoch.
		data := make([]byte, 0, len(tdilithium3DKGSampleDomain)+8+types.HashLength+8)
		data = append(data, tdilithium3DKGSampleDomain...)
		var field [8]byte
		binary.BigEndian.PutUint64(field[:], roster.Epoch)
		data = append(data, field[:]...)
		data = append(data, roster.SampleSeed[:]...)
		binary.BigEndian.PutUint64(field[:], uint64(round))
		data = append(data, field[:]...)
		roundHash := sha3.Sum256(data)
		ticket := new(big.Int).Mod(new(big.Int).SetBytes(roundHash[:]), total)
		cumulative := new(big.Int)
		chosen := -1
		for i, c := range pool {
			cumulative.Add(cumulative, c.stake)
			if ticket.Cmp(cumulative) < 0 {
				chosen = i
				break
			}
		}
		if chosen < 0 {
			// Rounding edge: the ticket fell into the mod-total tail gap.
			// Pick the last remaining candidate so the sample is total.
			chosen = len(pool) - 1
		}
		selected = append(selected, pool[chosen].index)
		pool = append(pool[:chosen], pool[chosen+1:]...)
	}
	sort.Ints(selected)
	return selected, nil
}

// tdilithium3DKGCommitteeForSelectedRoster builds the committee over the
// selected roster view: participant IDs are position+1 over the selection and
// the threshold is the family rule. The digest of this committee — not the raw
// roster — drives the session's committee commitment, so two nodes sampling
// identically derive the identical session.
func tdilithium3DKGCommitteeForSelectedRoster(roster *tdilithium3DKGEpochRoster, selection []int) (protocol.CommitteeID, error) {
	if len(selection) == 0 && roster != nil && len(roster.Entries) > 0 {
		return protocol.CommitteeID{}, fmt.Errorf("%w: no committee selection for a %d-entry roster",
			errTDilithium3DKGSamplingUnavailable, len(roster.Entries))
	}
	count := len(selection)
	threshold := protocol.Dilithium3V1ThresholdFor(uint32(count))
	if threshold == 0 {
		return protocol.CommitteeID{}, fmt.Errorf("%w: selected committee size %d is outside the Dilithium3 v1 family [%d, %d]",
			errTDilithium3DKGSamplingUnavailable, count,
			protocol.Dilithium3V1MinParticipants, protocol.Dilithium3V1MaxParticipants)
	}
	participants := make([]uint32, count)
	for position := range participants {
		participants[position] = uint32(position) + 1
	}
	committee := protocol.CommitteeID{Version: 1, Threshold: threshold, Participants: participants}
	if err := protocol.ValidateDilithium3V1Committee(committee); err != nil {
		return protocol.CommitteeID{}, fmt.Errorf("%w: sampled committee: %v", errTDilithium3DKGSamplingUnavailable, err)
	}
	if roster != nil {
		seen := make(map[int]bool, count)
		for _, index := range selection {
			if index < 0 || index >= len(roster.Entries) || seen[index] {
				return protocol.CommitteeID{}, fmt.Errorf("%w: selection index %d invalid for a %d-entry roster",
					errTDilithium3DKGSamplingUnavailable, index, len(roster.Entries))
			}
			seen[index] = true
		}
	}
	return committee, nil
}

// tdilithium3SigningParametersForShareSelection picks the signing row for a
// committee built by the D1 accessor. For sampled committees this is always
// the C=7 row; unsampled rosters up to 7 use their own size. Any other size
// fails closed via SigningParametersForParticipants.
func tdilithium3DKGSigningRowForCommittee(committee protocol.CommitteeID) (dilithium3v1.SigningParameters, error) {
	return dilithium3v1.SigningParametersForParticipants(len(committee.Participants))
}
