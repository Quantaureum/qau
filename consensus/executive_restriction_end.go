// Quantaureum Node source, version 1.0.0.
package consensus

// Executive restriction end epoch.
//
// While the executive chamber is active, its member may neither propose nor
// attest (ThreeChambersCoordinator.CanPropose / CanAttest). On the Dilithium3
// v1 sealing path the executive member holds no sealing power of its own: the
// threshold signers are the DKG committee, which is every validator at the
// pinned committee sizes. The restriction then only removes one validator per
// epoch from the review quorum. Together with the slot's proposer it leaves
// n-2 attesters, which at the minimum chamber sizes (6 and 7 validators) is
// exactly the two-thirds the review verdict needs, so any one offline
// validator stops review approval, QTD sealing and Casper justification.
//
// A network therefore configures an epoch from which the executive chamber's
// member has the same proposing and attesting rights as every other validator.
// Proposer election and attestation acceptance are cross-verified, so every
// node of a network MUST use the same value; a divergent one forks the chain
// at the epoch. Before it the code path is byte-identical to the previous
// behavior, and the default (0, never) keeps it for every network that does
// not opt in. The per-slot proposer and reviewer exclusions are independent of
// the executive chamber and are not affected.

// SetExecutiveRestrictionEndEpoch configures the first epoch at which the
// executive chamber's member regains the proposing and attesting rights. Call
// once at node startup from config. Zero (the default) means never.
func (q *QPOS) SetExecutiveRestrictionEndEpoch(epoch uint64) {
	q.executiveRestrictionEnd.Store(epoch)
}

// GetExecutiveRestrictionEndEpoch reports the configured end epoch (0 when
// the restriction never ends).
func (q *QPOS) GetExecutiveRestrictionEndEpoch() uint64 {
	return q.executiveRestrictionEnd.Load()
}

// executiveRestrictionEnded reports whether the executive restriction no
// longer applies in the given epoch. Lock-free, so the coordinator can call it
// while holding its own mutex.
func (q *QPOS) executiveRestrictionEnded(epoch uint64) bool {
	end := q.executiveRestrictionEnd.Load()
	return end != 0 && epoch >= end
}
