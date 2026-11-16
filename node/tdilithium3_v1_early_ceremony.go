// Quantaureum Node source, version 1.0.0.
package node

// Early-ceremony beat for the Dilithium3 v1 runtime-DKG posture
// (TSS-R3-B-1 lag fix, P2-4 round 2).
//
// PROBLEM. In the experimental runtime-DKG posture the ceremony key rotates
// every epoch, and the ceremony was triggered by the epoch transition INTO its
// own activation epoch (the chamber drives CompleteDKGViaDistributedRunner on
// the first slot ticks). The ceremony takes 20-40 seconds, so it always
// completed AFTER the activation epoch's boundary header had been produced —
// and that boundary header embedded the still-active OUTGOING key. Observers
// adopted it as a same-key continuation, which pinned the outgoing key for the
// whole activation epoch (the mid-epoch fresh key then hit the
// conflicting-key refusal), fresh-sync nodes adopted a key no signer would use
// (the fresh-sync one-way stall), and group signing collapsed from the first
// rotation on (the pre-fix devnet collapse measured in the P2-4 round-2
// posture verification).
//
// FIX — the approved ③ direction, "trigger the ceremony one beat early": while
// the chain is in epoch N, the node runs the ceremony for epoch N+1. The
// roster a session activates on is the one captured at the boundary of
// activationEpoch-1 (tdilithium3DKGSessionRosterEpoch), so the roster the
// epoch-(N+1) ceremony needs is available from the first slot of epoch N —
// one full epoch of margin for the 20-40 second ceremony.
//
// The ceremony itself is unchanged; the one semantic addition is the DEFERRED
// COMMIT. A ceremony that completes while the chain has not yet reached its
// activation epoch must not replace the ACTIVE share: every signing gate
// refuses `epoch < activationEpoch`, so an early commit would strip the rest
// of the current epoch of group signing and QTD sealing (a far worse
// availability loss than the lag being fixed). The verified activation
// certificate is instead PARKED in memory, and the produce-loop tick commits
// it — ActivateCandidate, the identical call the ceremony would have made —
// exactly when the chain enters the activation epoch, BEFORE that epoch's
// boundary header is built. The boundary carrier then embeds the epoch's own
// key, the chamber's ceremony entry short-circuits on the already-active
// share, and group signing is available from the epoch's first mid-epoch slot.
//
// AVAILABILITY INVARIANT: the active share's activation epoch never runs ahead
// of the chain epoch. The park is the only path that could violate it, and it
// commits strictly at (or after) the activation epoch's first slot.
//
// FAILURE DEGRADATION (the approved ① fallback). If the early ceremony fails
// (network rounds, a peer down), the park stays empty; at the boundary the
// header carries no anchor (the boundary epoch-membership rule in
// tdilithium3V1HeaderAnchorKey refuses the outgoing key) and the chamber's own
// ceremony entry runs the full ceremony at the transition as before — the key
// lands mid-epoch, the un-anchored window seeds it, and the same-epoch record
// advance (recordTDilithium3CanonicalAnchor) lets the fleet adopt it. One lost
// boundary, not one lost epoch.
//
// RESTART DEGRADATION. The park is in-memory; a restart between the early
// ceremony and the boundary loses the certificate (the candidate share stays
// on disk). The boundary then falls back to the chamber-path ceremony exactly
// as above. The durable candidate is never committed without its certificate,
// so no half-activated state exists.
//
// POSTURE SCOPE. The beat runs only when the experimental runtime-DKG gate is
// open AND the offline ceremony posture is not configured: on the offline path
// the key precedes its activation epoch by construction (operator-installed
// candidates), the adoption driver owns the exchange, and per-epoch re-keying
// does not exist. Mainnet closes the experimental gate, so the whole file is
// inert there.

import (
	"context"
	"errors"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3PendingActivation is one verified activation certificate parked
// by a ceremony (or a gossip adoption) that ran before the chain reached its
// activation epoch. It carries everything ActivateCandidate and the finality
// registration need, so the commit at the boundary tick is the identical call
// the ceremony would have made.
type tdilithium3PendingActivation struct {
	activationEpoch uint64
	groupPublicKey  []byte
	threshold       int
	certificate     dilithium3v1.DKGActivationCertificate
	sessionDigest   [32]byte
	verifier        dilithium3v1.DKGIdentityVerifier
	bindings        []dilithium3v1.DKGIdentityBinding
}

// tdilithium3ChainEpoch is the chain's wall-clock epoch — the same clock the
// header's epoch field and the signing gates derive their epochs from — used
// by the deferral decision and the promotion probe. The boolean is false on a
// node without a consensus engine: the deferral exists to protect live
// signing, and a node that cannot sign has nothing to protect, so callers
// commit immediately (the legacy behavior) when this reports false.
func (n *Node) tdilithium3ChainEpoch() (uint64, bool) {
	if n == nil || n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return 0, false
	}
	return n.blockProducer.QPOS().GetCurrentEpoch(), true
}

// parkTDilithium3PendingActivation stores one pending activation, replacing
// any earlier one (the runtime posture has at most one armed future ceremony;
// a later ceremony's certificate supersedes it).
func (n *Node) parkTDilithium3PendingActivation(pending *tdilithium3PendingActivation) {
	if n == nil || pending == nil || pending.activationEpoch == 0 {
		return
	}
	n.tdilithium3EarlyCeremonyMu.Lock()
	n.tdilithium3EarlyCeremonyPending = pending
	n.tdilithium3EarlyCeremonyMu.Unlock()
}

// takeTDilithium3PendingActivation removes and returns the parked activation,
// or nil when nothing is parked.
func (n *Node) takeTDilithium3PendingActivation() *tdilithium3PendingActivation {
	n.tdilithium3EarlyCeremonyMu.Lock()
	pending := n.tdilithium3EarlyCeremonyPending
	n.tdilithium3EarlyCeremonyPending = nil
	n.tdilithium3EarlyCeremonyMu.Unlock()
	return pending
}

// commitTDilithium3PendingActivation runs the deferred commit: the same
// ActivateCandidate call the ceremony's exchange would have made, then the
// finality-surface registration. The share cache is invalidated so the next
// identity probe reads the promoted share.
func (n *Node) commitTDilithium3PendingActivation(pending *tdilithium3PendingActivation) error {
	if n == nil || pending == nil || n.config == nil ||
		n.config.DataDir == "" || n.config.ValidatorKeyPassword == "" {
		return errors.New("Dilithium3 v1 deferred activation is not configured")
	}
	store := newThresholdShareStore(n.config.DataDir)
	if err := store.ActivateCandidate(
		pending.certificate, pending.sessionDigest, pending.activationEpoch,
		pending.verifier, pending.bindings, []byte(n.config.ValidatorKeyPassword),
	); err != nil {
		return err
	}
	n.invalidateTDilithium3ShareCache()
	if err := n.registerTDilithium3SigningFinalitySigner(
		pending.activationEpoch, pending.groupPublicKey, pending.threshold,
	); err != nil {
		// The active share is committed; the startup refresh or the next
		// share-bound call rebinds the surface.
		nodeLog.Warn("Dilithium3 v1 deferred activation: finality surface registration deferred: %v", err)
	}
	return nil
}

// tdilithium3V1EarlyCeremonyTick runs the per-slot early-ceremony beat. The
// produce loop calls it BEFORE the slot's header is built, so a promotion that
// lands on this tick is visible to the boundary carrier the same tick.
//
// Two duties, in order:
//  1. PROMOTION: commit a parked activation whose activation epoch has been
//     reached (the tick's slot epoch, the same clock the header's epoch field
//     derives from). A failed commit is re-parked and retried on the next
//     tick; the chamber-path ceremony at the transition is the recovery path
//     of last resort.
//  2. LAUNCH: start the ceremony for the NEXT epoch when this epoch is the
//     earliest one that can serve it (roster rule: activation >= 2) and no
//     armed candidate exists yet. One attempt per activation epoch; the
//     retryable startup refusals (roster not captured yet at the epoch's first
//     ticks, another ceremony in flight) clear the marker so the next tick
//     retries.
func (n *Node) tdilithium3V1EarlyCeremonyTick(slot uint64) {
	if n == nil || n.config == nil || n.blockProducer == nil || n.p2pHost == nil {
		return
	}
	// The experimental runtime-DKG posture only; the offline ceremony posture
	// owns its own activation timing (and mainnet closes the gate entirely).
	if !n.tdilithium3V1OwnsExecutiveActivation() || n.offlineTDilithium3SealingConfigured() {
		return
	}
	// A syncing node's ceremonies would run against a lagging chain; the
	// produce loop skips production while syncing, and so does the beat.
	if n.syncer != nil && n.syncer.IsSyncing() {
		return
	}
	epoch := consensus.SlotToEpoch(slot)

	// 1. Promotion: the parked activation's epoch has arrived. Commit BEFORE
	// this tick's header build so the boundary carrier embeds the new key.
	if pending := n.takeTDilithium3PendingActivation(); pending != nil {
		switch {
		case pending.activationEpoch > epoch:
			// Not due yet (a restart rewound the wall clock, or the park
			// raced ahead of the chain): re-park untouched.
			n.parkTDilithium3PendingActivation(pending)
		case pending.activationEpoch < epoch:
			// Stale (audit round-3 low): the chain moved PAST the activation
			// epoch (multi-epoch catch-up after downtime). Committing would
			// re-root the custody to a dead key and — through the re-root's
			// purge of different-key entries — destroy the newer entries the
			// import path already adopted, stalling verification. Drop the
			// park; the chamber-path ceremony at the next epoch transition
			// remains the recovery path.
			nodeLog.Warn("Dilithium3 v1 deferred activation for epoch %d dropped: the chain already reached epoch %d (stale park)",
				pending.activationEpoch, epoch)
		default:
			if err := n.commitTDilithium3PendingActivation(pending); err != nil {
				nodeLog.Warn("Dilithium3 v1 deferred activation commit failed for epoch %d (retried on the next tick): %v",
					pending.activationEpoch, err)
				n.parkTDilithium3PendingActivation(pending)
			} else {
				nodeLog.Info("Dilithium3 v1 deferred activation committed for epoch %d (group key prefix %x) — the boundary carrier embeds the epoch's own key",
					pending.activationEpoch, pending.groupPublicKey[:4])
			}
		}
	}

	// 2. Launch: the ceremony for epoch+1, one beat before its activation.
	target := epoch + 1
	if epoch < 1 {
		// Activation epochs below 2 have no roster to anchor on
		// (tdilithium3DKGSessionRosterEpoch refuses them).
		return
	}
	n.tdilithium3EarlyCeremonyMu.Lock()
	if n.tdilithium3EarlyCeremonyPending != nil ||
		n.tdilithium3EarlyCeremonyAttemptEpoch >= target {
		n.tdilithium3EarlyCeremonyMu.Unlock()
		return
	}
	// Mark the attempt before probing: the launch below is the only path that
	// un-marks it (retryable refusals), so a running ceremony is not
	// re-launched on every tick.
	n.tdilithium3EarlyCeremonyAttemptEpoch = target
	n.tdilithium3EarlyCeremonyMu.Unlock()

	// A candidate (or an active share) for the target epoch is already armed:
	// the beat has nothing to do this epoch.
	if n.tdilithium3V1ShareArmedForEpoch(target) {
		return
	}

	nodeLog.Info("Dilithium3 v1 early ceremony beat: launching the epoch-%d ceremony one epoch ahead (chain epoch %d)", target, epoch)
	go func() {
		if _, err := n.runTDilithium3DKGCeremony(context.Background(), target); err != nil {
			if tdilithium3EarlyCeremonyRetryable(err) {
				// Startup-order refusals (the roster for the target's roster
				// epoch is not captured yet, another ceremony holds the
				// single-flight): clear the marker so the next tick retries.
				n.tdilithium3EarlyCeremonyMu.Lock()
				if n.tdilithium3EarlyCeremonyAttemptEpoch == target {
					n.tdilithium3EarlyCeremonyAttemptEpoch = 0
				}
				n.tdilithium3EarlyCeremonyMu.Unlock()
				return
			}
			nodeLog.Warn("Dilithium3 v1 early ceremony beat failed for epoch %d (the epoch transition remains the recovery path): %v", target, err)
		}
	}()
}

// tdilithium3V1ShareArmedForEpoch reports whether the share store already
// holds an active share or an armed candidate for the given activation epoch.
func (n *Node) tdilithium3V1ShareArmedForEpoch(epoch uint64) bool {
	if n == nil || n.config == nil || n.config.DataDir == "" || n.config.ValidatorKeyPassword == "" {
		return false
	}
	store := newThresholdShareStore(n.config.DataDir)
	password := []byte(n.config.ValidatorKeyPassword)
	if activeEpoch, _, _, err := store.ActiveSharePublicIdentity(password); err == nil && activeEpoch >= epoch {
		return true
	}
	if candEpoch, _, _, _, err := store.CandidateSharePublicIdentity(password); err == nil && candEpoch >= epoch {
		return true
	}
	return false
}

// tdilithium3EarlyCeremonyRetryable reports whether an early-beat refusal is a
// startup-order outcome that the next slot tick can plausibly resolve: the
// target epoch's roster is not captured yet (the boundary block lands within
// the first slots), or another ceremony holds the single-flight mutex. A
// DETERMINISTIC per-epoch refusal is excluded: committee membership is fixed
// for the whole epoch (errTDilithium3DKGLocalNotACommitteeMember), so a
// non-committee node must keep its attempt marker instead of clearing it and
// re-launching a doomed ceremony on every remaining tick of the epoch.
func tdilithium3EarlyCeremonyRetryable(err error) bool {
	if errors.Is(err, errTDilithium3DKGLocalNotACommitteeMember) {
		return false
	}
	return errors.Is(err, errTDilithium3DKGSessionUnavailable) ||
		errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) ||
		errors.Is(err, errTDilithium3DKGCeremonyActive)
}
