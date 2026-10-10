// Quantaureum Node source, version 1.0.0.
package node

// Offline-ceremony adoption driver for Dilithium3 v1 sealing.
//
// Mainnet forbids any runtime DKG, so the v1 committee key enters the network
// through the offline ceremony (cmd/tdil3_ceremony) and this driver:
//
//  1. every validator installs its ceremony share as a store candidate
//     (InstallOfflineCeremonyShare);
//  2. the operator sets tssV1SealingActivationEpoch in config.json (0 means
//     disabled, the production default);
//  3. at the activation epoch boundary the chamber transition asks the DKG
//     runner for the epoch's group key; instead of running a ceremony, this
//     driver launches the STANDARD activation exchange (the same one the
//     runtime ceremony ends with) over the installed candidates, in a
//     background goroutine — never inline in the block-production call chain,
//     because a 60-second exchange would stall block production that long;
//  4. later epochs reuse the persistent active share's group key. The key
//     does not rotate per epoch on this path: membership changes are the only
//     rekey trigger, via the R76/R77 reshare line.
//
// Fail-closed rules: a candidate whose activation epoch or committee does not
// match the chain-derived session refuses the transition (the chamber keeps
// retrying per slot, exactly like a stalled ceremony); no candidate at all
// means no sealing — the chain stays on attestation finality, blocks keep
// carrying individual signatures.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// offlineTDilithium3SealingActivation returns the configured activation epoch
// of the offline v1 sealing path, or false when the operator never armed it.
func (n *Node) offlineTDilithium3SealingActivation() (uint64, bool) {
	if n == nil || n.config == nil || n.config.TSSV1SealingActivationEpoch == 0 {
		return 0, false
	}
	return n.config.TSSV1SealingActivationEpoch, true
}

// offlineTDilithium3SealingArmed reports whether the offline v1 sealing path
// is armed AND the chain has reached its activation epoch.
func (n *Node) offlineTDilithium3SealingArmed(currentEpoch uint64) bool {
	activation, ok := n.offlineTDilithium3SealingActivation()
	return ok && currentEpoch >= activation
}

// offlineTDilithium3SealingConfigured reports whether the operator armed the
// offline v1 sealing path at all (epoch-independent), which is what
// infrastructure wiring (the TSS p2p loop, the roster sidecar) keys on.
func (n *Node) offlineTDilithium3SealingConfigured() bool {
	_, ok := n.offlineTDilithium3SealingActivation()
	return ok
}

// offlineTDilithium3AdoptionGroupKey serves the epoch transition on a chain
// whose v1 sealing is armed through the offline ceremony. It returns
// handled=false while the chain has not reached the activation epoch, so the
// caller's own (experimental or legacy) path keeps serving that range.
//
// The function is deliberately synchronous-cheap: it never runs the
// activation exchange inline. The exchange takes a full round (~60 s), and
// the caller chain reaches this code through the block-production slot tick —
// an inline exchange would stall block production exactly as long. Instead,
// adoption runs in a single background goroutine per activation epoch and the
// transition retries get "in progress" until the exchange commits; a failed
// round is re-launched by the next call.
func (n *Node) offlineTDilithium3AdoptionGroupKey(ctx context.Context, epoch uint64) ([1952]byte, bool, error) {
	var zero [1952]byte
	activation, ok := n.offlineTDilithium3SealingActivation()
	if !ok || epoch < activation {
		return zero, false, nil
	}
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return zero, true, fmt.Errorf("offline v1 sealing: %w", errTDilithium3DKGSessionUnavailable)
	}
	if n.config == nil || n.config.DataDir == "" || n.config.ValidatorKeyPassword == "" {
		return zero, true, fmt.Errorf("offline v1 sealing requires the node data directory and validator password")
	}
	password := []byte(n.config.ValidatorKeyPassword)
	store := newThresholdShareStore(n.config.DataDir)

	// Fast path: the offline share is already active — serve its group key
	// for every epoch at or past activation. The v1 seal executor resolves
	// signers against the activation epoch's roster anchor, so a persistent
	// committee key keeps answering until membership changes.
	if activeEpoch, activeKey, activeThreshold, err := n.tdilithium3ActiveShareIdentityCached(); err == nil && activeEpoch == activation {
		if len(activeKey) != len(zero) {
			return zero, true, fmt.Errorf("offline v1 sealing: active share key has %d bytes, want %d", len(activeKey), len(zero))
		}
		if err := n.registerTDilithium3SigningFinalitySigner(activation, activeKey, int(activeThreshold)); err != nil {
			nodeLog.Warn("offline v1 sealing: finality signer registration deferred: %v", err)
		}
		var publicKey [1952]byte
		copy(publicKey[:], activeKey)
		return publicKey, true, nil
	}

	// Candidate sanity probes stay cheap and fail closed with a named cause.
	candEpoch, _, _, _, err := store.CandidateSharePublicIdentity(password)
	if errors.Is(err, os.ErrNotExist) {
		return zero, true, fmt.Errorf("offline v1 sealing armed for epoch %d but no candidate share is installed (run tdil3_ceremony install first)", activation)
	}
	if err != nil {
		return zero, true, fmt.Errorf("offline v1 sealing: candidate probe: %w", err)
	}
	if candEpoch != activation {
		return zero, true, fmt.Errorf("offline v1 sealing: installed candidate activates at epoch %d, config arms epoch %d — reinstall the ceremony output or fix the config", candEpoch, activation)
	}

	// Kick the adoption exchange once per activation epoch.
	n.offlineTDilithium3AdoptionMu.Lock()
	if n.offlineTDilithium3AdoptionEpoch == activation {
		n.offlineTDilithium3AdoptionMu.Unlock()
		return zero, true, fmt.Errorf("offline v1 sealing: activation exchange for epoch %d already running", activation)
	}
	n.offlineTDilithium3AdoptionEpoch = activation
	n.offlineTDilithium3AdoptionMu.Unlock()
	go func() {
		defer func() {
			n.offlineTDilithium3AdoptionMu.Lock()
			n.offlineTDilithium3AdoptionEpoch = 0
			n.offlineTDilithium3AdoptionMu.Unlock()
		}()
		if err := n.runOfflineTDilithium3Adoption(activation); err != nil {
			nodeLog.Warn("offline v1 sealing: adoption exchange failed (retried at the next epoch transition): %v", err)
		}
	}()
	return zero, true, fmt.Errorf("offline v1 sealing: activation exchange for epoch %d launched in background", activation)
}

// runOfflineTDilithium3Adoption executes the full adoption round: bind the
// installed candidate to the chain-derived session, verify identity and
// committee consistency, then run the standard activation exchange. Called
// only from the background goroutine above; every failure is a refusal with
// a reason (ActivateCandidate commits atomically, so a failure leaves no
// partial state).
func (n *Node) runOfflineTDilithium3Adoption(activation uint64) error {
	password := []byte(n.config.ValidatorKeyPassword)
	store := newThresholdShareStore(n.config.DataDir)
	session, err := n.deriveTDilithium3DKGSession(activation)
	if err != nil {
		return fmt.Errorf("derive session: %w", err)
	}
	_, _, candThreshold, candPid, err := store.CandidateSharePublicIdentity(password)
	if err != nil {
		return fmt.Errorf("candidate probe: %w", err)
	}
	if candThreshold != session.Committee.Threshold {
		return fmt.Errorf("candidate threshold %d != committee threshold %d", candThreshold, session.Committee.Threshold)
	}
	share, err := store.LoadCandidate(session.KeyGeneration, candPid, password)
	if err != nil {
		return fmt.Errorf("load candidate: %w", err)
	}
	defer share.Zeroize()
	if share.ActivationEpoch != session.ActivationEpoch || share.Key.Generation != session.KeyGeneration {
		return fmt.Errorf("candidate and session diverge (share epoch %d gen %d, session epoch %d gen %d)",
			share.ActivationEpoch, share.Key.Generation, session.ActivationEpoch, session.KeyGeneration)
	}
	shareCommitteeDigest, err := share.Committee.CanonicalDigest()
	if err != nil {
		return err
	}
	sessionCommitteeDigest, err := session.Committee.CanonicalDigest()
	if err != nil {
		return err
	}
	if shareCommitteeDigest != sessionCommitteeDigest {
		return fmt.Errorf("installed candidate belongs to a different committee than the chain-derived session")
	}

	rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(activation)
	if err != nil {
		return err
	}
	roster, err := n.capturedEpochValidatorRoster(rosterEpoch)
	if err != nil {
		return err
	}
	committee, position, err := n.tdilithium3DKGCommitteeForRoster(roster)
	if err != nil {
		return err
	}
	if digest, derr := committee.CanonicalDigest(); derr != nil || digest != sessionCommitteeDigest {
		return fmt.Errorf("roster committee and session committee diverge")
	}
	if position >= uint8(len(committee.Participants)) || committee.Participants[position] != share.ParticipantID {
		return fmt.Errorf("installed share (participant %d) does not match this node's committee position %d — share installed on the wrong validator", share.ParticipantID, position)
	}
	if err := n.tdilithium3DKGVerifyLocalIdentity(roster, position); err != nil {
		return err
	}
	if n.p2pHost == nil {
		return fmt.Errorf("p2p host is not running")
	}
	localKey := n.blockProducer.ValidatorKey()
	bindings, err := tdilithium3DKGRosterBindings(roster, committee)
	if err != nil {
		return err
	}
	sign := func(message []byte) ([]byte, error) { return localKey.Sign(message) }
	retrySend := func(send func() error) {
		go func() {
			for attempt := 0; attempt < 10; attempt++ {
				time.Sleep(500 * time.Millisecond)
				if err := send(); err != nil {
					return
				}
			}
		}()
	}
	broadcast := func(messageType uint8, payload []byte) error {
		if err := n.p2pHost.BroadcastTSS(messageType, payload); err != nil {
			return err
		}
		retrySend(func() error { return n.p2pHost.BroadcastTSS(messageType, payload) })
		return nil
	}
	// The activation certificate is verified against exactly the roster-bound
	// identity set the runtime ceremony would use.
	verifier := dilithium3v1.DKGIdentityVerifier(func(participantID uint32, message, signature []byte) bool {
		for _, binding := range bindings {
			if binding.ParticipantID != participantID {
				continue
			}
			key, kerr := qcrypto.PublicKeyFromBytes(binding.PublicKey)
			if kerr != nil || key == nil {
				return false
			}
			return qcrypto.Verify(key, message, signature)
		}
		return false
	})

	nodeLog.Info("offline v1 sealing: running activation exchange for epoch %d (participant %d, %d committee members)", activation, share.ParticipantID, len(committee.Participants))
	exchangeContext, cancel := context.WithTimeout(context.Background(), 2*tdilithium3DKGActivationExchangeTimeout)
	defer cancel()
	if err := n.runTDilithium3ActivationExchange(exchangeContext, session, share, store, password, verifier, bindings, sign, broadcast); err != nil {
		return fmt.Errorf("activation exchange: %w", err)
	}
	activeEpoch, activeKey, activeThreshold, err := store.ActiveSharePublicIdentity(password)
	if err != nil || activeEpoch != activation {
		return fmt.Errorf("exchange ended without an active share: %v", err)
	}
	if err := n.registerTDilithium3SigningFinalitySigner(activation, activeKey, int(activeThreshold)); err != nil {
		return fmt.Errorf("finality registration: %w", err)
	}
	if len(activeKey) != 1952 {
		return fmt.Errorf("activated share key has %d bytes, want 1952", len(activeKey))
	}
	nodeLog.Info("offline v1 sealing: share activated for epoch %d (group key prefix %x)", activation, activeKey[:4])
	return nil
}
