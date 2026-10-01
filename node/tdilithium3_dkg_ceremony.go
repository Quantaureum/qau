// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// Production ceremony orchestrator for the Dilithium3 v1 CNF-RSS DKG
// (session-derivation design, sections 4 and 5).
//
// It is the only production caller of the v1 round machinery: it derives the
// session, installs the authenticated inbox, runs the public-randomness round,
// drives the twenty canonical RSS groups in order and finalizes the local share.
// Everything is gated: the ceremony refuses to start unless both experimental
// gates are open and the network is not mainnet, so a production node that has
// not opted in never touches this path.

const (
	// tdilithium3DKGCeremonyTimeout bounds one ceremony end to end.
	tdilithium3DKGCeremonyTimeout = 180 * time.Second
	// tdilithium3DKGCeremonyRoundTimeout bounds the randomness round and each
	// individual group round. A round that cannot reach its peers within this
	// window fails closed with errTDilithium3DKGGroupStalled rather than
	// blocking the epoch transition forever.
	tdilithium3DKGCeremonyRoundTimeout = 30 * time.Second
)

var (
	// errTDilithium3DKGCeremonyDisabled is returned when the ceremony is asked
	// to run with the experimental gates closed or on mainnet.
	errTDilithium3DKGCeremonyDisabled = errors.New("Dilithium3 v1 DKG ceremony is disabled")
	// errTDilithium3DKGCeremonyActive is returned when a ceremony is already
	// running on this node. Two overlapping ceremonies would fight over the
	// single inbox field, so the second one is refused instead.
	errTDilithium3DKGCeremonyActive = errors.New("Dilithium3 v1 DKG ceremony is already running")
	// errTDilithium3DKGIdentityKeyMismatch is returned when the local validator
	// key is not the identity key the epoch roster attributes to this node.
	// Every peer would reject this node's envelopes, so the ceremony refuses to
	// start rather than fail one round later.
	errTDilithium3DKGIdentityKeyMismatch = errors.New("local validator key does not match the epoch roster identity")
)

// tdilithium3V1OwnsExecutiveActivation reports whether the Dilithium3 v1
// ceremony -- and not the legacy TSS group key -- must activate the executive
// chamber for an epoch. True only when both experimental gates are open on a
// non-mainnet network: the same predicate nodeConsensusDKGRunner uses to select
// the v1 branch, so the two decisions stay in step.
//
// While this is true the epoch transition must not activate the chamber with the
// legacy group key. That activation sets the chamber active, and
// CompleteDKGViaDistributedRunner then returns early on its IsActive() check
// (consensus/provinces.go), which makes the v1 ceremony unreachable on any chain
// that reaches an epoch boundary with the legacy key already established. The
// design's D8 rule is no legacy fallback, so the transition leaves the chamber
// in DKGRunning with its members selected instead.
func (n *Node) tdilithium3V1OwnsExecutiveActivation() bool {
	return n != nil && n.config != nil &&
		experimentalTDilithium3V1EnabledForNetwork(n.config.NetworkID)
}

// runTDilithium3DKGCeremony runs one full Dilithium3 v1 DKG ceremony for an
// activation epoch and returns the assembled 1952-byte mode3 group public key.
//
// The caller is the Three Chambers epoch transition, through
// nodeConsensusDKGRunner.RunDistributedDKG. A failure is returned as-is and is
// never converted into a legacy group key: activating the chamber with a key the
// v1 committee holds no shares for would be worse than failing (design, D8).
func (n *Node) runTDilithium3DKGCeremony(ctx context.Context, activationEpoch uint64) ([1952]byte, error) {
	var publicKey [1952]byte
	if n == nil || n.config == nil {
		return publicKey, fmt.Errorf("%w: node is not configured", errTDilithium3DKGSessionUnavailable)
	}
	if !experimentalTDilithium3V1EnabledForNetwork(n.config.NetworkID) {
		return publicKey, fmt.Errorf("%w: experimental gates are closed or the network is mainnet without the explicit mainnet acknowledgement", errTDilithium3DKGCeremonyDisabled)
	}
	if n.blockProducer == nil {
		return publicKey, fmt.Errorf("%w: local validator identity is not available", errTDilithium3DKGSessionUnavailable)
	}
	if n.p2pHost == nil {
		return publicKey, fmt.Errorf("%w: P2P host is not available", errTDilithium3DKGSessionUnavailable)
	}
	if n.config.DataDir == "" || n.config.ValidatorKeyPassword == "" {
		return publicKey, fmt.Errorf("%w: share storage is not configured", errTDilithium3DKGSessionUnavailable)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if n.ctx != nil {
		// Follow the node's lifetime: a shutdown cancels the ceremony.
		base := n.ctx
		ceremony, cancel := context.WithTimeout(base, tdilithium3DKGCeremonyTimeout)
		defer cancel()
		ctx = ceremony
	} else {
		ceremony, cancel := context.WithTimeout(ctx, tdilithium3DKGCeremonyTimeout)
		defer cancel()
		ctx = ceremony
	}

	n.tdilithium3DKGCeremonyMu.Lock()
	if n.tdilithium3DKGCeremonyRunning {
		n.tdilithium3DKGCeremonyMu.Unlock()
		return publicKey, errTDilithium3DKGCeremonyActive
	}
	n.tdilithium3DKGCeremonyRunning = true
	n.tdilithium3DKGCeremonyMu.Unlock()
	defer func() {
		n.tdilithium3DKGCeremonyMu.Lock()
		n.tdilithium3DKGCeremonyRunning = false
		n.tdilithium3DKGCeremonyMu.Unlock()
	}()

	rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(activationEpoch)
	if err != nil {
		return publicKey, err
	}
	roster, err := n.capturedEpochValidatorRoster(rosterEpoch)
	if err != nil {
		return publicKey, err
	}
	session, err := n.deriveTDilithium3DKGSession(activationEpoch)
	if err != nil {
		return publicKey, err
	}
	committee, position, err := n.tdilithium3DKGCommitteeForRoster(roster)
	if err != nil {
		return publicKey, err
	}
	// D6: the identity key that signs every envelope must be the key the roster
	// publishes for this node (see tdilithium3DKGVerifyLocalIdentity).
	if err := n.tdilithium3DKGVerifyLocalIdentity(roster, position); err != nil {
		return publicKey, err
	}
	localKey := n.blockProducer.ValidatorKey()

	bindings, err := tdilithium3DKGRosterBindings(roster, committee)
	if err != nil {
		return publicKey, err
	}
	// The host's validator->peer registry is populated only from signature-verified
	// STATUS messages received from REMOTE peers, so a node never has a binding for
	// its own validator address. Both consumers of peerForValidator -- the private
	// send targets below and the inbox identity snapshot (which requires the whole
	// committee) -- demand a binding for every committee member, including self, so
	// bind self explicitly to the host's own peer ID. The runner never addresses a
	// private message to itself (outboundSeedLocked skips the leader), so this entry
	// is never used as a send target; it only completes the roster.
	ownAddress := roster.Entries[position].Address
	ownPeer := n.p2pHost.ID()
	peerForValidator := func(address types.Address) (p2p.PeerID, bool) {
		if address == ownAddress {
			return ownPeer, ownPeer != ""
		}
		return n.p2pHost.GetPeerIDForValidator(address)
	}
	// Resolve the private-send targets from the same bindings the inbox commits
	// to, so a private seed can never be addressed to a peer outside the roster.
	peerByPosition := make(map[uint8]p2p.PeerID, len(bindings))
	for _, binding := range bindings {
		if binding.ParticipantID == 0 {
			return publicKey, fmt.Errorf("%w: roster position %d has no participant ID", errTDilithium3DKGSessionUnavailable, binding.ParticipantID)
		}
		peer, found := peerForValidator(types.Address(binding.ValidatorAddress))
		if !found || peer == "" {
			return publicKey, fmt.Errorf("%w: committee member %s has no peer binding", errTDilithium3DKGSessionUnavailable, types.Address(binding.ValidatorAddress).String())
		}
		peerByPosition[uint8(binding.ParticipantID-1)] = peer
	}

	// The runner owns the encrypted journal. Its session digest keys the journal
	// directory, so a crash mid-ceremony resumes the same session with the same
	// recorded randomness instead of starting a conflicting one (design, D3).
	runner, err := newTDilithium3DKGRunner(tdilithium3DKGRunnerConfig{
		Session:             session,
		ParticipantPosition: position,
		BasePath:            n.config.DataDir,
		Password:            []byte(n.config.ValidatorKeyPassword),
		Entropy:             rand.Reader,
	})
	if err != nil {
		return publicKey, fmt.Errorf("Dilithium3 v1 DKG runner: %w", err)
	}

	inbox, err := n.newTDilithium3DKGInboxFromCapturedEpochRoster(session, position, rosterEpoch, peerForValidator)
	if err != nil {
		return publicKey, err
	}
	n.installTDilithium3DKGInbox(inbox)
	defer n.installTDilithium3DKGInbox(nil)

	diff, err := session.Digest()
	if err != nil {
		return publicKey, err
	}
	nodeLog.Info("Dilithium3 v1 DKG ceremony starting (activation epoch %d, roster epoch %d, session %x, position %d)",
		activationEpoch, rosterEpoch, diff[:8], position)

	sign := func(message []byte) ([]byte, error) {
		return localKey.Sign(message)
	}
	broadcast := func(messageType uint8, payload []byte) error {
		return n.p2pHost.BroadcastTSS(messageType, payload)
	}
	sendPrivate := func(messageType uint8, recipientPosition uint8, payload []byte) error {
		peer, found := peerByPosition[recipientPosition]
		if !found {
			return fmt.Errorf("Dilithium3 v1 DKG private send to unknown position %d", recipientPosition)
		}
		return n.p2pHost.SendTSSToPeer(peer, messageType, payload)
	}
	// One exchange for the whole ceremony: a message for a group the local node
	// has not reached yet is retained instead of being lost, and early group
	// traffic that arrives during the randomness round is retained too.
	exchange := newTDilithium3DKGGroupExchange()

	randomnessContext, cancelRandomness := context.WithTimeout(ctx, tdilithium3DKGCeremonyRoundTimeout)
	err = n.runTDilithium3DKGRandomness(randomnessContext, runner, exchange, sign, broadcast)
	cancelRandomness()
	if err != nil {
		return publicKey, fmt.Errorf("Dilithium3 v1 DKG randomness round: %w", err)
	}

	for _, group := range dilithium3v1.CanonicalRSSGroups() {
		if err := ctx.Err(); err != nil {
			return publicKey, fmt.Errorf("Dilithium3 v1 DKG ceremony: %w", err)
		}
		groupContext, cancelGroup := context.WithTimeout(ctx, tdilithium3DKGCeremonyRoundTimeout)
		err := n.runTDilithium3DKGGroup(groupContext, runner, group, exchange, sign, broadcast, sendPrivate)
		cancelGroup()
		if err != nil {
			return publicKey, fmt.Errorf("Dilithium3 v1 DKG group %06b: %w", uint(group), err)
		}
	}

	result, err := tdilithium3DKGFinalize(runner)
	if err != nil {
		return publicKey, fmt.Errorf("Dilithium3 v1 DKG finalize: %w", err)
	}

	// Activation exchange: the finalized share is only a candidate until all
	// six committee members sign it. The ceremony drives the exchange inline:
	// every participant broadcasts its signed acknowledgement, everyone
	// collects the six receipts, assembles the activation certificate, and
	// promotes the candidate to the active share. A failure here fails the
	// ceremony closed; the candidate on disk is replay-safe and the next
	// epoch's ceremony supersedes it.
	//
	// Short-circuit: when the active share was already adopted via gossip
	// (a faster node's exchange completed and gossiped its certificate
	// before this node's ceremony ran its own exchange), the exchange is
	// redundant. Running it wastes the 30-second round and -- worse -- can
	// desync the commit-time window so peers that already sealed the slot
	// with the adopted key do not see this node's signature in time. The
	// share store is the source of truth: if an active share for this
	// activation epoch is already on disk, register the finality surface
	// directly and skip the exchange.
	if store := newThresholdShareStore(n.config.DataDir); store != nil {
		activeEpoch, activeKey, activeErr := store.ActiveSharePublicIdentity([]byte(n.config.ValidatorKeyPassword))
		if activeErr == nil && activeEpoch == activationEpoch {
			nodeLog.Info("Dilithium3 v1 DKG ceremony: active share already adopted for epoch %d (group key prefix %x); skipping activation exchange",
				activationEpoch, activeKey[:4])
			if err := n.registerTDilithium3SigningFinalitySigner(activationEpoch, activeKey); err != nil {
				nodeLog.Warn("Dilithium3 v1 DKG finality surface registration deferred (adopted path): %v", err)
			}
			nodeLog.Info("Dilithium3 v1 DKG ceremony completed (activation epoch %d, session %x, transcript %x, adoption short-circuit)",
				activationEpoch, diff[:8], result.TranscriptDigest[:8])
			return result.PublicKey, nil
		}
	}
	activationContext, cancelActivation := context.WithTimeout(ctx, tdilithium3DKGCeremonyRoundTimeout)
	err = n.runTDilithium3DKGActivationExchange(activationContext, session, runner, result, inbox.verifyIdentity, sign, broadcast)
	cancelActivation()
	if err != nil {
		return publicKey, fmt.Errorf("Dilithium3 v1 DKG activation exchange: %w", err)
	}
	if err := n.registerTDilithium3SigningFinalitySigner(activationEpoch, result.PublicKey[:]); err != nil {
		// The active share is already persisted, so the startup refresh or the
		// next share-bound call rebinds the surface; the ceremony still
		// succeeded.
		nodeLog.Warn("Dilithium3 v1 DKG finality surface registration deferred: %v", err)
	}
	nodeLog.Info("Dilithium3 v1 DKG ceremony completed (activation epoch %d, session %x, transcript %x)",
		activationEpoch, diff[:8], result.TranscriptDigest[:8])
	return result.PublicKey, nil
}
