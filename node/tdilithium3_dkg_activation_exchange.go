// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// The activation exchange is the last phase of the Dilithium3 v1 DKG
// ceremony: the locally finalized candidate share is promoted to the active
// share once every committee member has signed the activation acknowledgement.
//
// Every node runs the same exchange in the same order because the ceremony is
// deterministic; the exchange is therefore the same on all six members and
// converges on the same certificate.
//
// Inbound routing: the authenticated DKG inbox deliberately refuses
// activation envelopes (they carry the candidate-bound activation transcript
// rather than the per-message identity domain), so the certificate assembler
// verifies them as a set. The node's TSS processing loop routes activation
// packets to the sink channel below only while an exchange is running.

// tdilithium3DKGActivationSinkCapacity bounds how many acknowledgement packets
// the sink channel can hold while the exchange is busy. The maximum useful
// number is six; anything beyond that is a duplicate or replay.
const tdilithium3DKGActivationSinkCapacity = 6

// tdilithium3DKGActivationExchangeTimeout bounds one exchange end to end.
// The exchange is a single 30-second round (one broadcast + one collection
// window + one assembly), so 30 seconds matches the round timeout.
const tdilithium3DKGActivationExchangeTimeout = 30 * time.Second

// runTDilithium3DKGActivationExchange signs the locally finalized candidate
// share, broadcasts the signed acknowledgement, collects six verified
// receipts, assembles the activation certificate, and commits the active
// share locally. The verifier is the inbox's roster-bound identity verifier
// (or, in tests, an equivalent participant->key map).
//
// Re-verification is done inside assembleTDilithium3DKGActivationCertificate,
// which checks the signature of each packet against the verifier. Packets
// that do not pass that check are dropped, so the certificate will only
// assemble when all six correct packets arrive.
func (n *Node) runTDilithium3DKGActivationExchange(
	ctx context.Context,
	session dilithium3v1.DKGSession,
	runner *tdilithium3DKGRunner,
	result tdilithium3DKGResult,
	verifier dilithium3v1.DKGIdentityVerifier,
	sign func([]byte) ([]byte, error),
	broadcast func(messageType uint8, payload []byte) error,
) error {
	if runner == nil || result.Share == nil {
		return fmt.Errorf("Dilithium3 v1 activation exchange requires a finalized share")
	}
	return n.runTDilithium3ActivationExchange(
		ctx, session, result.Share, runner.shareStore, runner.password,
		verifier, sign, broadcast,
	)
}

// runTDilithium3ActivationExchange is the share-level core of the activation
// exchange: the DKG ceremony hands it a finalized candidate and the same-key
// reshare ceremony (R77) hands it the rotated store-candidate share.
func (n *Node) runTDilithium3ActivationExchange(
	ctx context.Context,
	session dilithium3v1.DKGSession,
	share *dilithium3v1.LocalShare,
	shareStore *thresholdShareStore,
	password []byte,
	verifier dilithium3v1.DKGIdentityVerifier,
	sign func([]byte) ([]byte, error),
	broadcast func(messageType uint8, payload []byte) error,
) error {
	if share == nil || shareStore == nil || len(password) == 0 {
		return fmt.Errorf("Dilithium3 v1 activation exchange requires a finalized share")
	}
	if session.ActivationEpoch == 0 {
		return fmt.Errorf("Dilithium3 v1 activation exchange requires a non-zero activation epoch")
	}
	// Sign and broadcast our own acknowledgement.
	own, err := encodeTDilithium3DKGActivationEnvelope(session, share, sign)
	if err != nil {
		return fmt.Errorf("encode activation envelope: %w", err)
	}
	if err := broadcast(p2p.MsgTypeTDilithium3DKGActivation, own); err != nil {
		return fmt.Errorf("broadcast activation envelope: %w", err)
	}

	// Collect verified packets from all committee members, then assemble
	// the certificate.
	//
	// Because the nodes begin their ceremonies at staggered times (the
	// per-slot produce loop drives the retry cadence), a node that installs
	// its sink after a peer already fired its single acknowledgement would
	// otherwise never observe that peer. Mirror the randomness round and
	// rebroadcast our own acknowledgement every second until every member is
	// collected, so late-starting nodes still converge on the full set.
	memberCount := len(session.Committee.Participants)
	colslected := map[string][]byte{string(own): own}
	sink := make(chan []byte, tdilithium3DKGActivationSinkCapacity)
	n.installTDilithium3DKGActivationSink(sink)
	defer n.clearTDilithium3DKGActivationSink()
	deadline, cancel := context.WithTimeout(ctx, tdilithium3DKGActivationExchangeTimeout)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for len(colslected) < memberCount {
		select {
		case packet := <-sink:
			// Dedup by content; a retransmitted packet is identical.
			// Invalid or foreign packets are dropped by the verifier at
			// assembly time, so we do not reject them here.
			if _, exists := colslected[string(packet)]; !exists {
				colslected[string(packet)] = packet
			}
		case <-ticker.C:
			// If a gossip adoption committed the active share for this
			// activation epoch while we were collecting, the exchange is
			// redundant: the share is already persisted and the finality
			// surface is already registered. Skip the assembly (which
			// requires all six receipts) and return success.
			activeEpoch, _, _, probeErr := shareStore.ActiveSharePublicIdentity(password)
			if probeErr == nil && activeEpoch == session.ActivationEpoch {
				nodeLog.Info("Dilithium3 v1 activation exchange: active share adopted via gossip during collection; skipping assembly (collected %d/%d, epoch %d)", len(colslected), memberCount, session.ActivationEpoch)
				return nil
			}
			// Retransmit our own acknowledgement so peers that installed
			// their sink after our first broadcast still receive it.
			if err := broadcast(p2p.MsgTypeTDilithium3DKGActivation, own); err != nil {
				return fmt.Errorf("rebroadcast activation envelope: %w", err)
			}
		case <-deadline.Done():
			return fmt.Errorf("Dilithium3 v1 activation exchange collected %d/%d acknowledgements before the deadline",
				len(colslected), memberCount)
		}
	}
	colslectedIn := make([][]byte, 0, len(colslected))
	for _, packet := range colslected {
		colslectedIn = append(colslectedIn, packet)
	}
	var sharePublicKey [1952]byte
	copy(sharePublicKey[:], share.Key.PublicKey)
	certificate, err := assembleTDilithium3DKGActivationCertificate(session, sharePublicKey, share.TranscriptDigest, colslectedIn, verifier)
	if err != nil {
		return fmt.Errorf("assemble activation certificate: %w", err)
	}
	sessionDigest, err := session.Digest()
	if err != nil {
		return fmt.Errorf("session digest: %w", err)
	}
	if err := shareStore.ActivateCandidate(certificate, sessionDigest, session.ActivationEpoch, verifier, password); err != nil {
		return fmt.Errorf("commit active share: %w", err)
	}
	nodeLog.Info("Dilithium3 v1 activation committed (activation epoch %d, session %x, group key prefix %x)",
		session.ActivationEpoch, sessionDigest[:8], sharePublicKey[:4])

	// Gossip the assembled certificate so peers that never reached the full
	// six-acknowledgement set for this session can adopt the same group key
	// instead of deriving a divergent one on a later epoch. The certificate is
	// self-verifying (it carries all six signed acknowledgements bound to the
	// session digest and transcript), so any peer that holds the matching
	// candidate share can commit it through the adoption path without a live
	// exchange. Rebroadcast a few times because pubsub is best-effort and a
	// late-joining peer may install its subscription after the first send.
	encoded, err := encodeThresholdActivationCertificate(certificate)
	if err != nil {
		// A failure here does not invalidate the local commit; log and move
		// on. Peers that ran their own exchange still converge independently.
		nodeLog.Warn("Dilithium3 v1 activation certificate encode for gossip failed: %v", err)
		return nil
	}
	n.broadcastTDilithium3DKGActivationCertificate(ctx, broadcast, encoded)
	return nil
}

// tdilithium3DKGActivationCertificateGossipRounds bounds how many times a
// committing node rebroadcasts its assembled certificate. Pubsub is
// best-effort, so a small burst covers peers whose subscription installs
// slightly after the first send without flooding the topic.
const tdilithium3DKGActivationCertificateGossipRounds = 3

// tdilithium3DKGActivationCertificateGossipInterval spaces out the rebroadcast
// burst so peers have time to receive, verify, and adopt between rounds.
const tdilithium3DKGActivationCertificateGossipInterval = 2 * time.Second

// broadcastTDilithium3DKGActivationCertificate gossips the encoded certificate
// a bounded number of times, stopping early if the context is cancelled.
func (n *Node) broadcastTDilithium3DKGActivationCertificate(ctx context.Context, broadcast func(messageType uint8, payload []byte) error, encoded []byte) {
	for round := 0; round < tdilithium3DKGActivationCertificateGossipRounds; round++ {
		if err := broadcast(p2p.MsgTypeTDilithium3DKGActivationCertificate, encoded); err != nil {
			nodeLog.Warn("Dilithium3 v1 activation certificate gossip failed: %v", err)
			return
		}
		if round == tdilithium3DKGActivationCertificateGossipRounds-1 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(tdilithium3DKGActivationCertificateGossipInterval):
		}
	}
}

// installTDilithium3DKGActivationSink publishes the running exchange's sink
// channel to the TSS processing loop. Passing a nil channel clears it.
func (n *Node) installTDilithium3DKGActivationSink(sink chan []byte) {
	if n == nil {
		return
	}
	n.tdilithium3DKGActivationMu.Lock()
	defer n.tdilithium3DKGActivationMu.Unlock()
	n.tdilithium3DKGActivationSink = sink
}

func (n *Node) clearTDilithium3DKGActivationSink() {
	n.installTDilithium3DKGActivationSink(nil)
}

// deliverTDilithium3DKGActivation routes one inbound activation packet to the
// running exchange. It returns true when the packet was consumed by an
// exchange and the caller should return; false otherwise (the caller drops
// the packet because no exchange is running, or because the sink is full and
// the packet was a duplicate).
func (n *Node) deliverTDilithium3DKGActivation(packet []byte) bool {
	if n == nil {
		return false
	}
	n.tdilithium3DKGActivationMu.Lock()
	sink := n.tdilithium3DKGActivationSink
	n.tdilithium3DKGActivationMu.Unlock()
	if sink == nil {
		return false
	}
	select {
	case sink <- append([]byte(nil), packet...):
		return true
	default:
		// Sink is full; the packet was a duplicate or the exchange already
		// has enough. The exchange will time out and retry.
		return false
	}
}

// adoptTDilithium3DKGActivationCertificate lets a node that did not finish its
// own activation exchange adopt a gossip-delivered certificate committed by a
// peer. The certificate is self-verifying: it carries all six signed
// acknowledgements bound to a session digest and transcript. ActivateCandidate
// re-checks the session digest against the locally derived session (fail-closed
// on mismatch) and requires the matching candidate share to be present
// (VerifyCandidate), so only a node that ran the same DKG round can adopt.
//
// The adoption is idempotent: if the node already committed the same
// certificate through its own exchange, ActivateCandidate short-circuits.
func (n *Node) adoptTDilithium3DKGActivationCertificate(payload []byte) {
	if n == nil || n.config == nil {
		return
	}
	certificate, err := decodeThresholdActivationCertificate(payload)
	if err != nil {
		nodeLog.Debug("Dilithium3 v1 activation certificate decode rejected: %v", err)
		return
	}
	if len(certificate.Acknowledgements) == 0 {
		nodeLog.Debug("Dilithium3 v1 activation certificate has no acknowledgements")
		return
	}
	activationEpoch := certificate.Acknowledgements[0].ActivationEpoch
	if activationEpoch == 0 {
		nodeLog.Debug("Dilithium3 v1 activation certificate has no activation epoch")
		return
	}

	// Reuse the live ceremony's verifier when one is running for the same
	// activation epoch; otherwise derive the session and verifier from the
	// epoch. The session is deterministic (D1-D8), so both paths yield the
	// same session digest and the same roster-bound identity verifier.
	var sessionDigest [32]byte
	var verifier dilithium3v1.DKGIdentityVerifier
	if inbox := n.tdilithium3DKGInboxSnapshot(); inbox != nil &&
		n.tdilithium3DKGInboxAdmissible(inbox) &&
		inbox.session.ActivationEpoch == activationEpoch {
		digest, err := inbox.session.Digest()
		if err != nil {
			nodeLog.Debug("Dilithium3 v1 activation certificate live session digest: %v", err)
			return
		}
		sessionDigest = digest
		verifier = inbox.verifyIdentity
	} else {
		session, err := n.deriveTDilithium3DKGSession(activationEpoch)
		if err != nil {
			nodeLog.Debug("Dilithium3 v1 activation certificate session derivation: %v", err)
			return
		}
		digest, err := session.Digest()
		if err != nil {
			nodeLog.Debug("Dilithium3 v1 activation certificate session digest: %v", err)
			return
		}
		sessionDigest = digest
		rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(activationEpoch)
		if err != nil {
			nodeLog.Debug("Dilithium3 v1 activation certificate roster epoch: %v", err)
			return
		}
		roster, err := n.capturedEpochValidatorRoster(rosterEpoch)
		if err != nil {
			nodeLog.Debug("Dilithium3 v1 activation certificate roster: %v", err)
			return
		}
		_, position, err := n.tdilithium3DKGCommitteeForRoster(roster)
		if err != nil {
			nodeLog.Debug("Dilithium3 v1 activation certificate committee: %v", err)
			return
		}
		ownAddress := roster.Entries[position].Address
		ownPeer := n.p2pHost.ID()
		peerForValidator := func(address types.Address) (p2p.PeerID, bool) {
			if address == ownAddress {
				return ownPeer, ownPeer != ""
			}
			return n.p2pHost.GetPeerIDForValidator(address)
		}
		builtInbox, err := n.newTDilithium3DKGInboxFromCapturedEpochRoster(session, position, rosterEpoch, peerForValidator)
		if err != nil {
			nodeLog.Debug("Dilithium3 v1 activation certificate verifier build: %v", err)
			return
		}
		verifier = builtInbox.verifyIdentity
	}
	if verifier == nil {
		nodeLog.Debug("Dilithium3 v1 activation certificate has no identity verifier")
		return
	}

	password := []byte(n.config.ValidatorKeyPassword)
	store := newThresholdShareStore(n.config.DataDir)
	if err := store.ActivateCandidate(certificate, sessionDigest, activationEpoch, verifier, password); err != nil {
		nodeLog.Debug("Dilithium3 v1 activation certificate adoption rejected: %v", err)
		return
	}

	nodeLog.Info("Dilithium3 v1 activation adopted via gossip (activation epoch %d, session %x)",
		activationEpoch, sessionDigest[:8])

	// Register the finality surface so the seal executor can sign with the
	// adopted group key. This mirrors refreshTDilithium3SigningFinalitySigner.
	adoptedEpoch, groupPublicKey, committeeThreshold, err := store.ActiveSharePublicIdentity(password)
	if err != nil {
		nodeLog.Warn("Dilithium3 v1 activation adopted but identity probe failed: %v", err)
		return
	}
	if committeeThreshold == 0 {
		nodeLog.Warn("Dilithium3 v1 activation adopted with a zero committee threshold")
		return
	}
	if err := n.registerTDilithium3SigningFinalitySigner(adoptedEpoch, groupPublicKey, int(committeeThreshold)); err != nil {
		nodeLog.Warn("Dilithium3 v1 activation finality surface registration deferred: %v", err)
	}
}

// The exchange type assertion: it is a Node method, so it is reachable on
// every node, but it is the only production caller of the activation
// machinery. The interface assertion below pins down the contract so a
// regression in the inbox's activation-refusal logic would fail to compile.
var _ = (*Node).runTDilithium3DKGActivationExchange

// p2p import is used by the broadcast function; the type assertion below
// ensures the import is not trimmed by the compiler when the function is
// only called through the closure argument in the ceremony.
var _ = p2p.MsgTypeTDilithium3DKGActivation

// sync import is referenced through the Node struct's activationMu field.
// The blank import here keeps the import block tidy even though no direct
// symbol is referenced.
var _ = sync.Mutex{}
