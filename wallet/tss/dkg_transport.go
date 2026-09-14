// Quantaureum Node source, version 1.0.0.
package tss

import (
	"crypto/sha256"
	"fmt"

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// ============================================================================
// Task 3 (TSS-R7-01 closure) — DKGTransport: the cross-party message-exchange abstraction for distributed DKG
//
// The previous task implemented the real distributed DKG runner in wallet/tss/qtd/dkg_distributed.go
// (NewRealDistributedDKGRunner, a transport-agnostic pure state machine). This file wires the TSSManager's
// GenerateKeyShares to that runner: when a runner + transport are injected, it drives the real multi-round
// distributed DKG; without injection it takes the original simulated path (zero behavior change).
//
// DKGTransport abstracts cross-process message exchange:
//   - one's own commitment goes to all other parties via SendCommitment, and
//     WaitCommitments collects the others' commitments;
//   - one's share open messages go to each recipient via SendShare, and WaitShares
//     collects the shares others sent.
//
// Session parameters (sessionID/rho) are aligned by the deployer when constructing each runner; the manager does not manage them.
// The node layer (node/) provides the production P2P implementation; tests use an in-process bus.
// ============================================================================

// DKGTransport is the cross-party message-exchange abstraction for distributed DKG.
type DKGTransport interface {
	// ParticipantID returns this party's participant ID (1..TotalShares) in the current DKG round.
	ParticipantID() int
	// SendCommitment sends one's own Round1 commitment to peerID.
	SendCommitment(peerID int, msg *qtd.Round1CommitmentMessage) error
	// SendShare sends the Round1OpenMessage (containing the recipient's dedicated share) to peerID.
	SendShare(peerID int, msg *qtd.Round1OpenMessage) error
	// WaitCommitments blocks until all total-1 commitments from others have arrived.
	WaitCommitments(total int) (map[int]*qtd.Round1CommitmentMessage, error)
	// WaitShares blocks until all total-1 share messages from others have arrived.
	WaitShares(total int) (map[int]*qtd.Round1OpenMessage, error)
}

// SetDKGTransport injects the cross-party DKG message transport (nil by default). In distributed-DKG mode
// it must be injected together with SetDistributedDKGRunner: the runner owns the protocol state machine, the transport
// owns message exchange. Missing either, GenerateKeyShares() cannot take the distributed path.
//
// Passing nil clears the injected transport.
func (m *TSSManager) SetDKGTransport(t DKGTransport) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dkgTransport = t
}

// generateKeySharesDistributed drives the injected qtd.DistributedDKGRunner through the full
// multi-round distributed DKG (Task 3 / TSS-R7-01 closure).
//
// Unlike the simulated path (GenerateDKGDistributedSimulated returns all shares),
// in distributed mode each TSSManager holds only "its own" share:
//   - m.qtdShares / shareCommitments / fullShareCommitments contain only this party's pid;
//   - the returned []*KeyShare contains only this party's own share.
//
// Protocol flow (self-delivery follows the same path per runner semantics; the gate opens only after
// collecting total distinct pids; commitments/shares are deduplicated by pid):
//
//	InitiateRound1(myPid, threshold, total)
//	→ broadcast one's own commitment (to everyone except oneself)
//	→ WaitCommitments collects the others' commitments
//	→ SubmitCommitment (self + others) (self-delivery)
//	→ InitiateRound2() yields the Round1OpenMessages for each recipient
//	→ SendShare delivers to each recipient (one's own copy is left for self-delivery)
//	→ WaitShares collects the others' shares
//	→ SubmitShare (self + others)
//	→ Finalize() produces the DKGResult
//
// REQUIRES dkgTransport to be injected; otherwise returns a clear error saying to inject a DKGTransport.
func (m *TSSManager) generateKeySharesDistributed() ([]*KeyShare, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.config.Threshold < 2 {
		return nil, fmt.Errorf(
			"TSS-R6-01: distributed DKG (the default path) requires threshold >= 2 "+
				"for security (got %d). With threshold=1, a single share contains the "+
				"full key, so distributed DKG provides no security benefit. For T=1 "+
				"configurations, use GenerateKeySharesTrustedDealer() with "+
				"QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1 (air-gapped ceremony only).",
			m.config.Threshold)
	}

	if len(m.config.Seed) > 0 {
		return nil, fmt.Errorf(
			"TSS-R6-01: distributed DKG (the default path) does not support " +
				"deterministic seed input. The whole point of distributed DKG is that " +
				"no single party controls the seed. Use GenerateKeySharesTrustedDealer() " +
				"if you need seeded key generation (requires " +
				"QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1).")
	}

	if m.dkgTransport == nil {
		return nil, fmt.Errorf(
			"TSS-R7-07: a DistributedDKGRunner is injected but no DKGTransport is " +
				"injected via SetDKGTransport. Distributed DKG requires BOTH a runner " +
				"(protocol state machine) and a transport (cross-participant message " +
				"exchange). Inject a DKGTransport (P2P in node/, in-process bus in tests) " +
				"before calling GenerateKeyShares.")
	}

	threshold := m.config.Threshold
	total := m.config.TotalShares
	myPid := m.dkgTransport.ParticipantID()

	// Round 1: sample local secrets and broadcast the commitment (self-delivery follows the same path).
	myCommitment, err := m.dkgRunner.InitiateRound1(myPid, threshold, total)
	if err != nil {
		return nil, fmt.Errorf("distributed DKG round1: %w", err)
	}
	for peer := 1; peer <= total; peer++ {
		if peer == myPid {
			continue
		}
		if err := m.dkgTransport.SendCommitment(peer, myCommitment); err != nil {
			return nil, fmt.Errorf("distributed DKG: send commitment to pid %d: %w", peer, err)
		}
	}
	othersCommitments, err := m.dkgTransport.WaitCommitments(total)
	if err != nil {
		return nil, fmt.Errorf("distributed DKG round1: %w", err)
	}
	if err := m.dkgRunner.SubmitCommitment(myCommitment); err != nil {
		return nil, fmt.Errorf("distributed DKG: submit self commitment: %w", err)
	}
	for pid, msg := range othersCommitments {
		if err := m.dkgRunner.SubmitCommitment(msg); err != nil {
			return nil, fmt.Errorf("distributed DKG: submit commitment from pid %d: %w", pid, err)
		}
		if err := m.dkgRunner.VerifyCommitment(msg); err != nil {
			return nil, fmt.Errorf("distributed DKG: verify commitment from pid %d: %w", pid, err)
		}
	}

	// Round 2: open the commitment and deliver each recipient's share via the transport.
	opens, err := m.dkgRunner.InitiateRound2()
	if err != nil {
		return nil, fmt.Errorf("distributed DKG round2: %w", err)
	}
	for recipient, msg := range opens {
		if recipient == myPid {
			continue
		}
		if err := m.dkgTransport.SendShare(recipient, msg); err != nil {
			return nil, fmt.Errorf("distributed DKG: send share to pid %d: %w", recipient, err)
		}
	}
	othersShares, err := m.dkgTransport.WaitShares(total)
	if err != nil {
		return nil, fmt.Errorf("distributed DKG round2: %w", err)
	}
	if selfOpen, ok := opens[myPid]; ok {
		if err := m.dkgRunner.SubmitShare(selfOpen); err != nil {
			return nil, fmt.Errorf("distributed DKG: submit self share: %w", err)
		}
	}
	for pid, msg := range othersShares {
		if err := m.dkgRunner.SubmitShare(msg); err != nil {
			return nil, fmt.Errorf("distributed DKG: submit share from pid %d: %w", pid, err)
		}
	}

	// Finalize: aggregate shares into this party's global share and the group public key.
	res, err := m.dkgRunner.Finalize()
	if err != nil {
		return nil, fmt.Errorf("distributed DKG finalize: %w", err)
	}
	if res == nil || res.GroupPublicKey == nil || res.MyShare == nil {
		return nil, fmt.Errorf("distributed DKG finalize: nil result from runner")
	}

	m.qtdPubKey = res.GroupPublicKey
	m.groupPubKey = make([]byte, len(res.GroupPublicKey.PubKey))
	copy(m.groupPubKey, res.GroupPublicKey.PubKey)

	// Distributed mode: this manager holds only its own share.
	pid := res.MyShare.ParticipantID
	m.qtdShares = make(map[int]*qtd.QTDShare, 1)
	m.qtdShares[pid] = res.MyShare
	h := sha256.Sum256(res.MyShare.S1ShareBytes)
	m.shareCommitments = make(map[int][]byte, 1)
	m.shareCommitments[pid] = h[:]
	m.fullShareCommitments = make(map[int][]byte, 1)
	m.fullShareCommitments[pid] = computeFullShareCommitment(res.MyShare)

	return []*KeyShare{{
		Index:              pid,
		Share:              res.MyShare.S1ShareBytes,
		PublicKey:          m.groupPubKey,
		VerificationVector: res.MyShare.VVector,
	}}, nil
}
