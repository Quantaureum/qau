// Quantaureum Node source, version 1.0.0.
package node

import (
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// ============================================================================
// Task 5 — node-layer distributed DKG wiring: DKGCoordinator
//
// The coordinator wires the wallet-layer distributed DKG pieces into the
// TSSManager at node startup when the TSSDistributedDKG switch is enabled
// (non-mainnet only — mainnet is hard-blocked by Config.Validate()):
//
//   - creates a real qtd.DistributedDKGRunner (protocol state machine) bound
//     to the DKG session (sessionID/rho),
//   - creates a P2PDKGTransport (cross-participant message exchange over the
//     P2P network),
//   - injects both into the TSSManager so GenerateKeyShares() takes the
//     multi-party distributed path instead of the single-process simulated
//     trusted-dealer path.
//
// When TSSDistributedDKG is OFF (default), no coordinator is created and node
// behavior is identical to previous releases.
// ============================================================================

// DKGCoordinator owns the distributed DKG wiring for this node. It is only
// ever constructed when the TSSDistributedDKG switch is enabled.
type DKGCoordinator struct {
	mgr       *tss.TSSManager
	transport *P2PDKGTransport
	sessionID []byte
	rho       [32]byte
}

// NewCoordinator constructs a DKGCoordinator for the given TSSManager and
// DKG round participant ID (1-based), and immediately wires a real runner +
// P2P transport into the manager so GenerateKeyShares() takes the
// multi-party distributed path.
//
// sessionID/rho must be agreed across all participants before starting the
// round; the node layer derives them from the genesis hash so all validators
// agree. host may be nil (outbound sends then fail closed with a clear
// error). Returns nil when mgr is nil.
func NewCoordinator(mgr *tss.TSSManager, participantID int, sessionID []byte, rho [32]byte, host *p2p.Host) *DKGCoordinator {
	if mgr == nil {
		return nil
	}
	c := &DKGCoordinator{
		mgr:       mgr,
		sessionID: append([]byte(nil), sessionID...),
		rho:       rho,
		transport: NewP2PDKGTransport(host, participantID, sessionID),
	}
	// Inject the real distributed runner + transport so GenerateKeyShares()
	// takes the multi-party distributed path.
	mgr.SetDistributedDKGRunner(qtd.NewRealDistributedDKGRunner(c.sessionID, c.rho))
	mgr.SetDKGTransport(c.transport)
	return c
}

// Transport returns the P2P DKG transport this coordinator created and
// injected. It is used by handleTSSMessage to route incoming DKG round
// messages (IngestCommitment / IngestShare) and by the node layer to install
// the participantID → peer resolver.
func (c *DKGCoordinator) Transport() *P2PDKGTransport {
	return c.transport
}

// SessionID returns the DKG session ID the coordinator bound to.
func (c *DKGCoordinator) SessionID() []byte {
	return append([]byte(nil), c.sessionID...)
}

// wireDKGCoordinator builds and wires the distributed DKG coordinator when
// the TSSDistributedDKG switch is enabled. It derives the DKG session binding
// (sessionID/rho) from the genesis hash so all participants agree on the same
// round parameters, resolves this node's participant ID (1-based validator
// index; falls back to 1 when the validator set is not yet available — the
// block producer initializes after initRPC), and installs the
// participantID → P2P peer resolver so private shares are delivered
// point-to-point (never broadcast). Returns nil when no TSSManager is present.
func (n *Node) wireDKGCoordinator() *DKGCoordinator {
	if n.tssManager == nil {
		return nil
	}
	pid := n.getMyParticipantID()
	if pid < 1 {
		pid = 1
	}
	var sessionID []byte
	var rho [32]byte
	if n.genesisBlock != nil {
		gh := block.ComputeBlockHash(n.genesisBlock.Header)
		sessionID = gh[:]
		copy(rho[:], gh[:32])
	} else {
		// No genesis (should not happen in practice): use a fixed session
		// label so all participants still agree on the same round binding.
		sessionID = []byte("quantaureum-distributed-dkg-v1")
		copy(rho[:], sessionID[:32])
	}
	c := NewCoordinator(n.tssManager, pid, sessionID, rho, n.p2pHost)
	if c == nil {
		return nil
	}
	c.Transport().SetPeerResolver(func(participantID int) (p2p.PeerID, bool) {
		return n.peerIDForDKGParticipant(participantID)
	})
	return c
}

// peerIDForDKGParticipant maps a DKG participant ID (1-based validator index)
// to its P2P peer ID for point-to-point share delivery. Fail-closed: returns
// false when the validator set or peer mapping is unavailable — private DKG
// shares must never fall back to broadcast.
func (n *Node) peerIDForDKGParticipant(participantID int) (p2p.PeerID, bool) {
	if n.p2pHost == nil || n.blockProducer == nil || n.blockProducer.qpos == nil {
		return "", false
	}
	vs := n.blockProducer.qpos.GetValidatorSet()
	if vs == nil {
		return "", false
	}
	validators := vs.Validators()
	if participantID < 1 || participantID > len(validators) {
		return "", false
	}
	return n.p2pHost.GetPeerIDForValidator(validators[participantID-1].Address)
}
