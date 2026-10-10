// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// reshareRunTimeout bounds one epoch rotation end to end. It must exceed the
// transport wait (reshareDefaultWaitTimeout) plus sub-share generation.
const reshareRunTimeout = 75 * time.Second

// nodeConsensusDKGRunner is the node-side implementation of the consensus
// DKG/reshare runner interfaces. Consensus calls it from a background
// goroutine (see ThreeChambersCoordinator.runEpochReshare) so the network
// rounds never run under the node or QPOS locks.
type nodeConsensusDKGRunner struct {
	node *Node
}

func (r *nodeConsensusDKGRunner) RunDistributedDKG(epoch uint64, threshold, total int) ([]byte, error) {
	if r == nil || r.node == nil {
		return nil, fmt.Errorf("consensus DKG runner is not wired")
	}
	// Offline-ceremony sealing (the mainnet-legal path): once the configured
	// activation epoch is reached, the epoch's group key comes from the
	// adopted offline share — no runtime DKG ceremony ever runs here.
	if r.node.config != nil && r.node.config.TSSV1SealingActivationEpoch > 0 && epoch >= r.node.config.TSSV1SealingActivationEpoch {
		publicKey, handled, err := r.node.offlineTDilithium3AdoptionGroupKey(context.Background(), epoch)
		if err != nil {
			return nil, err
		}
		if handled {
			return publicKey[:], nil
		}
	}
	// Dilithium3 v1 CNF-RSS: with the experimental gate open for this network
	// (mainnet additionally requires the QAU_ENABLE_TDILITHIUM3_V1_MAINNET
	// acknowledgement) the epoch transition is served by the v1 ceremony. There
	// is deliberately no fallback to the legacy group key: activating the
	// chamber with a key the v1 committee holds no shares for would be worse
	// than failing the transition (session-derivation design, D8).
	if r.node.config != nil && experimentalTDilithium3V1EnabledForNetwork(r.node.config.NetworkID) {
		publicKey, err := r.node.runTDilithium3DKGCeremony(context.Background(), epoch)
		if err != nil {
			return nil, err
		}
		return publicKey[:], nil
	}
	if r.node.tssManager == nil {
		return nil, fmt.Errorf("consensus DKG runner is not wired")
	}
	if !r.node.tssManager.HasGroupPublicKey() {
		return nil, fmt.Errorf("initial distributed DKG is still pending")
	}
	return r.node.tssManager.GroupPublicKey(), nil
}

func (r *nodeConsensusDKGRunner) RunDistributedReshare(epoch uint64, oldParticipantIDs, newParticipantIDs []int, threshold int) ([]byte, error) {
	if r == nil || r.node == nil {
		return nil, fmt.Errorf("consensus reshare runner is not wired")
	}
	return r.node.runDistributedReshare(epoch, oldParticipantIDs, newParticipantIDs, threshold)
}

var _ consensus.DistributedDKGRunner = (*nodeConsensusDKGRunner)(nil)
var _ consensus.DistributedReshareRunner = (*nodeConsensusDKGRunner)(nil)

func (n *Node) runDistributedReshare(epoch uint64, requestedOldIDs, requestedNewIDs []int, threshold int) ([]byte, error) {
	if n.blockProducer == nil {
		return nil, fmt.Errorf("reshare requires a block producer")
	}
	if request, handled, err := n.activeTMLDSAReshareRunRequest(
		epoch,
		requestedOldIDs,
		requestedNewIDs,
		threshold,
	); err != nil {
		return nil, err
	} else if handled {
		baseContext := n.ctx
		if baseContext == nil {
			baseContext = context.Background()
		}
		ctx, cancel := context.WithTimeout(baseContext, reshareRunTimeout)
		defer cancel()
		if err := n.runTMLDSAReshareV1(ctx, request); err != nil {
			return nil, err
		}
		return append([]byte(nil), request.Key.PublicKey...), nil
	}
	if n.tssManager == nil {
		return nil, fmt.Errorf("legacy reshare requires a TSS manager")
	}
	if threshold < 2 || len(requestedNewIDs) < threshold {
		return nil, fmt.Errorf("invalid reshare threshold %d for %d new participants", threshold, len(requestedNewIDs))
	}

	normalizeParticipants := func(ids []int) ([]int, error) {
		result := append([]int(nil), ids...)
		sort.Ints(result)
		for i, id := range result {
			if id <= 0 || (i > 0 && result[i-1] == id) {
				return nil, fmt.Errorf("invalid or duplicate participant ID %d", id)
			}
		}
		return result, nil
	}
	newIDs, err := normalizeParticipants(requestedNewIDs)
	if err != nil {
		return nil, err
	}
	// Consensus tracks the holder set deterministically from the committee
	// schedule, so its view is authoritative and identical on every node.
	// The manager's own record is only a fallback for callers that do not
	// track holders (tests, tooling).
	oldIDs, err := normalizeParticipants(requestedOldIDs)
	if err != nil {
		return nil, err
	}
	if len(oldIDs) == 0 {
		if known, ok := n.tssManager.ActiveParticipantIDs(); ok {
			oldIDs = known
		} else {
			oldIDs = n.tssManager.ParticipantIDs()
		}
	}
	if len(oldIDs) < 2 {
		return nil, fmt.Errorf("old share set has %d participants, need at least 2", len(oldIDs))
	}
	if sameParticipants(oldIDs, newIDs) && n.tssManager.Threshold() == threshold {
		return n.tssManager.GroupPublicKey(), nil
	}

	participantID := n.getMyParticipantID()
	if participantID < 1 {
		return nil, fmt.Errorf("local validator participant ID is not available")
	}
	sessionID := n.reshareSessionID(epoch, oldIDs, newIDs, threshold)
	transport := NewP2PReshareTransport(n.p2pHost, participantID, sessionID)
	// Snapshot-based resolver: never resolves through consensus locks while
	// the rotation runs (see snapshotDKGPeerResolver).
	transport.SetPeerResolver(n.snapshotDKGPeerResolver())

	n.reshareRunMu.Lock()
	defer n.reshareRunMu.Unlock()
	ctx, cancel := context.WithTimeout(n.ctx, reshareRunTimeout)
	defer cancel()
	n.attachReshareTransport(transport)
	defer n.detachReshareTransport(transport)
	journalOutbound, journalInbound, journalErr := n.loadReshareJournal(sessionID)
	if journalErr != nil {
		return nil, fmt.Errorf("load reshare journal: %w", journalErr)
	}
	if len(journalOutbound) != 0 || len(journalInbound) != 0 {
		nodeLog.Info("Reshare journal restored (outbound=%d inbound=%d)", len(journalOutbound), len(journalInbound))
	}
	for _, message := range journalInbound {
		if !transport.Ingest(message) {
			return nil, fmt.Errorf("invalid durable inbound reshare contribution from participant %d", message.FromParticipant)
		}
	}

	groupKeyData, keyErr := n.tssManager.GroupPublicKeyData()
	if keyErr != nil && n.tssManager.HasGroupPublicKey() {
		return nil, fmt.Errorf("export current group public key: %w", keyErr)
	}

	localContributions := make(map[int]*qtd.SubShare)
	outbound := make([]*reshareWireMessage, 0, len(newIDs))
	if containsInt(oldIDs, participantID) {
		prepared := journalOutbound
		if len(prepared) == 0 {
			contributions, prepareErr := n.tssManager.PrepareReshare(participantID, newIDs, threshold)
			if prepareErr != nil {
				return nil, prepareErr
			}
			prepared = make([]*reshareWireMessage, 0, len(contributions))
			for _, contribution := range contributions {
				if contribution == nil {
					continue
				}
				prepared = append(prepared, &reshareWireMessage{
					SessionID: sessionID, Epoch: epoch,
					FromParticipant: participantID, ToParticipant: contribution.ToParticipant,
					Threshold: threshold, OldParticipants: append([]int(nil), oldIDs...),
					NewParticipants:    append([]int(nil), newIDs...),
					GroupPublicKeyData: append([]byte(nil), groupKeyData...), Contribution: contribution,
				})
			}
			if err := n.persistOutboundReshareMessages(sessionID, prepared); err != nil {
				return nil, fmt.Errorf("persist prepared reshare contributions: %w", err)
			}
		}
		for _, message := range prepared {
			if message == nil || message.Contribution == nil || !bytes.Equal(message.SessionID, sessionID) ||
				message.Epoch != epoch || message.FromParticipant != participantID ||
				message.Contribution.FromParticipant != participantID || message.Contribution.ToParticipant != message.ToParticipant ||
				message.Threshold != threshold || !sameParticipants(message.OldParticipants, oldIDs) ||
				!sameParticipants(message.NewParticipants, newIDs) || !bytes.Equal(message.GroupPublicKeyData, groupKeyData) {
				return nil, fmt.Errorf("durable outbound reshare metadata mismatch")
			}
			contribution := message.Contribution
			localContributions[contribution.ToParticipant] = contribution
			if contribution.ToParticipant == participantID {
				continue
			}
			outbound = append(outbound, message)
		}
	} else if len(journalOutbound) != 0 {
		return nil, fmt.Errorf("non-holder has durable outbound reshare contributions")
	}
	if err := transport.Deliver(ctx, outbound); err != nil {
		return nil, err
	}
	if !containsInt(newIDs, participantID) {
		if err := n.tssManager.RetireResharedShare(newIDs, threshold); err != nil {
			return nil, err
		}
		if err := n.persistTSSKeyState(); err != nil {
			return nil, fmt.Errorf("persist retired reshare state: %w", err)
		}
		if err := n.cleanupReshareJournal(sessionID); err != nil {
			nodeLog.Warn("Failed to clean completed reshare journal: %v", err)
		}
		return n.tssManager.GroupPublicKey(), nil
	}

	received, waitErr := transport.Wait(ctx, oldIDs)
	if waitErr != nil && containsInt(newIDs, participantID) {
		return nil, waitErr
	}

	if containsInt(newIDs, participantID) {
		allContributions := make([]*qtd.SubShare, 0, len(oldIDs))
		if local := localContributions[participantID]; local != nil {
			allContributions = append(allContributions, local)
		}
		for senderID, message := range received {
			if message.Epoch != epoch || message.Threshold != threshold ||
				!sameParticipants(message.OldParticipants, oldIDs) ||
				!sameParticipants(message.NewParticipants, newIDs) {
				return nil, fmt.Errorf("reshare metadata mismatch from participant %d", senderID)
			}
			if len(message.GroupPublicKeyData) > 0 {
				if len(groupKeyData) == 0 {
					groupKeyData = append([]byte(nil), message.GroupPublicKeyData...)
				} else if !bytes.Equal(groupKeyData, message.GroupPublicKeyData) {
					return nil, fmt.Errorf("reshare group public key mismatch from participant %d", senderID)
				}
			}
			allContributions = append(allContributions, message.Contribution)
		}
		if err := n.tssManager.InstallResharedShare(participantID, newIDs, threshold, oldIDs, allContributions, groupKeyData); err != nil {
			return nil, err
		}
		if err := n.persistTSSKeyState(); err != nil {
			return nil, fmt.Errorf("persist installed reshare state: %w", err)
		}
		n.refreshTSSFinalitySigner()
	}
	if err := n.cleanupReshareJournal(sessionID); err != nil {
		nodeLog.Warn("Failed to clean completed reshare journal: %v", err)
	}
	return n.tssManager.GroupPublicKey(), nil
}

func (n *Node) reshareSessionID(epoch uint64, oldIDs, newIDs []int, threshold int) []byte {
	var base []byte
	if n.genesisBlock != nil {
		h := block.ComputeBlockHash(n.genesisBlock.Header)
		base = h[:]
	} else {
		base = []byte("quantaureum-distributed-reshare-v1")
	}
	h := sha256.New()
	h.Write(base)
	h.Write([]byte("epoch-reshare"))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], epoch)
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(threshold))
	h.Write(buf[:])
	for _, id := range oldIDs {
		binary.BigEndian.PutUint64(buf[:], uint64(id))
		h.Write(buf[:])
	}
	h.Write([]byte{0})
	for _, id := range newIDs {
		binary.BigEndian.PutUint64(buf[:], uint64(id))
		h.Write(buf[:])
	}
	return h.Sum(nil)
}

func sameParticipants(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]int(nil), left...)
	rightCopy := append([]int(nil), right...)
	sort.Ints(leftCopy)
	sort.Ints(rightCopy)
	for i := range leftCopy {
		if leftCopy[i] != rightCopy[i] {
			return false
		}
	}
	return true
}

func containsInt(ids []int, value int) bool {
	for _, id := range ids {
		if id == value {
			return true
		}
	}
	return false
}
