// Quantaureum Node source, version 1.0.0.
// Package node implements the ShardBlockProducer for shard chain block production.
//
// P1-2 (2026-07-14): Implements the shard block production loop. Each slot,
// the producer checks all active shards: if this validator is the elected
// proposer for the shard's next block height, it builds, signs, proposes, and
// broadcasts the block. All validators (including the proposer) run loops to
// receive incoming blocks, sign attestations, collect attestations for quorum
// finalization, and relay cross-shard messages.
package node

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
)

// shardProducerLog is the component logger for shard block production.
var shardProducerLog = &Logger{component: "ShardProducer"}

// SHRD- (2026-07-16): Attestation DoS protection constants.
//
// attestationHeightWindow bounds the height range (latest ± window) within
// which incoming attestations are accepted. Heights outside this window are
// rejected immediately, preventing an attacker from flooding the node with
// attestations for arbitrary (e.g., far-future or ancient) heights that
// would never finalize but would grow pendingAttestations unboundedly.
//
// attestationMaxHeightsPerShard bounds the number of distinct heights
// tracked per shard. When exceeded, the oldest heights are pruned.
const (
	attestationHeightWindow       = uint64(64)
	attestationMaxHeightsPerShard = 128
)

// ShardBlockProducer produces shard blocks and processes incoming shard
// protocol messages (blocks, attestations, cross-shard messages).
//
// P1-2 (2026-07-14): Wires the ShardManager into the node's block production
// lifecycle. The producer runs four goroutines after Start():
//
//  1. produceShardBlockLoop — per-slot tick: for each active shard, check if
//     this validator is the elected proposer (via QPOS.GetProposerForSlot).
//     If elected, sign the block header and call ShardChain.ProposeBlock,
//     then broadcast the block via P2P.
//  2. incomingShardBlockLoop — receive shard blocks from P2P, verify via
//     ShardChain.ReceiveBlock, then sign + broadcast an attestation.
//  3. attestationLoop — receive attestations from P2P, accumulate per
//     (shardID, height). When 2/3 quorum is reached, call FinalizeBlock.
//  4. crossShardMessageLoop — receive cross-shard messages from P2P, relay
//     to the destination shard via SubmitCrossShardMessage.
//
// Thread safety: ShardBlockProducer is safe for concurrent use. All shared
// state (pendingAttestations) is protected by a mutex.
//
// P3-1 (2026-07-15): The producer also injects ShardMetrics into each
// ShardChain and records P2P message counters (qau_shard_p2p_messages_total)
// and finalization delay observations (qau_shard_finalization_delay_seconds).
type ShardBlockProducer struct {
	node         *Node
	shardManager *consensus.ShardManager
	qpos         *consensus.QPOS
	p2pHost      *p2p.Host

	// Validator identity (from BlockProducer).
	validatorKey  *crypto.PrivateKey
	validatorAddr types.Address

	// Dependencies to inject into each ShardChain.
	stateStore       *consensus.ShardStateStore
	electionVerifier consensus.ElectionVerifier
	// P3-1 (2026-07-15): metrics is injected into each ShardChain so per-shard
	// events (block height, pending messages) are recorded at the source. May
	// be nil when sharding metrics are disabled.
	metrics *consensus.ShardMetrics

	interval time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	running bool

	// pendingAttestations accumulates attestations per (shardID, height).
	// When the count reaches the 2/3 quorum threshold, FinalizeBlock is called.
	pendingMu           sync.Mutex
	pendingAttestations map[uint64]map[uint64]map[types.Address][]byte // shardID → height → validator → sig

	// P3-1 (2026-07-15): proposedAt records the time each block was first
	// proposed/received, so finalization delay can be observed when
	// FinalizeBlock succeeds. Keyed by (shardID, height).
	proposedMu sync.Mutex
	proposedAt map[uint64]map[uint64]time.Time // shardID → height → proposed time
}

// NewShardBlockProducer creates a new ShardBlockProducer. The producer is
// idle until Start() is called.
//
// Prerequisites: node.blockProducer must be initialized (for validator key
// and QPOS), node.shardManager must be set, and node.p2pHost must be started.
func NewShardBlockProducer(node *Node, interval time.Duration) *ShardBlockProducer {
	if interval == 0 {
		interval = time.Duration(consensus.ShardBlockInterval) * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	sbp := &ShardBlockProducer{
		node:                node,
		shardManager:        node.shardManager,
		qpos:                node.blockProducer.QPOS(),
		p2pHost:             node.p2pHost,
		stateStore:          node.shardStateStore,
		electionVerifier:    node.shardElectionVerifier,
		metrics:             node.shardMetrics,
		interval:            interval,
		ctx:                 ctx,
		cancel:              cancel,
		pendingAttestations: make(map[uint64]map[uint64]map[types.Address][]byte),
		proposedAt:          make(map[uint64]map[uint64]time.Time),
	}

	// Inherit validator identity from BlockProducer.
	if node.blockProducer != nil {
		sbp.validatorKey = node.blockProducer.ValidatorKey()
		sbp.validatorAddr = node.blockProducer.ValidatorAddr()
	}

	return sbp
}

// Start launches the four background goroutines. Returns error if already
// running or if prerequisites are missing.
func (sbp *ShardBlockProducer) Start() error {
	sbp.mu.Lock()
	defer sbp.mu.Unlock()

	if sbp.running {
		return nil
	}

	if sbp.shardManager == nil {
		return fmt.Errorf("shard block producer: shardManager is nil")
	}
	if sbp.qpos == nil {
		return fmt.Errorf("shard block producer: qpos is nil")
	}
	if sbp.p2pHost == nil {
		return fmt.Errorf("shard block producer: p2pHost is nil")
	}
	if sbp.validatorKey == nil {
		shardProducerLog.Warn("ShardBlockProducer starting without validator key (produce-only disabled, receive-only mode)")
	}

	sbp.running = true

	// Inject dependencies into all existing shards (idempotent).
	// P3-1 (2026-07-15): Also inject metrics so per-shard events are recorded.
	for _, chain := range sbp.shardManager.GetActiveShards() {
		chain.InjectDependencies(sbp.stateStore, sbp.electionVerifier)
		if sbp.metrics != nil {
			chain.InjectMetrics(sbp.metrics)
		}
	}

	sbp.wg.Add(4)
	go sbp.produceShardBlockLoop()
	go sbp.incomingShardBlockLoop()
	go sbp.attestationLoop()
	go sbp.crossShardMessageLoop()

	shardProducerLog.Info("ShardBlockProducer started (interval=%v, validator=%x)",
		sbp.interval, sbp.validatorAddr[:8])
	return nil
}

// Stop signals all goroutines to exit and waits for them to finish.
func (sbp *ShardBlockProducer) Stop() {
	sbp.mu.Lock()
	defer sbp.mu.Unlock()

	if !sbp.running {
		return
	}

	sbp.cancel()
	sbp.wg.Wait()
	sbp.running = false
	shardProducerLog.Info("ShardBlockProducer stopped")
}

// --- Wire format structs for P2P serialization ---

// shardBlockWire is the JSON wire format for consensus.ShardBlock.
type shardBlockWire struct {
	ShardID      uint64                         `json:"shard_id"`
	Height       uint64                         `json:"height"`
	ParentHash   types.Hash                     `json:"parent_hash"`
	StateRoot    types.Hash                     `json:"state_root"`
	TxRoot       types.Hash                     `json:"tx_root"`
	CrossMsgRoot types.Hash                     `json:"cross_msg_root"`
	Timestamp    uint64                         `json:"timestamp"`
	Proposer     types.Address                  `json:"proposer"`
	Signature    []byte                         `json:"signature"`
	VRFProof     []byte                         `json:"vrf_proof"`
	VRFOutput    types.Hash                     `json:"vrf_output"`
	Txs          [][]byte                       `json:"txs"`
	CrossMsgs    []*consensus.CrossShardMessage `json:"cross_msgs"`
}

func encodeShardBlock(block *consensus.ShardBlock) ([]byte, error) {
	w := shardBlockWire{
		ShardID:      block.Header.ShardID,
		Height:       block.Header.Height,
		ParentHash:   block.Header.ParentHash,
		StateRoot:    block.Header.StateRoot,
		TxRoot:       block.Header.TxRoot,
		CrossMsgRoot: block.Header.CrossMsgRoot,
		Timestamp:    block.Header.Timestamp,
		Proposer:     block.Header.Proposer,
		Signature:    block.Header.Signature,
		VRFProof:     block.Header.VRFProof,
		VRFOutput:    block.Header.VRFOutput,
		Txs:          block.Txs,
		CrossMsgs:    block.CrossMsgs,
	}
	return json.Marshal(w)
}

func decodeShardBlock(data []byte) (*consensus.ShardBlock, error) {
	var w shardBlockWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("decode shard block: %w", err)
	}
	return &consensus.ShardBlock{
		Header: &consensus.ShardBlockHeader{
			ShardID:      w.ShardID,
			Height:       w.Height,
			ParentHash:   w.ParentHash,
			StateRoot:    w.StateRoot,
			TxRoot:       w.TxRoot,
			CrossMsgRoot: w.CrossMsgRoot,
			Timestamp:    w.Timestamp,
			Proposer:     w.Proposer,
			Signature:    w.Signature,
			VRFProof:     w.VRFProof,
			VRFOutput:    w.VRFOutput,
		},
		Txs:       w.Txs,
		CrossMsgs: w.CrossMsgs,
	}, nil
}

// shardAttestationWire is the JSON wire format for a single block attestation.
type shardAttestationWire struct {
	ShardID   uint64        `json:"shard_id"`
	Height    uint64        `json:"height"`
	Validator types.Address `json:"validator"`
	Signature []byte        `json:"signature"`
}

func encodeShardAttestation(shardID, height uint64, validator types.Address, sig []byte) ([]byte, error) {
	w := shardAttestationWire{
		ShardID:   shardID,
		Height:    height,
		Validator: validator,
		Signature: sig,
	}
	return json.Marshal(w)
}

func decodeShardAttestation(data []byte) (uint64, uint64, types.Address, []byte, error) {
	var w shardAttestationWire
	if err := json.Unmarshal(data, &w); err != nil {
		return 0, 0, types.Address{}, nil, fmt.Errorf("decode shard attestation: %w", err)
	}
	return w.ShardID, w.Height, w.Validator, w.Signature, nil
}

// --- Goroutines ---

// produceShardBlockLoop ticks every interval and checks if this validator
// should produce a block for any active shard.
func (sbp *ShardBlockProducer) produceShardBlockLoop() {
	defer sbp.wg.Done()

	ticker := time.NewTicker(sbp.interval)
	defer ticker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			shardProducerLog.Error("panic in produceShardBlockLoop: %v", r)
		}
	}()

	for {
		select {
		case <-sbp.ctx.Done():
			return
		case <-ticker.C:
			sbp.tryProduceAllShards()
		}
	}
}

// tryProduceAllShards iterates over all active shards and attempts block
// production for each.
func (sbp *ShardBlockProducer) tryProduceAllShards() {
	if sbp.validatorKey == nil {
		return // no validator key, cannot produce
	}

	shards := sbp.shardManager.GetActiveShards()
	for _, chain := range shards {
		sbp.tryProduceShardBlock(chain)
	}
}

// tryProduceShardBlock checks if this validator is the elected proposer for
// the shard's next block height. If so, it signs, proposes, and broadcasts.
func (sbp *ShardBlockProducer) tryProduceShardBlock(chain *consensus.ShardChain) {
	shardID := chain.ShardID()
	nextHeight := chain.LatestHeight() + 1

	// Map shard height → mainchain slot. With the default 1:1 resolver,
	// slot == height. The ShardQPOSAdapter uses the same mapping.
	slot := nextHeight

	proposer, err := sbp.qpos.GetProposerForSlot(slot)
	if err != nil {
		shardProducerLog.Debug("shard %d: no proposer for slot %d: %v", shardID, slot, err)
		return
	}
	if proposer == nil {
		return
	}

	// Only produce if this node is the elected proposer.
	if proposer.Address != sbp.validatorAddr {
		return
	}

	// Check this validator is assigned to this shard.
	validators := chain.Validators()
	assigned := false
	for _, v := range validators {
		if v == sbp.validatorAddr {
			assigned = true
			break
		}
	}
	if !assigned {
		shardProducerLog.Warn("shard %d: elected proposer %x but not assigned to shard", shardID, sbp.validatorAddr[:8])
		return
	}

	// Compute signing hash and sign.
	// Note: VRF proof/output are nil/zero because ShardQPOSAdapter ignores them
	// (it delegates to QPOS.GetProposerForSlot which performs its own election).
	// If a ShardElectionVerifier is used instead, real VRF proofs must be generated.
	var vrfProof []byte // nil — ShardQPOSAdapter ignores this
	var vrfOutput types.Hash

	signingHash, err := chain.PrepareBlockSigningHash(sbp.validatorAddr, nil, nil)
	if err != nil {
		shardProducerLog.Warn("shard %d: PrepareBlockSigningHash failed: %v", shardID, err)
		return
	}

	signature, err := crypto.Sign(sbp.validatorKey, signingHash)
	if err != nil {
		shardProducerLog.Warn("shard %d: sign block failed: %v", shardID, err)
		return
	}

	// Propose the block. ProposeBlock verifies the signature + election internally.
	block, err := chain.ProposeBlock(sbp.validatorAddr, nil, nil, signature, vrfProof, vrfOutput)
	if err != nil {
		shardProducerLog.Warn("shard %d: ProposeBlock failed: %v", shardID, err)
		return
	}

	shardProducerLog.Info("shard %d: produced block height %d (slot %d)", shardID, block.Header.Height, slot)

	// P3-1 (2026-07-15): Record proposal time for finalization delay.
	sbp.recordProposed(shardID, block.Header.Height)

	// Broadcast the block to the network.
	data, err := encodeShardBlock(block)
	if err != nil {
		shardProducerLog.Warn("shard %d: encode block failed: %v", shardID, err)
		return
	}
	if err := sbp.p2pHost.BroadcastShardBlock(data); err != nil {
		shardProducerLog.Warn("shard %d: broadcast block failed: %v", shardID, err)
	}
}

// incomingShardBlockLoop receives shard blocks from P2P, verifies them, and
// signs + broadcasts an attestation for each verified block.
func (sbp *ShardBlockProducer) incomingShardBlockLoop() {
	defer sbp.wg.Done()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			shardProducerLog.Error("panic in incomingShardBlockLoop: %v", r)
		}
	}()

	if sbp.p2pHost == nil {
		return
	}
	blockCh := sbp.p2pHost.SubscribeShardBlocks()

	for {
		select {
		case <-sbp.ctx.Done():
			return
		case data, ok := <-blockCh:
			if !ok {
				return
			}
			sbp.handleIncomingShardBlock(data)
		}
	}
}

// handleIncomingShardBlock decodes, verifies, stores, and attests to a block.
func (sbp *ShardBlockProducer) handleIncomingShardBlock(data []byte) {
	// P3-1 (2026-07-15): Record P2P message counter.
	if sbp.metrics != nil {
		sbp.metrics.IncP2PMessages("block")
	}

	block, err := decodeShardBlock(data)
	if err != nil {
		shardProducerLog.Warn("decode shard block failed: %v", err)
		return
	}

	chain, err := sbp.shardManager.GetShard(block.Header.ShardID)
	if err != nil {
		shardProducerLog.Warn("shard %d: not found: %v", block.Header.ShardID, err)
		return
	}

	// Inject dependencies (idempotent — needed if shard was created after Start).
	chain.InjectDependencies(sbp.stateStore, sbp.electionVerifier)
	if sbp.metrics != nil {
		chain.InjectMetrics(sbp.metrics)
	}

	// Verify and store the block.
	if err := chain.ReceiveBlock(block); err != nil {
		shardProducerLog.Warn("shard %d: receive block height %d failed: %v",
			block.Header.ShardID, block.Header.Height, err)
		return
	}

	// P3-1 (2026-07-15): Record proposal time for finalization delay.
	sbp.recordProposed(block.Header.ShardID, block.Header.Height)

	shardProducerLog.Info("shard %d: received block height %d from %x",
		block.Header.ShardID, block.Header.Height, block.Header.Proposer[:8])

	// Sign and broadcast an attestation (if this node is a validator for the shard).
	if sbp.validatorKey != nil {
		sbp.signAndBroadcastAttestation(chain, block)
	}
}

// signAndBroadcastAttestation signs the block hash and broadcasts the attestation.
func (sbp *ShardBlockProducer) signAndBroadcastAttestation(chain *consensus.ShardChain, block *consensus.ShardBlock) {
	// Check this node is a validator for the shard.
	validators := chain.Validators()
	isValidator := false
	for _, v := range validators {
		if v == sbp.validatorAddr {
			isValidator = true
			break
		}
	}
	if !isValidator {
		return
	}

	// Get the block to compute the block hash.
	stored, err := chain.GetBlock(block.Header.Height)
	if err != nil {
		shardProducerLog.Warn("shard %d: get block %d for attestation failed: %v",
			chain.ShardID(), block.Header.Height, err)
		return
	}

	// Sign the block hash.
	blockHash := consensus.ComputeShardBlockHashPublic(stored.Header)
	sig, err := crypto.Sign(sbp.validatorKey, blockHash[:])
	if err != nil {
		shardProducerLog.Warn("shard %d: sign attestation failed: %v", chain.ShardID(), err)
		return
	}

	// Broadcast the attestation.
	data, err := encodeShardAttestation(chain.ShardID(), stored.Header.Height, sbp.validatorAddr, sig)
	if err != nil {
		shardProducerLog.Warn("shard %d: encode attestation failed: %v", chain.ShardID(), err)
		return
	}
	if err := sbp.p2pHost.BroadcastShardAttestation(data); err != nil {
		shardProducerLog.Warn("shard %d: broadcast attestation failed: %v", chain.ShardID(), err)
	}

	// Also add to local pending attestations (so this node's own attestation
	// counts toward quorum).
	sbp.addPendingAttestation(chain.ShardID(), stored.Header.Height, sbp.validatorAddr, sig)
}

// attestationLoop receives attestations from P2P, accumulates them, and
// finalizes blocks when quorum is reached.
func (sbp *ShardBlockProducer) attestationLoop() {
	defer sbp.wg.Done()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			shardProducerLog.Error("panic in attestationLoop: %v", r)
		}
	}()

	if sbp.p2pHost == nil {
		return
	}
	attCh := sbp.p2pHost.SubscribeShardAttestations()

	for {
		select {
		case <-sbp.ctx.Done():
			return
		case data, ok := <-attCh:
			if !ok {
				return
			}
			sbp.handleIncomingAttestation(data)
		}
	}
}

// handleIncomingAttestation decodes an attestation, validates it, and if it
// passes pre-accumulation checks, adds it to the pending map and checks if
// quorum is reached for finalization.
//
// SHRD-FIX (2026-07-16): Previously, attestations from P2P were
// accumulated without any validation, allowing an attacker to flood the node
// with forged attestations from arbitrary addresses. While FinalizeBlock
// internally verifies signatures (so forged attestations cannot finalize a
// block), the unvalidated attestations caused:
//  1. Unbounded memory growth in pendingAttestations (no height window, no
//     per-height capacity limit, no pruning of stale heights).
//  2. CPU amplification: every incoming attestation triggered GetShard +
//     FinalizeBlock (full signature verification over all accumulated
//     attestations).
//
// Fix: validateAttestation performs cheap checks (validator membership,
// height window, signature when block is known) before the expensive
// FinalizeBlock path. addPendingAttestation enforces a per-height capacity
// limit (≤ validator count) and prunes stale heights.
func (sbp *ShardBlockProducer) handleIncomingAttestation(data []byte) {
	// P3-1 (2026-07-15): Record P2P message counter.
	if sbp.metrics != nil {
		sbp.metrics.IncP2PMessages("attestation")
	}

	shardID, height, validator, sig, err := decodeShardAttestation(data)
	if err != nil {
		shardProducerLog.Warn("decode attestation failed: %v", err)
		return
	}

	// SHRD- Pre-validate before accumulating.
	if !sbp.validateAttestation(shardID, height, validator, sig) {
		return
	}

	sbp.addPendingAttestation(shardID, height, validator, sig)
}

// validateAttestation performs pre-accumulation validation of an attestation
// to prevent DoS via anonymous flooding. Returns true if the attestation
// should be accumulated.
//
// SHRD-FIX (2026-07-16). Checks performed (cheap → expensive):
//  1. Shard exists.
//  2. Validator is registered for this shard (has a Dilithium3 public key).
//  3. Height is within attestationHeightWindow of the shard's latest height.
//  4. If the block is already known, verify the attestation signature over
//     the block hash. If the block is not yet known (attestation arrived
//     before the block), accept the attestation — FinalizeBlock will verify
//     the signature when the block is available.
func (sbp *ShardBlockProducer) validateAttestation(shardID, height uint64, validator types.Address, sig []byte) bool {
	chain, err := sbp.shardManager.GetShard(shardID)
	if err != nil {
		shardProducerLog.Debug("attestation: shard %d not found: %v", shardID, err)
		return false
	}

	// Check 1: Validator must be registered for this shard (has a public key).
	pubKeyBytes, ok := chain.ValidatorPubKey(validator)
	if !ok {
		shardProducerLog.Debug("attestation: validator %x not registered for shard %d",
			validator[:8], shardID)
		return false
	}

	// Check 2: Height must be within attestationHeightWindow of the latest
	// height. This rejects far-future and ancient heights that would never
	// finalize but would grow pendingAttestations unboundedly.
	latest := chain.LatestHeight()
	if height > latest+attestationHeightWindow {
		shardProducerLog.Debug("attestation: height %d too far ahead (latest=%d) for shard %d",
			height, latest, shardID)
		return false
	}
	if height+attestationHeightWindow < latest {
		shardProducerLog.Debug("attestation: height %d too old (latest=%d) for shard %d",
			height, latest, shardID)
		return false
	}

	// Check 3: If the block is already known, verify the attestation signature
	// over the block hash. This is the expensive check, so it's done last.
	// If the block is not yet known, accept the attestation — it will be
	// verified by FinalizeBlock when the block arrives.
	block, err := chain.GetBlock(height)
	if err != nil {
		// Block not yet known — accept for now. FinalizeBlock will verify.
		return true
	}

	// Verify the attestation signature over the block hash.
	blockHash := consensus.ComputeShardBlockHashPublic(block.Header)
	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil || pubKey == nil {
		shardProducerLog.Debug("attestation: invalid public key for validator %x on shard %d",
			validator[:8], shardID)
		return false
	}
	if !crypto.Verify(pubKey, blockHash[:], sig) {
		shardProducerLog.Debug("attestation: signature verification failed for validator %x on shard %d height %d",
			validator[:8], shardID, height)
		return false
	}

	return true
}

// addPendingAttestation adds an attestation to the pending map and checks
// if quorum is reached. If so, calls FinalizeBlock.
//
// SHRD-FIX (2026-07-16): Enforces per-height capacity limit (≤
// validator count) and prunes stale heights beyond
// attestationMaxHeightsPerShard to bound memory usage.
func (sbp *ShardBlockProducer) addPendingAttestation(shardID, height uint64, validator types.Address, sig []byte) {
	sbp.pendingMu.Lock()
	// Initialize nested maps if needed.
	if sbp.pendingAttestations[shardID] == nil {
		sbp.pendingAttestations[shardID] = make(map[uint64]map[types.Address][]byte)
	}
	if sbp.pendingAttestations[shardID][height] == nil {
		sbp.pendingAttestations[shardID][height] = make(map[types.Address][]byte)
	}

	// SHRD- Enforce per-height capacity limit. Each validator can
	// only attest once per height, so the maximum number of attestations
	// per height is the validator count. Rejecting excess attestations
	// prevents an attacker from flooding a single height with forged
	// entries (each forged entry from a non-validator would have been
	// rejected by validateAttestation, but duplicate entries from the
	// same validator could still overwrite and consume map slots).
	if chain, err := sbp.shardManager.GetShard(shardID); err == nil {
		maxAttestations := len(chain.Validators())
		if maxAttestations > 0 && len(sbp.pendingAttestations[shardID][height]) >= maxAttestations {
			sbp.pendingMu.Unlock()
			shardProducerLog.Debug("attestation: per-height capacity (%d) reached for shard %d height %d",
				maxAttestations, shardID, height)
			return
		}
	}

	sbp.pendingAttestations[shardID][height][validator] = sig
	count := len(sbp.pendingAttestations[shardID][height])

	// SHRD- Prune stale heights to bound memory. When the number of
	// tracked heights for this shard exceeds attestationMaxHeightsPerShard,
	// remove the oldest heights. This handles the case where attestations
	// for some heights never reach quorum (e.g., orphaned heights).
	shardMap := sbp.pendingAttestations[shardID]
	if len(shardMap) > attestationMaxHeightsPerShard {
		// Collect and sort heights, then prune the oldest.
		heights := make([]uint64, 0, len(shardMap))
		for h := range shardMap {
			heights = append(heights, h)
		}
		sort.Slice(heights, func(i, j int) bool { return heights[i] < heights[j] })
		// Keep only the most recent attestationMaxHeightsPerShard heights.
		pruneCount := len(heights) - attestationMaxHeightsPerShard
		for i := 0; i < pruneCount; i++ {
			delete(shardMap, heights[i])
		}
	}

	sbp.pendingMu.Unlock()

	// Check if quorum reached.
	sbp.checkQuorumAndFinalize(shardID, height, count)
}

// checkQuorumAndFinalize checks if the attestation count meets the 2/3
// quorum threshold and calls FinalizeBlock if so.
func (sbp *ShardBlockProducer) checkQuorumAndFinalize(shardID, height uint64, count int) {
	chain, err := sbp.shardManager.GetShard(shardID)
	if err != nil {
		return
	}

	validators := chain.Validators()
	total := len(validators)
	if total == 0 {
		return
	}

	// Quorum: ceil(total * 2 / 3) = (total * 2 + 2) / 3
	required := (total*consensus.ShardFinalityQuorumNum + consensus.ShardFinalityQuorumDen - 1) / consensus.ShardFinalityQuorumDen
	if required < 1 {
		required = 1
	}

	if count < required {
		return
	}

	// Gather attestations.
	sbp.pendingMu.Lock()
	attestations := make(map[types.Address][]byte)
	if shardMap, ok := sbp.pendingAttestations[shardID]; ok {
		if heightMap, ok := shardMap[height]; ok {
			for addr, sig := range heightMap {
				attestations[addr] = sig
			}
		}
	}
	sbp.pendingMu.Unlock()

	// Attempt finalization. FinalizeBlock is idempotent (returns nil if
	// already finalized) and verifies all attestations internally.
	if err := chain.FinalizeBlock(height, attestations); err != nil {
		shardProducerLog.Debug("shard %d: finalize block %d failed (may need more attestations): %v",
			shardID, height, err)
		return
	}

	shardProducerLog.Info("shard %d: finalized block height %d (attestations=%d, required=%d)",
		shardID, height, len(attestations), required)

	// P3-1 (2026-07-15): Observe finalization delay (time from proposal to
	// finalization). This measures how long it takes to collect 2/3 quorum.
	sbp.observeFinalization(shardID, height)

	// Clean up pending attestations for this height.
	sbp.pendingMu.Lock()
	if shardMap, ok := sbp.pendingAttestations[shardID]; ok {
		delete(shardMap, height)
	}
	sbp.pendingMu.Unlock()
}

// recordProposed tracks the time a block at (shardID, height) was first
// proposed or received. Used by observeFinalization to compute the delay.
// P3-1 (2026-07-15).
func (sbp *ShardBlockProducer) recordProposed(shardID, height uint64) {
	sbp.proposedMu.Lock()
	defer sbp.proposedMu.Unlock()
	if sbp.proposedAt[shardID] == nil {
		sbp.proposedAt[shardID] = make(map[uint64]time.Time)
	}
	// Only record the first proposal time (idempotent).
	if _, exists := sbp.proposedAt[shardID][height]; !exists {
		sbp.proposedAt[shardID][height] = time.Now()
	}
}

// observeFinalization records the finalization delay for a block if its
// proposal time was tracked. Removes the entry after observing.
// P3-1 (2026-07-15).
func (sbp *ShardBlockProducer) observeFinalization(shardID, height uint64) {
	sbp.proposedMu.Lock()
	var proposed time.Time
	var exists bool
	if shardMap, ok := sbp.proposedAt[shardID]; ok {
		if proposed, exists = shardMap[height]; exists {
			delete(shardMap, height)
		}
	}
	sbp.proposedMu.Unlock()

	if !exists || sbp.metrics == nil {
		return
	}
	sbp.metrics.ObserveFinalizationDelay(time.Since(proposed))
}

// crossShardMessageLoop receives cross-shard messages from P2P and relays
// them to the destination shard.
func (sbp *ShardBlockProducer) crossShardMessageLoop() {
	defer sbp.wg.Done()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			shardProducerLog.Error("panic in crossShardMessageLoop: %v", r)
		}
	}()

	if sbp.p2pHost == nil {
		return
	}
	msgCh := sbp.p2pHost.SubscribeCrossShardMessages()

	for {
		select {
		case <-sbp.ctx.Done():
			return
		case data, ok := <-msgCh:
			if !ok {
				return
			}
			sbp.handleIncomingCrossShardMessage(data)
		}
	}
}

// handleIncomingCrossShardMessage decodes a cross-shard message received from
// P2P and routes it through the correct relay→receipt pipeline.
//
// SHRD-FIX (2026-07-16): Previously this function called
// `chain.SubmitCrossShardMessage(&msg)` on the DESTINATION shard. But
// SubmitCrossShardMessage enforces `msg.SourceShard == sc.shardID`, i.e. it
// expects to be invoked on the SOURCE shard (the shard that originated the
// message). For any real cross-shard message (SourceShard != DestShard) this
// check always fails, so cross-shard delivery was completely broken — every
// incoming P2P cross-shard message was rejected and silently dropped.
//
// Fix: route the message through ShardManager.RelayCrossShardMessage, which
// is the intended entry point for the relay→receipt flow. It verifies the
// sender's signature on the source shard, creates (or returns the existing)
// receipt, and relays it via the main chain. Nodes that only run the
// destination shard will fail with "source shard not found" — this is the
// correct behavior, since only a node that tracks the source shard can
// attest to the message's authenticity.
//
// txHash: P2P messages do not carry the source-shard transaction hash. We
// use the message ID (the canonical hash of the message content, see
// GenerateCrossShardMessageID) as a deterministic stand-in. This keeps the
// receipt's proof verifiable without extending the wire format.
func (sbp *ShardBlockProducer) handleIncomingCrossShardMessage(data []byte) {
	// P3-1 (2026-07-15): Record P2P message counter.
	if sbp.metrics != nil {
		sbp.metrics.IncP2PMessages("cross_msg")
	}

	var msg consensus.CrossShardMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		shardProducerLog.Warn("decode cross-shard message failed: %v", err)
		return
	}

	// SHRD- Reject same-shard "cross-shard" messages — they are
	// either malformed or an attempt to abuse the relay path.
	if msg.SourceShard == msg.DestShard {
		shardProducerLog.Warn("cross-shard message: source == dest shard %d (id=%x)",
			msg.SourceShard, msg.ID[:8])
		return
	}

	// Inject dependencies (idempotent) into both shards so RelayCrossShardMessage
	// can verify signatures and persist receipts on the source shard.
	if sourceChain, err := sbp.shardManager.GetShard(msg.SourceShard); err == nil {
		sourceChain.InjectDependencies(sbp.stateStore, sbp.electionVerifier)
		if sbp.metrics != nil {
			sourceChain.InjectMetrics(sbp.metrics)
		}
	}
	if destChain, err := sbp.shardManager.GetShard(msg.DestShard); err == nil {
		destChain.InjectDependencies(sbp.stateStore, sbp.electionVerifier)
		if sbp.metrics != nil {
			destChain.InjectMetrics(sbp.metrics)
		}
	}

	receipt, err := sbp.shardManager.RelayCrossShardMessage(
		msg.SourceShard, msg.DestShard, &msg, msg.ID,
	)
	if err != nil {
		shardProducerLog.Warn("cross-shard message: relay from shard %d to %d failed: %v (id=%x)",
			msg.SourceShard, msg.DestShard, err, msg.ID[:8])
		return
	}

	shardProducerLog.Info("cross-shard message: relayed from shard %d to %d (id=%x, receipt=%x)",
		msg.SourceShard, msg.DestShard, msg.ID[:8], receipt.MessageID[:8])
}
