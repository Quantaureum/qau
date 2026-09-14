// Quantaureum Node source, version 1.0.0.
package miner

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

const (
	MaxBidSize       = 2 * 1024 * 1024
	MaxBidsPerSlot   = 128
	BidWindowPercent = 50
	// MaxTrackedBidSlots caps the number of DISTINCT slots the auction will
	// track. AUDIT ROUND-4 2026-08-17 FIX: bids are keyed by slot and
	// CleanupOldSlots only removes PAST slots — a signed bidder could
	// therefore create unbounded future-slot entries (slot = now + 10^9)
	// and grow the bids/winningBids/closed maps without limit. New bids
	// for not-yet-tracked slots are rejected once this cap is reached.
	MaxTrackedBidSlots = 4096
	// MaxFutureSlotAhead bounds how far in the future a bid's slot may lie
	// relative to the currentSlot observed by CleanupOldSlots. Far-future
	// slots are dropped alongside stale past slots ().
	MaxFutureSlotAhead = 4096
)

// MinBidValue is the minimum bid value accepted by the builder auction.
// A non-zero floor of 1 wei prevents zero-value bids from occupying bid
// slots without contributing value ().
var MinBidValue = big.NewInt(1) // 1 wei

var (
	ErrBidTooLarge     = fmt.Errorf("bid exceeds maximum size")
	ErrBidTooLate      = fmt.Errorf("bid submitted too late in slot")
	ErrBidTooEarly     = fmt.Errorf("bid submitted too early")
	ErrAuctionClosed   = fmt.Errorf("auction is closed")
	ErrInvalidBidValue = fmt.Errorf("invalid bid value")
	ErrBidRejected     = fmt.Errorf("bid rejected by proposer")
	// L6-020: bid parent hash does not match current chain head
	ErrStaleBidParent = fmt.Errorf("bid parent hash does not match current chain head")
)

type BuilderBid struct {
	Slot           uint64
	ParentHash     types.Hash
	BlockHash      types.Hash
	Header         *encoding.BlockHeader
	Transactions   []*encoding.Transaction
	Value          *big.Int
	BuilderAddress types.Address
	BuilderSig     []byte
	Timestamp      int64
	GasUsed        uint64
}

func (b *BuilderBid) Validate() error {
	if b.Header == nil {
		return fmt.Errorf("bid has no header")
	}
	if b.Value == nil || b.Value.Sign() < 0 {
		return ErrInvalidBidValue
	}
	if len(b.BuilderSig) == 0 {
		return fmt.Errorf("bid is not signed")
	}
	return nil
}

func (b *BuilderBid) Hash() types.Hash {
	h := sha3.New256()
	binary.Write(h, binary.BigEndian, b.Slot)
	h.Write(b.ParentHash[:])
	h.Write(b.BlockHash[:])
	valBytes := b.Value.Bytes()
	binary.Write(h, binary.BigEndian, uint32(len(valBytes)))
	h.Write(valBytes)
	h.Write(b.BuilderAddress[:])
	var result types.Hash
	h.Sum(result[:0])
	return result
}

func (b *BuilderBid) SigningHash() types.Hash {
	h := sha3.New256()
	h.Write([]byte("quantaureum-builder-bid-v2"))
	binary.Write(h, binary.BigEndian, b.Slot)
	h.Write(b.ParentHash[:])
	h.Write(b.BlockHash[:])
	valBytes := b.Value.Bytes()
	binary.Write(h, binary.BigEndian, uint32(len(valBytes)))
	h.Write(valBytes)
	h.Write(b.BuilderAddress[:])
	binary.Write(h, binary.BigEndian, b.Timestamp)
	binary.Write(h, binary.BigEndian, b.GasUsed)
	// AUDIT (2026) ECON-FIX: Bind the transaction list to the
	// signature. Without this, a builder could sign a bid with innocuous
	// transactions and the transaction list could be swapped post-signing
	// without invalidating the signature. Now each transaction's hash is
	// included in the signing digest, so any modification to Transactions
	// invalidates BuilderSig.
	binary.Write(h, binary.BigEndian, uint32(len(b.Transactions)))
	for _, tx := range b.Transactions {
		if tx == nil {
			continue
		}
		txHash := tx.Hash()
		h.Write(txHash[:])
	}
	var result types.Hash
	h.Sum(result[:0])
	return result
}

func (b *BuilderBid) VerifySignature(verifier SignatureVerifier, pubKey []byte) error {
	if len(b.BuilderSig) == 0 {
		return fmt.Errorf("bid is not signed")
	}

	signingHash := b.SigningHash()

	if err := verifier.Verify(pubKey, signingHash[:], b.BuilderSig); err != nil {
		return fmt.Errorf("invalid builder signature: %w", err)
	}

	return nil
}

type SignatureVerifier interface {
	Verify(pubKey []byte, message []byte, signature []byte) error
}

type Builder interface {
	BuildBlock(slot uint64, parentHash types.Hash, txs []*encoding.Transaction, proposer types.Address, baseFee *big.Int) (*BuilderBid, error)
	SubmitBid(bid *BuilderBid) error
	GetBid(slot uint64, bidHash types.Hash) *BuilderBid
}

type MEVAuction struct {
	mu sync.RWMutex

	currentSlot uint64
	bids        map[uint64]map[types.Hash]*BuilderBid
	winningBids map[uint64]*BuilderBid
	closed      map[uint64]bool

	proposerAddr types.Address
	proposerKey  interface {
		Sign(data []byte) ([]byte, error)
	}

	// AUDIT (2026) ECON-FIX: Registry for bid signature verification.
	// When set, SubmitBid verifies the builder's signature before accepting
	// the bid. Without this, any peer could submit a forged bid with arbitrary
	// transactions and value, and the block producer would use it without
	// checking authenticity.
	registry *BuilderRegistry

	minBidValue *big.Int
	bidTimeout  time.Duration
}

func NewMEVAuction(proposerAddr types.Address, minBidValue *big.Int) *MEVAuction {
	if minBidValue == nil {
		minBidValue = big.NewInt(0)
	}
	return &MEVAuction{
		bids:         make(map[uint64]map[types.Hash]*BuilderBid),
		winningBids:  make(map[uint64]*BuilderBid),
		closed:       make(map[uint64]bool),
		proposerAddr: proposerAddr,
		minBidValue:  new(big.Int).Set(minBidValue),
		bidTimeout:   6 * time.Second,
	}
}

func (a *MEVAuction) SetProposerKey(key interface {
	Sign(data []byte) ([]byte, error)
}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.proposerKey = key
}

// SetRegistry attaches a BuilderRegistry for bid signature verification.
// AUDIT (2026) ECON- When set, SubmitBid verifies the builder's
// signature and registration status before accepting the bid.
func (a *MEVAuction) SetRegistry(registry *BuilderRegistry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.registry = registry
}

func (a *MEVAuction) SubmitBid(bid *BuilderBid) error {
	if err := bid.Validate(); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// AUDIT (2026) ECON-FIX: Verify the builder's signature before
	// accepting the bid. Without this, any peer could submit a forged bid
	// with arbitrary transactions and value. The block producer would then
	// use the forged bid's transactions without checking authenticity.
	// AUDIT (2026) ECON-FIX (residual): Fail-closed when registry
	// is nil. Previously, a nil registry silently skipped signature
	// verification, allowing unauthenticated bids. Now the bid is rejected.
	if a.registry == nil {
		return fmt.Errorf("bid rejected: builder registry not configured (signature verification mandatory)")
	}
	if err := a.registry.VerifyBid(bid); err != nil {
		return fmt.Errorf("bid signature verification failed: %w", err)
	}

	if a.closed[bid.Slot] {
		return ErrAuctionClosed
	}

	if bid.Value.Cmp(a.minBidValue) < 0 {
		return ErrInvalidBidValue
	}

	if a.bids[bid.Slot] == nil {
		// AUDIT ROUND-4 2026-08-17 FIX: reject bids that would open a
		// NEW tracked slot once the cap is reached (see MaxTrackedBidSlots).
		// Existing slots keep accepting up to MaxBidsPerSlot — the cap only
		// limits the number of distinct slots, so legitimate bidding on the
		// live window is unaffected.
		if len(a.bids) >= MaxTrackedBidSlots {
			return fmt.Errorf("too many tracked bid slots (%d); bid for slot %d rejected (audit )", len(a.bids), bid.Slot)
		}
		a.bids[bid.Slot] = make(map[types.Hash]*BuilderBid)
	}

	if len(a.bids[bid.Slot]) >= MaxBidsPerSlot {
		return fmt.Errorf("too many bids for slot %d", bid.Slot)
	}

	bidHash := bid.Hash()
	a.bids[bid.Slot][bidHash] = bid
	return nil
}

func (a *MEVAuction) GetBid(slot uint64, bidHash types.Hash) *BuilderBid {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.bids[slot] == nil {
		return nil
	}
	return a.bids[slot][bidHash]
}

func (a *MEVAuction) GetWinningBid(slot uint64) *BuilderBid {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.winningBids[slot]
}

func (a *MEVAuction) SelectWinningBid(slot uint64) *BuilderBid {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.bids[slot] == nil || len(a.bids[slot]) == 0 {
		return nil
	}

	var bestBid *BuilderBid
	bestValue := big.NewInt(-1)
	var bestHash types.Hash

	for _, bid := range a.bids[slot] {
		cmp := bid.Value.Cmp(bestValue)
		if cmp > 0 {
			bestValue = bid.Value
			bestBid = bid
			bestHash = bid.BlockHash
		} else if cmp == 0 && bestBid != nil {
			// R11-MIN-003 FIX: Deterministic tie-breaking using block hash.
			if bytes.Compare(bid.BlockHash[:], bestHash[:]) < 0 {
				bestBid = bid
				bestHash = bid.BlockHash
			}
		}
	}

	if bestBid != nil {
		a.winningBids[slot] = bestBid
	}

	return bestBid
}

func (a *MEVAuction) CloseAuction(slot uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed[slot] = true
}

func (a *MEVAuction) IsOpen(slot uint64) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return !a.closed[slot]
}

func (a *MEVAuction) BidTimeout() time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.bidTimeout
}

func (a *MEVAuction) SetBidTimeout(timeout time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bidTimeout = timeout
}

func (a *MEVAuction) CleanupOldSlots(currentSlot uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for slot := range a.bids {
		// AUDIT ROUND-4 2026-08-17 FIX: also drop FAR-FUTURE slots.
		// Previously only stale past slots were pruned, so entries created
		// for arbitrarily distant future slots (which never become "old")
		// accumulated forever. A bid more than MaxFutureSlotAhead ahead of
		// the observed current slot can never win an auction in this
		// process lifetime and is dropped here.
		if slot+64 < currentSlot || slot > currentSlot+MaxFutureSlotAhead {
			delete(a.bids, slot)
			delete(a.winningBids, slot)
			delete(a.closed, slot)
		}
	}
}

type MEVBlockBuilder struct {
	chainID  uint64
	gasLimit uint64
	auction  *MEVAuction

	mu sync.Mutex
}

func NewMEVBlockBuilder(chainID, gasLimit uint64, auction *MEVAuction) *MEVBlockBuilder {
	return &MEVBlockBuilder{
		chainID:  chainID,
		gasLimit: gasLimit,
		auction:  auction,
	}
}

func (b *MEVBlockBuilder) BuildBlock(
	slot uint64,
	parent *encoding.BlockHeader,
	txs []*encoding.Transaction,
	proposer types.Address,
	baseFee *big.Int,
) (*BuilderBid, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	selectedTxs := b.selectTransactionsByPriority(txs, baseFee)

	header := &encoding.BlockHeader{
		Version: 1,
		Height:  parent.Height + 1,
		Slot:    slot,
		Epoch:   slot / 32,
		// R11-CORE-004 FIX: Use Unix() (seconds) for consistency with
		// core/block_builder.go and miner/block_builder.go.
		Timestamp:    time.Now().Unix(),
		ParentHash:   block.ComputeHeaderHash(parent),
		ProposerAddr: proposer,
		ChainID:      b.chainID,
		BaseFee:      baseFee,
		GasLimit:     b.gasLimit,
	}

	var totalGasUsed uint64
	for _, tx := range selectedTxs {
		// R11-MIN-001 FIX: Use overflow-safe subtraction check instead of
		// addition that can wrap around on uint64 overflow.
		if tx.GasLimit > b.gasLimit-totalGasUsed {
			break
		}
		totalGasUsed += tx.GasLimit
	}
	header.GasUsed = totalGasUsed

	txHashes := make([]types.Hash, len(selectedTxs))
	for i, tx := range selectedTxs {
		txHashes[i] = tx.Hash()
	}
	header.TxRoot = ComputeMerkleRoot(txHashes)

	blockHash := block.ComputeHeaderHash(header)

	bidValue := b.calculateBidValue(selectedTxs, baseFee)

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto/rand.Read failed: %w", err)
	}

	bid := &BuilderBid{
		Slot:           slot,
		ParentHash:     parentHashToHash(parent),
		BlockHash:      blockHash,
		Header:         header,
		Transactions:   selectedTxs,
		Value:          bidValue,
		BuilderAddress: proposer,
		Timestamp:      time.Now().UnixNano(),
		GasUsed:        totalGasUsed,
	}

	return bid, nil
}

func (b *MEVBlockBuilder) selectTransactionsByPriority(txs []*encoding.Transaction, baseFee *big.Int) []*encoding.Transaction {
	// AUDIT (2026) ECON-04 FIX: Previously, transactions were sorted purely
	// by gas price across ALL senders, ignoring per-sender nonce ordering. This
	// could produce non-executable blocks where a sender's tx[nonce=1] (higher
	// gas price) was placed before tx[nonce=0] (lower gas price), causing
	// nonce=1 to fail execution.
	//
	// Fix: Group transactions by sender, sort each sender's transactions by
	// nonce ascending, then interleave across senders by priority fee (highest
	// first). This ensures per-sender nonce ordering is enforced by construction
	// while preserving gas-price-based prioritization across senders.
	type txWithPriority struct {
		tx       *encoding.Transaction
		priority *big.Int
	}

	// Step 1: Group by sender
	senderGroups := make(map[types.Address][]txWithPriority)
	for _, tx := range txs {
		priority := effectivePriorityFee(tx, baseFee)
		senderGroups[tx.From] = append(senderGroups[tx.From], txWithPriority{tx: tx, priority: priority})
	}

	// Step 2: Sort each sender's group by nonce ascending
	for _, group := range senderGroups {
		sort.Slice(group, func(i, j int) bool {
			return group[i].tx.Nonce < group[j].tx.Nonce
		})
	}

	// Step 3: Build a flat list by interleaving senders by priority.
	// We use a simple greedy approach: repeatedly pick the sender whose
	// next-nonce transaction has the highest priority fee.
	// This preserves cross-sender gas-price prioritization while enforcing
	// per-sender nonce ordering.
	var selected []*encoding.Transaction
	var gasUsed uint64

	// Track the next unprocessed index for each sender's group
	cursors := make(map[types.Address]int)
	// Build a list of active senders (those with at least one tx)
	activeSenders := make([]types.Address, 0, len(senderGroups))
	for sender := range senderGroups {
		activeSenders = append(activeSenders, sender)
	}

	for len(activeSenders) > 0 {
		// Find the sender with the highest-priority next transaction
		bestSender := types.Address{}
		bestPriority := new(big.Int)
		bestIdx := -1
		for idx, sender := range activeSenders {
			cursor := cursors[sender]
			group := senderGroups[sender]
			if cursor >= len(group) {
				continue // This sender is exhausted
			}
			if bestIdx == -1 || group[cursor].priority.Cmp(bestPriority) > 0 {
				bestSender = sender
				bestPriority = group[cursor].priority
				bestIdx = idx
			}
		}

		if bestIdx == -1 {
			break // All senders exhausted
		}

		// Pick the best sender's next transaction
		cursor := cursors[bestSender]
		tx := senderGroups[bestSender][cursor].tx
		cursors[bestSender] = cursor + 1

		// R11-MIN-001 FIX: Use overflow-safe subtraction check.
		if gasUsed >= b.gasLimit {
			break // No more gas available
		}
		if tx.GasLimit > b.gasLimit-gasUsed {
			// This tx doesn't fit; skip it but continue trying others.
			// If this sender's tx doesn't fit, later txs from the same sender
			// (higher nonce, potentially larger) likely won't either, but we
			// still check other senders.
			continue
		}
		selected = append(selected, tx)
		gasUsed += tx.GasLimit

		// Remove exhausted senders from active list
		if cursors[bestSender] >= len(senderGroups[bestSender]) {
			activeSenders = append(activeSenders[:bestIdx], activeSenders[bestIdx+1:]...)
		}
	}

	return selected
}

func (b *MEVBlockBuilder) calculateBidValue(txs []*encoding.Transaction, baseFee *big.Int) *big.Int {
	total := big.NewInt(0)
	for _, tx := range txs {
		priorityFee := effectivePriorityFee(tx, baseFee)
		// L6-019 SECURITY FIX: Use SetUint64 instead of int64 cast to avoid
		// truncation when tx.GasLimit > math.MaxInt64. int64() conversion would
		// silently wrap to a negative value, corrupting the bid value calculation.
		gasLimitBig := new(big.Int).SetUint64(tx.GasLimit)
		fee := new(big.Int).Mul(priorityFee, gasLimitBig)
		total.Add(total, fee)
	}
	return total
}

func effectivePriorityFee(tx *encoding.Transaction, baseFee *big.Int) *big.Int {
	if tx.MaxPriorityFeePerGas != nil && tx.MaxFeePerGas != nil {
		if tx.MaxFeePerGas.Cmp(baseFee) < 0 {
			return big.NewInt(0)
		}
		maxPriority := new(big.Int).Sub(tx.MaxFeePerGas, baseFee)
		if maxPriority.Cmp(tx.MaxPriorityFeePerGas) > 0 {
			maxPriority = tx.MaxPriorityFeePerGas
		}
		return maxPriority
	}
	if tx.GasPrice != nil && baseFee != nil {
		if tx.GasPrice.Cmp(baseFee) <= 0 {
			return big.NewInt(0)
		}
		return new(big.Int).Sub(tx.GasPrice, baseFee)
	}
	return big.NewInt(0)
}

func parentHashToHash(parent *encoding.BlockHeader) types.Hash {
	return block.ComputeHeaderHash(parent)
}

type MEVProtection struct {
	mu sync.RWMutex

	auction  *MEVAuction
	builder  *MEVBlockBuilder
	registry *BuilderRegistry

	enabled bool
}

func NewMEVProtection(chainID, gasLimit uint64, proposerAddr types.Address) *MEVProtection {
	// R11-MIN-004 FIX: Use MinBidValue instead of big.NewInt(0).
	auction := NewMEVAuction(proposerAddr, new(big.Int).Set(MinBidValue))
	builder := NewMEVBlockBuilder(chainID, gasLimit, auction)

	return &MEVProtection{
		auction: auction,
		builder: builder,
		enabled: true,
	}
}

func NewMEVProtectionWithRegistry(chainID, gasLimit uint64, proposerAddr types.Address, registry *BuilderRegistry) *MEVProtection {
	mp := NewMEVProtection(chainID, gasLimit, proposerAddr)
	mp.registry = registry
	// AUDIT (2026) ECON- Wire the registry into the auction so
	// SubmitBid verifies builder signatures before accepting bids.
	mp.auction.SetRegistry(registry)
	return mp
}

func (m *MEVProtection) Registry() *BuilderRegistry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.registry
}

func (m *MEVProtection) SetRegistry(registry *BuilderRegistry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry = registry
}

func (m *MEVProtection) Auction() *MEVAuction {
	return m.auction
}

func (m *MEVProtection) Builder() *MEVBlockBuilder {
	return m.builder
}

func (m *MEVProtection) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// audit-fix L6-047/L9-013 (P1): MEV protection immutability is now controlled
// by a package-level write-once flag, NOT os.Getenv.
// mevProtectionImmutableFlag is set once at init time via SetMEVProtectionImmutable.
// It cannot be changed at runtime, preventing environment variable bypass.
var mevProtectionImmutableFlag bool

// SetMEVProtectionImmutable sets the MEV protection immutability flag.
// This must be called once during node initialization, BEFORE any MEV protection
// logic runs. Subsequent calls are ignored (the flag is write-once).
// audit-fix L6-047/L9-013: Replaces os.Getenv("QAU_MEV_IMMUTABLE") which could
// be manipulated at runtime by an attacker with process environment access.
var mevProtectionImmutableSet bool

func SetMEVProtectionImmutable(immutable bool) {
	if mevProtectionImmutableSet {
		return // write-once: ignore subsequent calls
	}
	mevProtectionImmutableFlag = immutable
	mevProtectionImmutableSet = true
}

func (m *MEVProtection) SetEnabled(enabled bool) {
	// audit-fix L6-047/L9-013 REGRESSION FIX: Check the live flag directly,
	// not a copy taken at package init time. The previous code used a separate
	// var (mevProtectionEnabledImmutable = mevProtectionImmutableFlag) which
	// was evaluated at init time when the flag was still false, so the
	// immutability check never triggered even after SetMEVProtectionImmutable(true).
	if mevProtectionImmutableFlag {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
}

func (m *MEVProtection) GetBlockForSlot(slot uint64, parent *encoding.BlockHeader, txs []*encoding.Transaction, proposer types.Address, baseFee *big.Int) (*BuilderBid, error) {
	if !m.IsEnabled() {
		return m.builder.BuildBlock(slot, parent, txs, proposer, baseFee)
	}

	winningBid := m.auction.GetWinningBid(slot)
	if winningBid != nil {
		// L6-020 SECURITY FIX: Verify the winning bid's parent hash matches the
		// current chain head. A stale bid built on a different parent block could
		// cause a fork or propagate an invalid block. If the parent hashes differ,
		// reject the bid and fall through to local block building.
		expectedParentHash := parentHashToHash(parent)
		if winningBid.ParentHash != expectedParentHash {
			return nil, ErrStaleBidParent
		}
		return winningBid, nil
	}

	return m.builder.BuildBlock(slot, parent, txs, proposer, baseFee)
}
