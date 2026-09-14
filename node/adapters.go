// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/graphql"
	"github.com/quantaureum/qau/internal/version"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/qaudb/trie"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/qvm/qvmasync"
	"github.com/quantaureum/qau/rpc"
	"github.com/quantaureum/qau/txpool"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss"
)

// distributedTSSEnabled controls whether distributed P2P threshold signing
// is used.
//
// AUDIT (2026) TSS-FIX (CRITICAL): The previous comment claimed
// that masked contributions (c·s2, c·t0) are "signature-derived and leak
// nothing about the private key." THIS IS CRYPTOGRAPHICALLY FALSE.
//
// In the NTT ring Z_q[X]/(X^256+1) (q=8380417), the challenge polynomial c
// (τ=49 ±1 coefficients) is invertible with overwhelming probability. An
// aggregator holding c and the summed c·t0 can recover t0 via NTT inversion:
//
//	t0 = InvNTT( NTT(c·t0) ⊘ NTT(c) )
//
// Combined with public t1, this gives t = t1·2^d + t0. Similarly, c·s2 → s2.
// Then s1 is recovered by solving A·s1 = t - s2 (overdetermined linear system
// in the NTT domain). The FULL private key (s1, s2, t0) is reconstructed.
//
// The Round5 protocol change (Z0Share = λ_i·c·(t0_i - s2_i)) prevents the
// aggregator from obtaining c·s2 and c·t0 SEPARATELY — only their difference
// c·(t0-s2) is available, which leaks s1 (via A·s1 = t1·2^d + (t0-s2)) but
// NOT s2 or t0 individually. This reduces the vulnerability from Critical
// (full key recovery) to High (s1 recovery only).
//
// FULL CLOSURE requires either:
//
//	(a) DH-based pairwise zero-sum masking (aggregator cannot remove masks),
//	(b) Distributed hint generation via MPC (no single party sees z0), or
//	(c) A threshold Dilithium scheme with distributed hint protocol.
//
// Until one of these is implemented, distributed TSS MUST NOT be used in
// production.
//
// ENFORCEMENT: The kill-switch is OFF by default. In production mode
// (QAU_PRODUCTION=1), distributed TSS is HARD-BLOCKED unless the operator
// explicitly sets QAU_ALLOW_UNSAFE_DISTRIBUTED_TSS=1, acknowledging the
// residual s1-leakage risk. This two-key gate prevents accidental enablement.
//
// TSS-C1 (R8 2026-07-19 FIX): Previously the testnet path (QAU_PRODUCTION != 1)
// bypassed the unsafe acknowledgment gate entirely — operators could set
// QAU_ENABLE_DISTRIBUTED_TSS=1 on testnet and immediately get distributed
// signing with full s1-leakage risk. The leakage is a CRYPTOGRAPHIC issue
// (independent of network mode), so testnet deployments also MUST explicitly
// acknowledge the risk. Now both paths require QAU_ALLOW_UNSAFE_DISTRIBUTED_TSS=1.
// This is especially important for public testnets where multiple parties
// participate and the W+H aggregator collusion is realistic.
func distributedTSSEnabled() bool {
	if os.Getenv("QAU_ENABLE_DISTRIBUTED_TSS") != "1" {
		return false
	}
	// TSS-C1 FIX: require unsafe acknowledgment on ALL networks.
	// The previous code only enforced this on production. The s1 leakage
	// is a property of the QTD protocol itself, not the deployment mode.
	if os.Getenv("QAU_ALLOW_UNSAFE_DISTRIBUTED_TSS") != "1" {
		log.Printf("[SECURITY] [BLOCKED] Distributed TSS is disabled. " +
			"QAU_ENABLE_DISTRIBUTED_TSS=1 was set, but you must ALSO set " +
			"QAU_ALLOW_UNSAFE_DISTRIBUTED_TSS=1 to acknowledge the s1-leakage risk (TSS- / TSS-C1). " +
			"This requirement is enforced on BOTH mainnet and testnet because the " +
			"vulnerability is cryptographic, not deployment-specific. " +
			"Falling back to local in-process aggregation.")
		return false
	}
	// Both gates passed: log warning with network context.
	networkMode := "testnet/devnet"
	if params.IsProductionEnv() {
		networkMode = "PRODUCTION"
	}
	log.Printf("[SECURITY] [WARNING] Distributed TSS enabled in %s mode with UNSAFE acknowledgment. "+
		"TSS- RESIDUAL RISK: the aggregator (block proposer) can recover s1 "+
		"from the aggregated Z0Share contributions. Do NOT use in production until "+
		"DH-based pairwise masking or distributed hint generation is implemented.", networkMode)
	return true
}

// Helper function to parse stake string
func parseStake(s string) *big.Int {
	stake, ok := new(big.Int).SetString(s, 10)
	if !ok {
		stake, _ = new(big.Int).SetString(stripHexPrefix(s), 16)
	}
	if stake == nil {
		stake = big.NewInt(0)
	}
	return stake
}

// Adapter types for RPC interfaces

// stateReaderAdapter adapts StateDB to rpc.StateReader
// Uses node reference to always get the latest stateDB (which may be replaced
// by the block producer after each block).
type stateReaderAdapter struct {
	node *Node
}

// L11-025 FIX: getStateDB now returns an error when stateDB is unavailable,
// so callers cannot silently treat a nil stateDB as zero balance/nonce/code.
var errStateDBUnavailable = fmt.Errorf("stateDB not available")

func (a *stateReaderAdapter) getStateDB() (*state.StateDB, error) {
	// R34 P3-01 FIX (2026-07-29): Synchronize stateDB pointer reads with
	// writes in block_producer.go (tryProduceBlock at line ~1162 under
	// n.mu.Lock, produceBlock at line ~2743 in DevMode). Without this
	// RLock, `go run -race` reports a data race because the pointer is
	// written concurrently during block production while RPC handlers
	// read it here. Pointer-sized writes are atomic on amd64/arm64, so
	// the fail-safe nil check still works, but the explicit RLock makes
	// the happens-before relationship explicit and silences the race
	// detector.
	if a.node == nil {
		return nil, errStateDBUnavailable
	}
	a.node.mu.RLock()
	sdb := a.node.stateDB
	a.node.mu.RUnlock()
	if sdb == nil {
		return nil, errStateDBUnavailable
	}
	return sdb, nil
}

// GetBalance returns the current QAU balance of addr in units of 10^-18 QAU
// (wei-equivalent). The returned *big.Int is always non-nil.
//
// Contract:
//   - Input:  addr is the account whose balance to read. A zero Address is
//     allowed and returns the balance of the zero account (typically 0 unless
//     the genesis preallocated it).
//   - Output: *big.Int with the account's balance, or big.NewInt(0) when
//     StateDB is unavailable.
//   - Error:  No error is returned. StateDB unavailability is logged at
//     ERROR level and the method returns 0 as a fail-safe default. Callers
//     that need to distinguish "no balance" from "state unavailable" must
//     check node.stateDB themselves before invoking the adapter.
//
// P2P-R11-L02 (2026-07-20): Documented to clarify fail-safe semantics.
// Returning zero rather than an error keeps the rpc.StateReader interface
// simple (no error returns) but means wallet/UI callers see a zero balance
// during node startup or recovery — operators must watch ERROR logs.
func (a *stateReaderAdapter) GetBalance(addr types.Address) *big.Int {
	sdb, err := a.getStateDB()
	if err != nil {
		// FIX: Log at ERROR level to make StateDB unavailability more
		// visible. Returning zero is fail-safe but could mislead callers into
		// thinking the account has no balance. Operators should investigate
		// ERROR-level logs for StateDB issues.
		log.Printf("[ERROR] [stateReaderAdapter] GetBalance(%s): StateDB unavailable: %v", addr.String(), err)
		return big.NewInt(0)
	}
	return sdb.GetBalance(addr)
}

// GetNonce returns the pending transaction count (nonce) for addr. The
// returned nonce is the next nonce the sender should use for a new
// transaction.
//
// Contract:
//   - Input:  addr is the account whose nonce to read.
//   - Output: uint64 transaction count, or 0 when StateDB is unavailable
//     or the account does not exist.
//   - Error:  No error is returned. StateDB unavailability is logged at
//     ERROR level. Callers cannot distinguish "fresh account" from
//     "state unavailable" — both return 0.
//
// P2P-R11-L02 (2026-07-20): Documented fail-safe semantics.
func (a *stateReaderAdapter) GetNonce(addr types.Address) uint64 {
	sdb, err := a.getStateDB()
	if err != nil {
		log.Printf("[ERROR] [stateReaderAdapter] GetNonce(%s): StateDB unavailable: %v", addr.String(), err)
		return 0
	}
	return sdb.GetNonce(addr)
}

// GetCode returns the smart contract bytecode stored at addr, or nil if
// addr is an EOA (externally owned account) or StateDB is unavailable.
//
// Contract:
//   - Input:  addr is the account whose code to read.
//   - Output: []byte of contract bytecode (may be empty for EOAs), or nil
//     when StateDB is unavailable. Callers cannot distinguish "EOA (no
//     code)" from "state unavailable" — both return nil/empty.
//   - Error:  No error is returned. StateDB unavailability is logged at
//     ERROR level.
//   - Ownership: The returned slice is owned by StateDB; callers MUST NOT
//     mutate it. Make a copy if mutation is required.
//
// P2P-R11-L02 (2026-07-20): Documented ownership and fail-safe semantics.
func (a *stateReaderAdapter) GetCode(addr types.Address) []byte {
	sdb, err := a.getStateDB()
	if err != nil {
		log.Printf("[ERROR] [stateReaderAdapter] GetCode(%s): StateDB unavailable: %v", addr.String(), err)
		return nil
	}
	return sdb.GetCode(addr)
}

// GetState returns the 32-byte value stored at slot `key` in the account
// at addr. Used by eth_getStorageAt and light-client proof verification.
//
// Contract:
//   - Input:  addr is the account whose storage to read. key is the
//     32-byte storage slot key.
//   - Output: types.Hash containing the 32-byte slot value, or types.Hash{}
//     (zero hash) when StateDB is unavailable or the slot is empty.
//   - Error:  No error is returned. StateDB unavailability is logged at
//     ERROR level. Callers cannot distinguish "empty slot" from "state
//     unavailable" — both return the zero hash.
//
// P2P-R11-L02 (2026-07-20): Documented fail-safe semantics. Light clients
// must verify state availability through other means (e.g., check
// eth_syncing) before trusting a zero-hash response.
func (a *stateReaderAdapter) GetState(addr types.Address, key types.Hash) types.Hash {
	sdb, err := a.getStateDB()
	if err != nil {
		log.Printf("[ERROR] [stateReaderAdapter] GetState(%s): StateDB unavailable: %v", addr.String(), err)
		return types.Hash{}
	}
	return sdb.GetState(addr, key)
}

// IterateAccounts iterates over all accounts in StateDB, invoking fn for
// each. Iteration stops early if fn returns false. Used by RPC methods
// that need to enumerate accounts (e.g., for indexers or admin tools).
//
// Contract:
//   - Input:  fn is invoked with (addr, code, balance) for each account.
//     Returning false from fn stops iteration. Returning true continues.
//   - Output: None. The fn callback receives account data.
//   - Error:  No error is returned. StateDB unavailability is logged at
//     INFO level (not ERROR — this method is typically called by background
//     indexers that should retry gracefully).
//   - Ordering: Iteration order is undefined (depends on StateDB internal
//     layout). Callers must not depend on any particular order.
//   - Snapshot semantics: The iteration reflects StateDB state at the time
//     of the call; concurrent block production may add/modify accounts
//     during iteration. Callers that need a consistent snapshot should
//     pause block production or take a database-level snapshot.
//
// P2P-R11-L02 (2026-07-20): Documented ordering and concurrency semantics.
func (a *stateReaderAdapter) IterateAccounts(fn func(addr types.Address, code []byte, balance *big.Int) bool) {
	sdb, err := a.getStateDB()
	if err != nil {
		log.Printf("[stateReaderAdapter] IterateAccounts: %v", err)
		return
	}
	sdb.IterateAccounts(fn)
}

// StateRoot returns the canonical state root of the latest committed
// block (R38-P2-04 DEEP FIX 2026-08-02). Used by rpc.GetProof to surface
// the canonical state root alongside the account/storage proof so light
// clients / bridges can cryptographically bind the proof to a block.
//
// Contract:
//   - Output: types.Hash containing the canonical state root, or
//     types.Hash{} when StateDB is unavailable. Callers cannot distinguish
//     "empty genesis state" from "state unavailable" — both return zero.
//   - Error:  No error is returned. StateDB unavailability is logged at
//     ERROR level. The caller is expected to fall back to Unverified=true
//     when StateRoot returns zero.
func (a *stateReaderAdapter) StateRoot() types.Hash {
	sdb, err := a.getStateDB()
	if err != nil {
		// R38-P2-04 DEEP FIX (2026-08-02): log at ERROR so operators can
		// see when eth_getProof has to fall back to the Unverified path.
		log.Printf("[ERROR] [stateReaderAdapter] StateRoot: StateDB unavailable: %v", err)
		return types.Hash{}
	}
	return sdb.Root()
}

// ProveAccount returns a stateRoot-aware Verkle proof for the account at
// addr (R38-P2-04 DEEP FIX 2026-08-02). Delegates to StateDB.ProveAccount
// which produces a REAL Verkle path against the canonical state trie
// (not a synthetic singleton tree).
//
// Contract:
//   - Output: *trie.VerkleProof, or nil when StateDB is unavailable or
//     does not support proofs (e.g. NewStateDBWithoutStorage stub).
//   - Error:  errStateDBUnavailable when the StateDB is down,
//     ErrProofNotSupported when the StateDB has no live state trie.
//     The caller (rpc.GetProof) ranks these errors and falls back to
//     the Unverified=true path honestly rather than fabricating a proof.
func (a *stateReaderAdapter) ProveAccount(addr types.Address) (*trie.VerkleProof, error) {
	sdb, err := a.getStateDB()
	if err != nil {
		return nil, err
	}
	return sdb.ProveAccount(addr)
}

// ProveStorage returns a stateRoot-aware Verkle proof for one storage
// slot at (addr, key) (R38-P2-04 DEEP FIX 2026-08-02). See ProveAccount
// for the contract — the storage variant uses the same trie.Prove path
// under a key derived from (addr, key) per StateDB's storage layout.
func (a *stateReaderAdapter) ProveStorage(addr types.Address, key types.Hash) (*trie.VerkleProof, error) {
	sdb, err := a.getStateDB()
	if err != nil {
		return nil, err
	}
	return sdb.ProveStorage(addr, key)
}

// blockReaderAdapter adapts BlockStore to rpc.BlockReader
type blockReaderAdapter struct {
	blockStore *block.BlockStore
	stateDB    *state.StateDB // fallback, prefer a.node.stateDB
	gasLimit   uint64
	node       *Node
}

// validateBlockHeaderIntegrity performs sanity checks on a block before
// returning it via the RPC adapter. P2P-R11-H06 (2026-07-20): Previously the
// adapter returned whatever the block store returned without verifying that
// critical header fields are populated. A corrupted block store (or a
// memory-mapped DB returning garbage) could feed inconsistent state root /
// transaction root to light clients, who trust the header's StateRoot as
// the authoritative commitment to the state trie at that block height.
//
// Checks:
//   - blk and blk.Header are non-nil (FormatBlock already checks, but we
//     re-check defensively in case FormatBlock's behavior changes).
//   - StateRoot and ParentHash are non-zero for non-genesis blocks.
//     Genesis (height=0) is allowed to have a zero ParentHash, and blocks
//     with no transactions are allowed to have the canonical zero TxRoot.
//   - Height is not absurdly large (>2^63 is a clear sign of corruption).
//
// This does NOT verify that the block's StateRoot matches the actual state
// trie root computed from StateDB — that would require re-executing the
// block, which is the consensus layer's responsibility, not the RPC adapter's.
// The check here is a defensive lower bound: refuse to serve obviously
// broken blocks to light clients.
func validateBlockHeaderIntegrity(blk *encoding.Block) error {
	if blk == nil {
		return fmt.Errorf("block is nil")
	}
	if blk.Header == nil {
		return fmt.Errorf("block header is nil")
	}
	var zeroHash types.Hash
	// Genesis (height 0) is permitted a zero ParentHash; all other blocks
	// must have a non-zero parent linking them to the chain.
	if blk.Header.Height > 0 && blk.Header.ParentHash == zeroHash {
		return fmt.Errorf("block at height %d has zero ParentHash", blk.Header.Height)
	}
	// StateRoot must always be set for real blocks. TxRoot is zero for the
	// canonical empty transaction list, so only reject it when transactions
	// are actually present.
	if blk.Header.StateRoot == zeroHash {
		return fmt.Errorf("block at height %d has zero StateRoot", blk.Header.Height)
	}
	if len(blk.Transactions) > 0 && blk.Header.TxRoot == zeroHash {
		return fmt.Errorf("block at height %d has zero TxRoot", blk.Header.Height)
	}
	// Sanity bound on Height to detect memory corruption / overflow.
	if blk.Header.Height > (uint64(1) << 62) {
		return fmt.Errorf("block height %d exceeds sanity bound (2^62)", blk.Header.Height)
	}
	return nil
}

// getStateDB returns the latest stateDB from the node (which may be replaced
// by the block producer after each block), falling back to the captured reference.
func (a *blockReaderAdapter) getStateDB() *state.StateDB {
	if a.node != nil && a.node.stateDB != nil {
		return a.node.stateDB
	}
	return a.stateDB
}

func (a *blockReaderAdapter) GetBlockByHash(hash types.Hash) (any, error) {
	blk, err := a.blockStore.GetBlock(hash)
	if err != nil {
		return nil, err
	}
	// P2P-R11-H06 (2026-07-20): Validate header integrity before returning
	// to RPC layer. A block with zero StateRoot/TxRoot/ParentHash indicates
	// either corruption or a genesis block being mis-served as a real block.
	// Refuse to return such blocks to light clients, who would otherwise
	// trust inconsistent state data.
	if err := validateBlockHeaderIntegrity(blk); err != nil {
		return nil, err
	}
	return rpc.FormatBlock(blk, true), nil
}

func (a *blockReaderAdapter) GetBlockByHeight(height uint64) (any, error) {
	blk, err := a.blockStore.GetBlockByHeight(height)
	if err != nil {
		return nil, err
	}
	// P2P-R11-H06: Validate header integrity (see GetBlockByHash).
	if err := validateBlockHeaderIntegrity(blk); err != nil {
		return nil, err
	}
	return rpc.FormatBlock(blk, true), nil
}

func (a *blockReaderAdapter) GetLatestHeight() uint64 {
	height, err := a.blockStore.GetLatestHeight()
	if err != nil {
		return 0
	}
	return height
}

func (a *blockReaderAdapter) GetTransaction(hash types.Hash) (any, error) {
	tx, loc, err := a.blockStore.GetTransaction(hash)
	if err != nil {
		return nil, err
	}
	// Get block to find block height
	blk, err := a.blockStore.GetBlock(loc.BlockHash)
	if err != nil {
		return rpc.FormatTransaction(tx, loc.BlockHash, 0, uint64(loc.TxIndex)), nil
	}
	return rpc.FormatTransaction(tx, loc.BlockHash, blk.Header.Height, uint64(loc.TxIndex)), nil
}

// receiptFromStored converts a persisted encoding.StoredReceipt into the
// JSON-RPC receipt map format expected by eth_getTransactionReceipt callers.
//
// R35-P0-09 FIX: this helper exists so that the persisted-receipt fast path
// produces the same JSON shape as the simulated-receipt fallback path.
func receiptFromStored(r *encoding.StoredReceipt) map[string]any {
	if r == nil {
		return nil
	}
	status := "0x0"
	if r.Status == 1 {
		status = "0x1"
	}
	logs := make([]any, 0, len(r.Logs))
	for _, lg := range r.Logs {
		if lg == nil {
			continue
		}
		topics := make([]string, 0, len(lg.Topics))
		for _, t := range lg.Topics {
			topics = append(topics, "0x"+hex.EncodeToString(t[:]))
		}
		logs = append(logs, map[string]any{
			"address":          "0x" + hex.EncodeToString(lg.Address[:]),
			"topics":           topics,
			"data":             "0x" + hex.EncodeToString(lg.Data),
			"blockNumber":      fmt.Sprintf("0x%x", r.BlockNumber),
			"transactionHash":  "0x" + hex.EncodeToString(r.TxHash[:]),
			"transactionIndex": fmt.Sprintf("0x%x", r.TxIndex),
			"blockHash":        "0x" + hex.EncodeToString(r.BlockHash[:]),
			"logIndex":         fmt.Sprintf("0x%x", len(logs)),
			"removed":          false,
		})
	}
	receipt := map[string]any{
		"transactionHash":   "0x" + hex.EncodeToString(r.TxHash[:]),
		"transactionIndex":  fmt.Sprintf("0x%x", r.TxIndex),
		"blockHash":         "0x" + hex.EncodeToString(r.BlockHash[:]),
		"blockNumber":       fmt.Sprintf("0x%x", r.BlockNumber),
		"cumulativeGasUsed": fmt.Sprintf("0x%x", r.GasUsed),
		"gasUsed":           fmt.Sprintf("0x%x", r.GasUsed),
		"contractAddress":   nil,
		"logs":              logs,
		"logsBloom":         "0x" + strings.Repeat("00", 256),
		"status":            status,
		"effectiveGasPrice": fmt.Sprintf("0x%x", rpc.DefaultGasPriceWei),
		"type":              "0x0",
	}
	return receipt
}

func (a *blockReaderAdapter) GetTransactionReceipt(hash types.Hash) (any, error) {
	// R35-P0-09 FIX: Try persisted receipt first. Previously receipts were
	// only in the in-memory receiptCache (lost on restart). Now we persist
	// them to disk in block_producer.go and load them here. If no persisted
	// receipt exists (pre-R35 blocks or sync path), fall back to the
	// simulated receipt path below.
	if a.blockStore != nil {
		// R40-DEPLOY FIX (2026-08-10): Race condition between PutBlock/
		// IndexTransactions (which add the tx to the block index) and
		// StoreReceipts (which writes the persisted receipt) can make a
		// first GetReceipt return ErrTxNotFound for a tx that has *just*
		// been included in a block. The fallback path below then infers
		// status by reading deployed code from a possibly-stale stateDB
		// snapshot, returning a false "0x0" (FAILED) receipt — observed
		// as spurious "DEPLOYMENT FAILED!" in deploy_vesting_all even
		// though the contract was successfully deployed.
		//
		// Mitigation: when a tx is already in the block index but its
		// persisted receipt is missing, briefly retry GetReceipt (up to
		// ~500ms in 50ms steps) before falling back to the inferred path.
		// This is short enough to never block RPC handlers meaningfully
		// but long enough to bridge the typical PutBlock -> StoreReceipts
		// write-order window on the producer.
		if txInBlock, _, txErr := a.blockStore.GetTransaction(hash); txErr == nil && txInBlock != nil {
			const receiptRetryDelay = 50 * time.Millisecond
			const receiptRetryMax = 10
			for attempt := 0; attempt < receiptRetryMax; attempt++ {
				if stored, err := a.blockStore.GetReceipt(hash); err == nil && stored != nil {
					receipt := receiptFromStored(stored)
					// R38-DEPLOY FIX (2026-07-31): StoredReceipt does not persist
					// ContractAddress (would require consensus-breaking schema change).
					// Since the address is deterministic from sender+nonce
					// (keccak256(rlp([sender, nonce]))[12:]), recompute it here for
					// contract creation txs so eth_getTransactionReceipt returns the
					// correct contractAddress field instead of nil.
					if tx, _, err := a.blockStore.GetTransaction(hash); err == nil && tx != nil {
						if tx.Type == encoding.TxTypeCreate && tx.To == nil {
							addr := qvm.CreateAddress(qvm.Address(tx.From), tx.Nonce)
							receipt["contractAddress"] = "0x" + hex.EncodeToString(addr[:])
						}
					}
					return receipt, nil
				}
				time.Sleep(receiptRetryDelay)
			}
		} else if stored, err := a.blockStore.GetReceipt(hash); err == nil && stored != nil {
			// Fast path: tx not yet indexed (or tx lookup had a transient
			// error) but the receipt already persisted — trust it.
			receipt := receiptFromStored(stored)
			if tx, _, err := a.blockStore.GetTransaction(hash); err == nil && tx != nil {
				if tx.Type == encoding.TxTypeCreate && tx.To == nil {
					addr := qvm.CreateAddress(qvm.Address(tx.From), tx.Nonce)
					receipt["contractAddress"] = "0x" + hex.EncodeToString(addr[:])
				}
			}
			return receipt, nil
		}
	}
	// P2P-R11-M06 (2026-07-20) FIX: differentiate "not found" (legitimate
	// absence — tx is pending or in a reorged block) from "execution failed"
	// (database corruption, I/O error, etc.). The previous code conflated
	// both into (nil, nil), which made it impossible for callers to surface
	// real errors or distinguish "tx doesn't exist yet" from "we tried but
	// failed to read it".
	//
	// New contract:
	//   - (nil, nil)            — transaction not in chain yet (ErrTxNotFound)
	//   - (nil, nil)            — block missing (ErrBlockNotFound, e.g. reorg)
	//   - (nil, err)            — actual read error (DB I/O, decode, etc.)
	//   - (receipt, nil)        — success
	tx, loc, err := a.blockStore.GetTransaction(hash)
	if err != nil {
		// Transaction not found is a legitimate "not yet in chain" state.
		// Other errors indicate storage/decoding failures that callers
		// may want to log or retry.
		if errors.Is(err, block.ErrTxNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if tx == nil {
		// Defensive: GetTransaction returned nil tx without an error — treat
		// as not found rather than crashing downstream.
		return nil, nil
	}

	// Get the block to get block info
	blk, err := a.blockStore.GetBlock(loc.BlockHash)
	if err != nil {
		if errors.Is(err, block.ErrBlockNotFound) {
			// Block was reorged away or never persisted. Treat as not-found
			// rather than an error: the tx may resurface in a future block.
			return nil, nil
		}
		return nil, err
	}
	if blk == nil {
		// Defensive: GetBlock returned nil block without an error.
		return nil, nil
	}

	txHash := tx.Hash()

	// Determine gasUsed and status
	// Check receipt cache first for actual gasUsed
	gasUsed := uint64(21000) // conservative fallback (vuln-8 fix)
	if a.node != nil {
		a.node.receiptCacheMu.RLock()
		if cached, ok := a.node.receiptCache[txHash]; ok {
			gasUsed = cached
		}
		a.node.receiptCacheMu.RUnlock()
	}
	if gasUsed == 0 {
		gasUsed = 21000 // fallback for legacy txs without GasLimit
	}

	// Determine status: for contract creation, check if code exists at the address
	// P3-9 FIX: getStateDB() may return nil if both a.node and a.stateDB are
	// unavailable. The nil check below prevents a panic on sdb.GetCode().
	// When sdb is nil, we default to status "0x1" (success) rather than
	// failing the receipt — consistent with Ethereum behavior when state
	// is unavailable for receipt generation.
	//
	// R42-SERVER-HARDENING (2026-08-18): The original logic defaulted to
	// status="0x1" but immediately flipped to "0x0" when sdb.GetCode
	// returned empty. In the race window between PutBlock+IndexTransactions
	// (Successful tx lookup) and StoreReceipts (persisted receipt), the RPC
	// handler frequently gets a stateDB snapshot that has not yet committed
	// the freshly-deployed runtime code -> sdb.GetCode returns empty even
	// though the contract deployment SUCCEEDED on-chain. This caused R42
	// "DEPLOYMENT FAILED!" false-negatives (3/6 LinearVesting contracts on
	// the 2026-08-18 mainnet rebuild).
	//
	// Mitigation: differentiate race from genuine failure via sender nonce:
	//   - nonce > tx.Nonce => sender's nonce has advanced past this tx's
	//     nonce, which only happens if the tx was accepted and executed by
	//     the consensus layer (nonce is bumped ATOMICALLY with deploy code
	//     write during state transition). Treat as success even without code
	//     on this stateDB snapshot.
	//   - nonce <= tx.Nonce => sender's nonce has NOT advanced; combined with
	//     empty code, this is the genuine-failure signature -> status="0x0".
	//
	// This preserves the existing genuine-failure branch (covered by
	// TestGetTransactionReceipt_R42_GenuineFailureNotMaskedToSuccess) AND
	// fixes the race false-negative (covered by
	// TestGetTransactionReceipt_R42_RaceContractDeployedButStaleStateDBCode).
	status := "0x1" // default: success
	if tx.Type == encoding.TxTypeCreate && tx.To == nil {
		// Contract creation: check if code was deployed at the contract address
		contractAddr := qvm.CreateAddress(qvm.Address(tx.From), tx.Nonce)
		if sdb := a.getStateDB(); sdb != nil {
			code := sdb.GetCode(types.Address(contractAddr))
			if len(code) == 0 {
				// R42-SERVER-HARDENING: empty code alone is insufficient to
				// call this a deployment failure - it could be the race
				// window where stateDB code commit is still pending. Use
				// the sender's nonce as a second signal: if it has
				// advanced past tx.Nonce, the tx WAS executed (consensus
				// bumps nonce atomically with code deployment), so the
				// missing code is a snapshot-lag artifact, not failure.
				currentNonce := sdb.GetNonce(tx.From)
				if currentNonce > tx.Nonce {
					// Race window: deployment succeeded but code not yet
					// visible on this stateDB snapshot. Keep status="0x1".
					// (intentionally no status mutation here)
				} else {
					// Genuine failure: nonce did not advance AND no code ->
					// consensus rejected the deploy or it reverted/OOG.
					status = "0x0"
				}
			}
		}
	}

	// AUDIT (2026) R3-NODE-04 FIX: Use the central rpc.DefaultGasPriceWei
	// constant instead of a hardcoded hex literal, so the default tracks the
	// same value used by rpc.API.GasPrice.
	effectiveGasPrice := fmt.Sprintf("0x%x", rpc.DefaultGasPriceWei)
	if tx.GasPrice != nil && tx.GasPrice.Sign() > 0 {
		effectiveGasPrice = "0x" + tx.GasPrice.Text(16)
	}

	// Compute contract address for contract creation transactions
	var contractAddr any = nil
	if tx.Type == encoding.TxTypeCreate && tx.To == nil {
		// Contract address = keccak256(rlp([sender, nonce]))[12:]
		addr := qvm.CreateAddress(qvm.Address(tx.From), tx.Nonce)
		contractAddr = "0x" + hex.EncodeToString(addr[:])
	}

	receipt := map[string]any{
		"transactionHash":   "0x" + hex.EncodeToString(txHash[:]),
		"transactionIndex":  fmt.Sprintf("0x%x", loc.TxIndex),
		"blockHash":         "0x" + hex.EncodeToString(loc.BlockHash[:]),
		"blockNumber":       fmt.Sprintf("0x%x", blk.Header.Height),
		"from":              "0x" + hex.EncodeToString(tx.From[:]),
		"to":                nil,
		"cumulativeGasUsed": fmt.Sprintf("0x%x", gasUsed),
		"gasUsed":           fmt.Sprintf("0x%x", gasUsed),
		"contractAddress":   contractAddr,
		"logs":              []any{},
		"logsBloom":         "0x" + strings.Repeat("00", 256),
		"status":            status,
		"effectiveGasPrice": effectiveGasPrice,
		"type":              fmt.Sprintf("0x%x", tx.Type),
	}

	if tx.To != nil {
		receipt["to"] = "0x" + hex.EncodeToString(tx.To[:])
	}

	return receipt, nil
}

func (a *blockReaderAdapter) GetGasLimit() uint64 {
	return a.gasLimit
}

func (a *blockReaderAdapter) GetBlockByHeightRange(from, to uint64) ([]any, error) {
	// R35 P3 FIX (2026-07-29): Guard against uint64 underflow when to < from.
	// Without this check, to-from+1 underflows to ~2^64, causing make() to
	// attempt a multi-exabyte allocation (OOM/panic). Mirrors the bounds
	// check already present in graphqlReaderAdapter.GetBlockRange.
	if to < from {
		return nil, nil
	}
	blocks := make([]any, 0, to-from+1)
	for height := from; height <= to; height++ {
		blk, err := a.blockStore.GetBlockByHeight(height)
		if err != nil {
			continue
		}
		blocks = append(blocks, rpc.FormatBlock(blk, false))
	}
	return blocks, nil
}

// feeHistoryReaderAdapter implements rpc.FeeHistoryReader using BlockStore
type feeHistoryReaderAdapter struct {
	blockStore *block.BlockStore
}

func (a *feeHistoryReaderAdapter) GetFeeHistory(blockCount uint64, newestBlock uint64, rewardPercentiles []float64) (*rpc.FeeHistoryResult, error) {
	// Cap blockCount to 1024 (standard limit)
	if blockCount > 1024 {
		blockCount = 1024
	}
	if blockCount == 0 {
		blockCount = 1
	}

	// Calculate oldest block
	oldestBlock := uint64(0)
	if newestBlock >= blockCount-1 {
		oldestBlock = newestBlock - blockCount + 1
	}

	baseFeePerGas := make([]string, 0, blockCount+1)
	gasUsedRatio := make([]float64, 0, blockCount)
	reward := make([][]string, 0, blockCount)

	for i := oldestBlock; i <= newestBlock; i++ {
		blk, err := a.blockStore.GetBlockByHeight(i)
		if err != nil || blk == nil {
			continue
		}

		// BaseFee
		if blk.Header.BaseFee != nil && blk.Header.BaseFee.Sign() > 0 {
			baseFeePerGas = append(baseFeePerGas, "0x"+blk.Header.BaseFee.Text(16))
		} else {
			// AUDIT (2026) R3-NODE-05 FIX: Use central default constant.
			baseFeePerGas = append(baseFeePerGas, fmt.Sprintf("0x%x", rpc.DefaultGasPriceWei))
		}

		// GasUsedRatio
		if blk.Header.GasLimit > 0 {
			gasUsedRatio = append(gasUsedRatio, float64(blk.Header.GasUsed)/float64(blk.Header.GasLimit))
		} else {
			gasUsedRatio = append(gasUsedRatio, 0.0)
		}

		// Reward percentiles — use base fee as reward estimate
		if len(rewardPercentiles) > 0 {
			rewardRow := make([]string, len(rewardPercentiles))
			var rewardVal string
			if blk.Header.BaseFee != nil && blk.Header.BaseFee.Sign() > 0 {
				rewardVal = "0x" + blk.Header.BaseFee.Text(16)
			} else {
				// AUDIT (2026) R3-NODE-05 FIX: Use central default constant.
				rewardVal = fmt.Sprintf("0x%x", rpc.DefaultGasPriceWei)
			}
			for j := range rewardPercentiles {
				rewardRow[j] = rewardVal
			}
			reward = append(reward, rewardRow)
		}
	}

	// EIP-1559 convention: one extra base fee element for the next block
	if len(baseFeePerGas) > 0 {
		baseFeePerGas = append(baseFeePerGas, baseFeePerGas[len(baseFeePerGas)-1])
	}

	return &rpc.FeeHistoryResult{
		OldestBlock:   fmt.Sprintf("0x%x", oldestBlock),
		BaseFeePerGas: baseFeePerGas,
		GasUsedRatio:  gasUsedRatio,
		Reward:        reward,
	}, nil
}

// contractCallerAdapter implements rpc.ContractCaller for eth_call
type contractCallerAdapter struct {
	stateDB    *state.StateDB // fallback
	blockStore *block.BlockStore
	qvmExec    *qvm.Executor
	gasLimit   uint64
	chainID    uint64 // P2-13 FIX: store actual chain ID instead of hardcoding 1
	node       *Node
}

// getStateDB returns the latest stateDB from the node
func (a *contractCallerAdapter) getStateDB() *state.StateDB {
	if a.node != nil && a.node.stateDB != nil {
		return a.node.stateDB
	}
	return a.stateDB
}

func (a *contractCallerAdapter) Call(req *rpc.ContractCallRequest) (*rpc.ContractCallResult, error) {
	// Get code at target address
	// P3-9 FIX: Guard against nil stateDB — getStateDB() returns nil when
	// both a.node and a.stateDB are unavailable (e.g., during node shutdown
	// or before initial state is loaded). Without this check, sdb.GetCode()
	// would panic with a nil pointer dereference.
	sdb := a.getStateDB()
	if sdb == nil {
		return nil, fmt.Errorf("stateDB not available")
	}
	code := sdb.GetCode(req.To)
	if len(code) == 0 {
		// No code at address, return empty result (like Ethereum)
		return &rpc.ContractCallResult{
			ReturnData: []byte{},
			GasUsed:    0,
			Error:      nil,
		}, nil
	}

	// Convert addresses
	var caller, callee qvm.Address
	copy(caller[:], req.From[:])
	copy(callee[:], req.To[:])

	// Default gas limit if not specified
	gas := req.Gas
	if gas == 0 {
		gas = a.gasLimit
	}

	// Create block context
	blockNumber := uint64(0)
	if height, err := a.blockStore.GetLatestHeight(); err == nil {
		blockNumber = height
	}

	// Get recent block hashes for BLOCKHASH opcode
	blockHashes := make(map[uint64]qvm.Hash)
	for i := uint64(0); i < 256 && blockNumber > i; i++ {
		hash, err := a.blockStore.GetBlockHash(blockNumber - i)
		if err == nil {
			blockHashes[blockNumber-i] = qvm.Hash(hash)
		}
	}

	// Use block timestamp for deterministic eth_call results
	blockTimestamp := time.Now().Unix()
	if a.blockStore != nil {
		if blk, err := a.blockStore.GetBlockByHeight(blockNumber); err == nil && blk != nil && blk.Header != nil {
			blockTimestamp = blk.Header.Timestamp
		}
	}
	// P2-13 FIX: Use the chain ID stored in the adapter, set at construction
	// time from the node's actual chain ID (1668 mainnet, 1669 testnet, 1333 devnet).
	chainID := a.chainID

	blockCtx := &qvm.BlockContext{
		BlockNumber: blockNumber,
		Timestamp:   blockTimestamp,
		Coinbase:    qvm.Address{}, // Zero address for call context
		GasLimit:    a.gasLimit,
		GasPrice:    big.NewInt(1),
		ChainID:     chainID,
		BlockHashes: blockHashes,
	}

	// Execute contract call using QVM
	stateAdapter := &qvmasync.StateDBAdapter{StateDB: sdb}
	result := a.qvmExec.StaticCall(stateAdapter, caller, callee, req.Data, gas, blockCtx, 0)

	return &rpc.ContractCallResult{
		ReturnData: result.ReturnData,
		GasUsed:    result.GasUsed,
		Error:      result.Err,
	}, nil
}

// txPoolAdapter adapts TxPool to rpc.TxPool
type txPoolAdapter struct {
	txPool *txpool.TxPool
	node   *Node // for P2P transaction broadcasting
}

// AddTransaction implements rpc.TxPool. It is the canonical entry point used by
// eth_sendRawTransaction (rpc/api.go) — the AUDIT-FULL-ROUND1-2026-08-15 entry
// point #4. The tx flows through: txPoolAdapter.AddTransaction →
// encoding.UnmarshalTransaction → txPool.Add → txPool.BatchAdd →
// txpool.Validator.ValidateBasic → encoding.VerifyTransactionAuthorization
// (single-source boundary). Same canonical surface as node.handleIncomingTransaction
// (entry point #5). No bypass exists; the P2P inbound and RPC submit paths share
// this verification boundary.
func (a *txPoolAdapter) AddTransaction(txData []byte) (types.Hash, error) {
	// Debug log to file
	nodeDebugLog("AddTransaction called, data size=%d\n", len(txData))

	tx, err := encoding.UnmarshalTransaction(txData)
	if err != nil {
		nodeDebugLog("Failed to unmarshal tx: %v\n", err)
		nodeLog.Error("[txPoolAdapter] Failed to unmarshal tx: %v", err)
		return types.Hash{}, err
	}

	nodeDebugLog("Tx unmarshaled: from=%x, nonce=%d, value=%s\n", tx.From[:8], tx.Nonce, tx.Value)

	nodeLog.Debug("[txPoolAdapter] Adding tx: from=%x, nonce=%d, value=%s", tx.From[:8], tx.Nonce, tx.Value)
	if err := a.txPool.Add(tx); err != nil {
		nodeDebugLog("Failed to add tx: %v\n", err)
		nodeLog.Error("[txPoolAdapter] Failed to add tx: %v", err)
		return types.Hash{}, err
	}
	hash := tx.Hash()

	nodeDebugLog("Tx added successfully: hash=%x\n", hash[:8])

	nodeLog.Debug("[txPoolAdapter] Tx added successfully: hash=%x", hash[:8])

	// Broadcast the transaction to all peers (Ethereum-like tx propagation).
	// Uses Broadcaster's built-in dedup (seenTxs) so re-broadcasts are no-ops.
	// This is critical: without propagation, transactions submitted via RPC
	// stay on the receiving node and never reach the block proposer.
	if a.node == nil {
		nodeLog.Warn("[txPoolAdapter] Cannot broadcast: node is nil")
	} else if a.node.p2pHost == nil {
		nodeLog.Warn("[txPoolAdapter] Cannot broadcast: p2pHost is nil")
	} else {
		if bc := a.node.p2pHost.Broadcaster(); bc == nil {
			nodeLog.Warn("[txPoolAdapter] Cannot broadcast: broadcaster is nil")
		} else {
			if err := bc.BroadcastTransaction(context.Background(), txData); err != nil {
				nodeLog.Warn("[txPoolAdapter] Failed to broadcast tx: %v", err)
			} else {
				connectedPeers := a.node.p2pHost.ConnectedPeerCount()
				nodeLog.Info("[txPoolAdapter] Tx broadcast to %d peers: hash=%x", connectedPeers, hash[:8])
			}
		}
	}

	return hash, nil
}

// AddVerifiedTransaction adds a pre-verified transaction to the pool without
// Dilithium3 signature re-verification, then broadcasts it to peers.
// Used by qau_stake/qau_unstake RPC to create on-chain staking transactions
// that propagate to all nodes through block synchronization.
func (a *txPoolAdapter) AddVerifiedTransaction(tx *encoding.Transaction) (types.Hash, error) {
	if err := a.txPool.AddVerified(tx); err != nil {
		nodeLog.Error("[txPoolAdapter] Failed to add verified tx: %v", err)
		return types.Hash{}, err
	}
	hash := tx.Hash()

	nodeLog.Debug("[txPoolAdapter] Verified tx added: hash=%x, type=%d", hash[:8], tx.Type)

	// Broadcast to peers so the transaction reaches the block proposer.
	// Without this, staking transactions submitted on non-proposer nodes
	// would never be packed into blocks.
	if a.node != nil && a.node.p2pHost != nil {
		if bc := a.node.p2pHost.Broadcaster(); bc != nil {
			txData, err := encoding.MarshalTransaction(tx)
			if err != nil {
				nodeLog.Warn("[txPoolAdapter] Failed to marshal tx for broadcast: %v", err)
			} else if err := bc.BroadcastTransaction(context.Background(), txData); err != nil {
				nodeLog.Warn("[txPoolAdapter] Failed to broadcast verified tx: %v", err)
			} else {
				nodeLog.Debug("[txPoolAdapter] Verified tx broadcast to peers: hash=%x", hash[:8])
			}
		}
	}

	return hash, nil
}

func (a *txPoolAdapter) GetPendingTransactions() []any {
	txs := a.txPool.Pending()
	result := make([]any, len(txs))
	for i, tx := range txs {
		result[i] = tx
	}
	return result
}

func (a *txPoolAdapter) GetPendingCount() int {
	return a.txPool.GetPendingCount()
}

func (a *txPoolAdapter) GetQueuedCount() int {
	return a.txPool.GetQueuedCount()
}

func (a *txPoolAdapter) GetPendingNonce(addr types.Address) uint64 {
	return a.txPool.GetPendingNonce(addr)
}
func (a *txPoolAdapter) AddUserOperation(uo *encoding.UserOperation) error {
	return a.txPool.AddUserOperation(uo)
}

func (a *txPoolAdapter) GetUserOperation(hash types.Hash) *encoding.UserOperation {
	return a.txPool.GetUserOperation(hash)
}

func (a *txPoolAdapter) PendingUserOps() []*encoding.UserOperation {
	return a.txPool.PendingUserOps()
}

// chainInfoAdapter adapts Node to rpc.ChainInfo
type chainInfoAdapter struct {
	node *Node
}

func (a *chainInfoAdapter) ChainID() uint64 {
	return a.node.chainID
}

func (a *chainInfoAdapter) NetworkID() uint64 {
	if a.node.genesis != nil {
		return a.node.genesis.NetworkID
	}
	return 1
}

func (a *chainInfoAdapter) ProtocolVersion() string {
	return version.ProtocolVersion
}

func (a *chainInfoAdapter) IsSyncing() bool {
	return a.node.IsSyncing()
}

// audit-fix R6-L1: expose syncer's highest known block for accurate sync progress.
func (a *chainInfoAdapter) HighestBlock() uint64 {
	if a.node.syncer != nil {
		status := a.node.syncer.Status()
		return status.HighestBlock
	}
	return a.node.CurrentHeight()
}

func (a *chainInfoAdapter) PeerCount() int {
	return a.node.PeerCount()
}

func (a *chainInfoAdapter) GetPeers() []rpc.PeerInfo {
	if a.node.p2pHost == nil {
		return []rpc.PeerInfo{}
	}

	peers := a.node.p2pHost.Peers()
	result := make([]rpc.PeerInfo, 0, len(peers))

	for _, p := range peers {
		peerInfo := rpc.PeerInfo{
			ID:   string(p.ID),
			Name: fmt.Sprintf("Quantaureum/v%s", version.Version),
			Caps: []string{"qau/1"},
			Network: rpc.Network{
				LocalAddress:  a.node.config.ListenAddr,
				RemoteAddress: p.Addr,
			},
			Protocols: rpc.Protocol{
				Qau: &rpc.QauProtocol{
					Version:    1,
					Difficulty: "0x0",
					Head:       "0x0",
				},
			},
		}
		result = append(result, peerInfo)
	}

	return result
}

func (a *chainInfoAdapter) GetEnodeURL() string {
	if a.node.p2pHost == nil {
		return ""
	}
	return a.node.p2pHost.EnodeURL()
}

// FIX: GetListenAddr returns the configured P2P listen address.
func (a *chainInfoAdapter) GetListenAddr() string {
	if a.node == nil || a.node.config == nil {
		return ""
	}
	return a.node.config.ListenAddr
}

// FIX: GetAdvertisedIP returns the configured external/advertised IP.
func (a *chainInfoAdapter) GetAdvertisedIP() string {
	if a.node == nil || a.node.config == nil {
		return ""
	}
	return a.node.config.ExternalIP
}

// GetQPOSStatus returns the current QPOS consensus status
func (a *chainInfoAdapter) GetQPOSStatus() map[string]any {
	result := map[string]any{
		"consensus":     "QPOS",
		"slotDuration":  12,
		"slotsPerEpoch": 32,
	}

	// R87-STATE-TRUST (2026-08-29): surface local-state health. The
	// stateRootMismatches counter existed since R12 but had NO consumer, so a
	// node whose state had drifted from the network looked perfectly healthy
	// over RPC while it kept producing blocks. These three fields are the
	// operator-visible signal; stateProducing=false means this node is
	// following the chain but has stopped proposing on purpose.
	result["stateTrusted"] = a.node.IsStateTrusted()
	result["stateRootMismatchStreak"] = a.node.StateRootMismatchStreak()
	if detail := a.node.StateTrustDetail(); detail != "" {
		result["stateTrustDetail"] = detail
	}
	if a.node.syncer != nil {
		result["stateRootMismatchTotal"] = a.node.syncer.StateRootMismatches()
	}

	if a.node.blockProducer == nil || a.node.blockProducer.QPOS() == nil {
		result["error"] = "QPOS not initialized"
		return result
	}

	qpos := a.node.blockProducer.QPOS()
	currentSlot := qpos.GetCurrentSlot()
	currentEpoch := qpos.GetCurrentEpoch()

	result["currentSlot"] = currentSlot
	result["currentEpoch"] = currentEpoch
	result["slotInEpoch"] = currentSlot % consensus.SlotsPerEpoch
	result["justifiedEpoch"] = qpos.GetJustifiedEpoch()
	result["finalizedEpoch"] = qpos.GetFinalizedEpoch()

	// Get validator set info
	if vs := qpos.GetValidatorSet(); vs != nil {
		result["validatorCount"] = vs.Size()
		validators := vs.Validators()
		validatorInfos := make([]map[string]any, len(validators))
		for i, v := range validators {
			validatorInfos[i] = map[string]any{
				"address": hex.EncodeToString(v.Address[:]),
				"stake":   v.Stake.String(),
				"active":  v.Active,
				"slashed": qpos.IsSlashed(i),
			}
		}
		result["validators"] = validatorInfos
	}

	// Get proposer for current slot
	if proposer, err := qpos.GetProposerForSlot(currentSlot); err == nil && proposer != nil {
		result["currentProposer"] = hex.EncodeToString(proposer.Address[:])
	}

	// Get epoch summary
	if summary := qpos.GetEpochSummary(currentEpoch); summary != nil {
		result["epochSummary"] = map[string]any{
			"epoch":             summary.Epoch,
			"startSlot":         summary.StartSlot,
			"endSlot":           summary.EndSlot,
			"totalAttestations": summary.TotalAttestations,
			"participationRate": summary.ParticipationRate,
			"isJustified":       summary.IsJustified,
			"isFinalized":       summary.IsFinalized,
		}
	}

	// Get finality status
	result["finality"] = qpos.GetFinalityStatus()

	// Get epoch rewards if available
	// audit-fix R8-L2: guard against uint64 underflow when currentEpoch == 0.
	if currentEpoch > 0 {
		if rewards := qpos.GetEpochRewards(currentEpoch - 1); rewards != nil {
			result["lastEpochRewards"] = map[string]any{
				"epoch":              rewards.Epoch,
				"totalRewards":       rewards.TotalRewards.String(),
				"totalPenalties":     rewards.TotalPenalties.String(),
				"participatingStake": rewards.ParticipatingStake.String(),
				"totalStake":         rewards.TotalStake.String(),
			}
		}
	}

	// Get slashed validators
	slashed := qpos.GetSlashedValidators()
	if len(slashed) > 0 {
		result["slashedValidators"] = slashed
	}

	// Get proposer boost info
	boostRoot, boostSlot := qpos.GetProposerBoost()
	if boostSlot > 0 {
		result["proposerBoost"] = map[string]any{
			"blockRoot": hex.EncodeToString(boostRoot[:]),
			"slot":      boostSlot,
		}
	}

	// Get advanced QPOS status if available
	if a.node.blockProducer.QPOSAdvanced() != nil {
		advanced := a.node.blockProducer.QPOSAdvanced()
		result["advanced"] = map[string]any{
			"forkChoice":           advanced.GetForkChoice().GetForkChoiceStatus(),
			"inactivityLeakActive": advanced.GetInactivityLeakManager().IsLeakActive(),
			"pendingWithdrawals":   len(advanced.GetWithdrawalManager().GetPendingWithdrawals()),
		}

		// Sync committee info
		if sc := advanced.GetSyncCommitteeManager().GetCurrentCommittee(); sc != nil {
			result["syncCommittee"] = map[string]any{
				"period": sc.Period,
				"size":   len(sc.ValidatorIndices),
			}
		}
	}

	return result
}

// stakingManagerAdapter adapts economics.StakingManager to rpc.StakingManager
type stakingManagerAdapter struct {
	sm *economics.StakingManager
}

func (a *stakingManagerAdapter) Stake(addr types.Address, amount *big.Int, commission uint32, blockHeight uint64) error {
	return a.sm.Stake(addr, amount, commission, blockHeight)
}

func (a *stakingManagerAdapter) RequestUnstake(addr types.Address, amount *big.Int, blockHeight uint64) error {
	return a.sm.RequestUnstake(addr, amount, blockHeight)
}

func (a *stakingManagerAdapter) CompleteUnstake(addr types.Address, currentHeight uint64) (*big.Int, error) {
	return a.sm.CompleteUnstake(addr, currentHeight)
}

func (a *stakingManagerAdapter) GetStake(addr types.Address) (*rpc.StakeInfo, error) {
	stake, err := a.sm.GetStake(addr)
	if err != nil {
		return nil, err
	}
	return &rpc.StakeInfo{
		Address:     stake.Address,
		Amount:      stake.Amount,
		Commission:  stake.Commission,
		StakeHeight: stake.StakeHeight,
		Active:      stake.Active,
	}, nil
}

func (a *stakingManagerAdapter) GetUnstakeRequest(addr types.Address) (*rpc.UnstakeRequest, error) {
	req, err := a.sm.GetUnstakeRequest(addr)
	if err != nil {
		return nil, err
	}
	return &rpc.UnstakeRequest{
		Address:       req.Address,
		Amount:        req.Amount,
		RequestHeight: req.RequestHeight,
		UnlockHeight:  req.UnlockHeight,
	}, nil
}

func (a *stakingManagerAdapter) GetTotalStaked() *big.Int {
	return a.sm.GetTotalStaked()
}

func (a *stakingManagerAdapter) GetAllStakes() []*rpc.StakeInfo {
	stakes := a.sm.GetAllStakes()
	result := make([]*rpc.StakeInfo, len(stakes))
	for i, s := range stakes {
		result[i] = &rpc.StakeInfo{
			Address:     s.Address,
			Amount:      s.Amount,
			Commission:  s.Commission,
			StakeHeight: s.StakeHeight,
			Active:      s.Active,
		}
	}
	return result
}

func (a *stakingManagerAdapter) GetActiveValidators() map[types.Address]*big.Int {
	return a.sm.GetActiveValidators()
}

func (a *stakingManagerAdapter) ValidatorCount() int {
	return a.sm.ValidatorCount()
}

func (a *stakingManagerAdapter) ActiveValidatorCount() int {
	return a.sm.ActiveValidatorCount()
}

func (a *stakingManagerAdapter) GetConfig() *rpc.StakingConfig {
	cfg := a.sm.GetConfig()
	return &rpc.StakingConfig{
		MinStakeAmount:  cfg.MinStakeAmount,
		MaxStakeAmount:  cfg.MaxStakeAmount,
		UnbondingPeriod: cfg.UnbondingPeriod,
		MaxValidators:   cfg.MaxValidators,
		MinCommission:   cfg.MinCommission,
		MaxCommission:   cfg.MaxCommission,
	}
}

func (a *stakingManagerAdapter) GetRewardPoolStatus() map[string]any {
	return a.sm.GetRewardPoolStatus()
}

func (a *stakingManagerAdapter) GetTotalRewardsClaimed() *big.Int {
	return a.sm.GetTotalRewardsClaimed()
}

func (a *stakingManagerAdapter) UpdateCommission(caller, addr types.Address, commission uint32) error {
	return a.sm.UpdateCommission(caller, addr, commission)
}

func (a *stakingManagerAdapter) SaveState() error {
	return a.sm.SaveState()
}

// StakingManager returns the staking manager
func (n *Node) StakingManager() *economics.StakingManager {
	return n.stakingManager
}

// DeFiManager returns the DeFi manager
func (n *Node) DeFiManager() *economics.DeFiManager {
	return n.defiManager
}

// tssSignerAdapter adapts tss.TSSManager to consensus.ThresholdKeySigner
type tssSignerAdapter struct {
	tss  *tss.TSSManager
	node *Node // Non-nil when TSSDistributedMode is enabled, for P2P coordination
}

func newTSSSignerAdapter(mgr *tss.TSSManager) *tssSignerAdapter {
	return &tssSignerAdapter{tss: mgr}
}

// newTSSSignerAdapterWithNode creates an adapter that uses distributed P2P signing.
func newTSSSignerAdapterWithNode(mgr *tss.TSSManager, node *Node) *tssSignerAdapter {
	return &tssSignerAdapter{tss: mgr, node: node}
}

func (a *tssSignerAdapter) SignBlock(validatorIndex int, message []byte) ([]byte, error) {
	participants := a.allParticipantIDs()
	if len(participants) < a.tss.Threshold() {
		return nil, fmt.Errorf("insufficient participants for threshold signing: have %d, need %d", len(participants), a.tss.Threshold())
	}
	// AUDIT (2026) TSS-FIX (CRITICAL): Distributed TSS signing is
	// NOT fully safe yet. The previous design transmitted SEPARATE masked
	// contributions Cs2Share (λ_i·c·s2_i) and Ct0Share (λ_i·c·t0_i), which
	// allowed the aggregator to invert the challenge polynomial c in the NTT
	// ring Z_q[X]/(X^256+1) and recover s2 and t0 separately, then s1 via
	// A·s1 = t - s2, reconstructing the FULL Dilithium3 private key.
	//
	// The Round5 fix COMBINES the two contributions into a single Z0Share =
	// λ_i·c·(t0_i - s2_i) which the aggregator CANNOT decompose. This reduces
	// the vulnerability from Critical (full key recovery) to High (s1 recovery
	// only) — the aggregator can recover s1 but CANNOT recover s2 or t0
	// individually, so it CANNOT forge signatures.
	//
	// RESIDUAL RISK (High): Full closure requires DH-based pairwise masking or
	// distributed hint generation. Until then, distributed TSS is HARD-BLOCKED
	// in production via the distributedTSSEnabled() two-key gate
	// (QAU_PRODUCTION=1 requires QAU_ALLOW_UNSAFE_DISTRIBUTED_TSS=1).
	// Raw s2_i/t0_i shares NEVER traverse the wire in either design.
	if a.node != nil && a.node.distributedSigner != nil && distributedTSSEnabled() {
		// R7 P0-3 FIX (TSS-, 2026-07-17): Use distributeTSSSignNoFallback
		// instead of DistributeTSSSign (allowFallback=true). Previously, a
		// distributed signing failure (e.g., DoS-induced timeout) silently fell
		// back to local SignWithRetry, downgrading t-of-n threshold security to
		// 1-of-n. Now a failure returns an error so the caller can fail-and-skip
		// (fail-safe, prefer-no-op) rather than producing a single-signer block/vote signature.
		return a.node.distributeTSSSignNoFallback(message, participants)
	}
	return a.tss.SignWithRetry(message, participants)
}

func (a *tssSignerAdapter) SignVote(validatorIndex int, message []byte) ([]byte, error) {
	participants := a.allParticipantIDs()
	if len(participants) < a.tss.Threshold() {
		return nil, fmt.Errorf("insufficient participants for threshold signing: have %d, need %d", len(participants), a.tss.Threshold())
	}
	// AUDIT (2026) TSS-FIX: Same as SignBlock — distributed TSS
	// now transmits only masked contributions and is safe to enable.
	// R7 P0-3 FIX (TSS-): Use no-fallback path to preserve threshold.
	if a.node != nil && a.node.distributedSigner != nil && distributedTSSEnabled() {
		return a.node.distributeTSSSignNoFallback(message, participants)
	}
	return a.tss.SignWithRetry(message, participants)
}

func (a *tssSignerAdapter) allParticipantIDs() []int {
	if a.tss == nil {
		return nil
	}
	ids := make([]int, 0, a.tss.TotalShares())
	for i := 1; i <= a.tss.TotalShares(); i++ {
		ids = append(ids, i)
	}
	return ids
}

func (a *tssSignerAdapter) VerifyBlock(pubKey []byte, message []byte, signature []byte) bool {
	if a.tss == nil {
		return false
	}
	// R33 CONS-02 FIX (2026-07-28): Honor the pubKey parameter. Previously
	// this method ignored pubKey entirely and always used the current group
	// public key via VerifyCombinedSignature. After a DKG rotation, the group
	// key changes, so historical block signatures would be rejected,
	// causing nodes to disagree on finality for old epochs and split the
	// chain. When pubKey is provided (non-empty), use it; otherwise fall
	// back to the current group key for backward compatibility.
	if len(pubKey) > 0 {
		err := a.tss.VerifySignatureWithPublicKey(pubKey, message, signature)
		return err == nil
	}
	err := a.tss.VerifyCombinedSignature(signature, message)
	return err == nil
}

func (a *tssSignerAdapter) VerifyVote(pubKey []byte, message []byte, signature []byte) bool {
	return a.VerifyBlock(pubKey, message, signature)
}

func (a *tssSignerAdapter) GroupPublicKey() []byte {
	if a.tss == nil {
		return nil
	}
	return a.tss.GroupPublicKey()
}

func (a *tssSignerAdapter) IsThresholdMode() bool {
	if a.tss == nil {
		return false
	}
	return a.tss.HasThreshold()
}

// AggregatePartialSignatures combines collected partial signatures from
// multiple validators into a single threshold signature.
//
// P0-1 FIX (2026-07-13): The previous implementation ignored the partialSigs
// parameter entirely and used SignWithRetry to produce ALL partial signatures
// locally. This allowed any single node holding >= threshold key shares to
// forge a "threshold" signature, defeating the t-of-n security guarantee.
//
// New behavior:
//   - Distributed mode (TSSDistributedMode=true): uses distributeTSSSignNoFallback
//     which enforces strict P2P multi-party signing. Failure does NOT fall back
//     to local SignWithRetry — the seal remains pending for retry.
//   - Local mode + external partialSigs: fail-closed (cannot safely aggregate
//     external partial signatures without a distributed signer to verify provenance).
//   - Local mode + no external partialSigs: SignWithRetry for test/development
//     only. Logs a warning that this is not production-safe.
//
// AggregatePartialSignatures combines collected partial signatures from
// distributed P2P signers into the final threshold signature.
//
// SECURITY (audit R3 TSS- B-1): The distributed signing path transmits
// raw S2/T0 secret-key shares to the aggregator (= block proposer), allowing
// any single validator who becomes proposer to reconstruct the full group
// signing key. This is the SAME vulnerability as SignBlock/SignVote (R2-CRIT-01).
//
// The previous fix (R2-CRIT-01) added an env kill-switch (QAU_ENABLE_DISTRIBUTED_TSS)
// to SignBlock/SignVote, but MISSED this sealing path — AggregatePartialSignatures
// only checked `distributedSigner != nil`, not `distributedTSSEnabled()`. This
// meant that setting TSSDistributedMode=true alone (without the env var) would
// route sealing through the share-leaking protocol.
//
// Now this path is also gated by distributedTSSEnabled(). Until the protocol
// is redesigned to never transmit raw shares, distributed sealing is disabled
// by default. Production MUST NOT enable QAU_ENABLE_DISTRIBUTED_TSS until the
// TSS- protocol redesign is complete.
func (a *tssSignerAdapter) AggregatePartialSignatures(sealers []int, partialSigs map[int][]byte, message []byte) ([]byte, error) {
	if a.tss == nil {
		return nil, fmt.Errorf("tss: TSSManager is nil")
	}
	if len(sealers) < a.tss.Threshold() {
		return nil, fmt.Errorf("insufficient sealers for threshold: have %d, need %d", len(sealers), a.tss.Threshold())
	}

	// SECURITY (audit R3 TSS- B-1): Distributed sealing path MUST be
	// gated by the same env kill-switch as SignBlock/SignVote. Without this
	// check, TSSDistributedMode=true alone routes sealing through the
	// share-leaking protocol, bypassing the R2-CRIT-01 mitigation.
	if a.node != nil && a.node.distributedSigner != nil && distributedTSSEnabled() {
		sig, err := a.node.distributeTSSSignNoFallback(message, sealers)
		if err != nil {
			// Do NOT fall back to local SignWithRetry. The seal remains
			// pending so participants can re-submit. This preserves the
			// t-of-n threshold security guarantee.
			return nil, fmt.Errorf("strict distributed TSS signing failed (no fallback): %w", err)
		}
		return sig, nil
	}

	// Local mode (no distributed signer): cannot safely aggregate external
	// partial signatures. The partialSigs came from P2P (SubmitPartialSeal)
	// but without a distributed signer we cannot verify their provenance or
	// aggregate them via the QTD protocol.
	if len(partialSigs) > 0 {
		return nil, fmt.Errorf("cannot aggregate %d external partial signatures in local TSS mode: enable TSSDistributedMode=true for threshold signing", len(partialSigs))
	}

	// Local mode with no external partialSigs: test/development only.
	// SignWithRetry uses locally stored qtdShares to produce all partial
	// signatures — this is NOT threshold security and must not be used
	// in production. In production, TSSDistributedMode must be enabled.
	nodeLog.Warn("AggregatePartialSignatures: using local SignWithRetry (test/development mode only, not for production)")
	return a.tss.SignWithRetry(message, sealers)
}

// snapshotManagerAdapter adapts Node to rpc.SnapshotManager
type snapshotManagerAdapter struct {
	node *Node
}

func newSnapshotManagerAdapter(n *Node) *snapshotManagerAdapter {
	return &snapshotManagerAdapter{node: n}
}

func (a *snapshotManagerAdapter) CreateSnapshot(blockHeight uint64) (map[string]any, error) {
	if a.node == nil || a.node.stateDB == nil {
		return nil, fmt.Errorf("node or stateDB not available")
	}

	// Create the snapshot
	if err := a.node.stateDB.CreateSnapshot(blockHeight); err != nil {
		return nil, fmt.Errorf("failed to create snapshot: %w", err)
	}

	// Get pruning stats for info
	enabled, keepBlocks, lastPruned, snapshotCount := a.node.stateDB.GetPruningStats()

	result := map[string]any{
		"success":        true,
		"blockHeight":    blockHeight,
		"snapshotCount":  snapshotCount,
		"pruningEnabled": enabled,
		"keepBlocks":     keepBlocks,
		"lastPruned":     lastPruned,
	}

	return result, nil
}

func (a *snapshotManagerAdapter) RestoreSnapshot(blockHeight uint64) (map[string]any, error) {
	if a.node == nil || a.node.stateDB == nil {
		return nil, fmt.Errorf("node or stateDB not available")
	}

	// Revert to the snapshot at the given block height
	a.node.stateDB.RevertToSnapshot(int(blockHeight))

	result := map[string]any{
		"success":     true,
		"blockHeight": blockHeight,
		"message":     "State reverted to snapshot",
	}

	return result, nil
}

// consensusStakeUpdaterAdapter bridges RPC staking operations to the consensus
// ValidatorManager AND the QPOS ValidatorSet cache. When qau_stake updates the
// economics StakingManager, this adapter propagates the change to both:
//  1. ValidatorManager (for persistence and ValidatorInfo)
//  2. QPOS.validators (for proposer selection and finality voting)
//
// Without updating QPOS.validators, QPOS still sees stake=0 and participation
// rate stays low, preventing finality.
type consensusStakeUpdaterAdapter struct {
	vm   *consensus.ValidatorManager
	qpos *consensus.QPOS
}

func (a *consensusStakeUpdaterAdapter) UpdateValidatorStake(addr types.Address, stake *big.Int, commission uint32, blockHeight uint64) error {
	if a.vm != nil && a.vm.IsValidator(addr) {
		if err := a.vm.UpdateStake(addr, addr, stake); err != nil {
			return err
		}
	}
	// Update QPOS ValidatorSet cache so proposer selection sees the new stake.
	// AddStakingValidator handles both new and existing validators (updates stake
	// if already present, adds if new).
	if a.qpos != nil {
		a.qpos.AddStakingValidator(addr, stake)
	}
	return nil
}

func (a *consensusStakeUpdaterAdapter) IsKnownValidator(addr types.Address) bool {
	if a.vm == nil {
		return false
	}
	return a.vm.IsValidator(addr)
}

// blockStoreReaderAdapter adapts BlockStore to the BlockStoreReader interface
// required by HistoryExpirer. BlockStore does not natively implement
// DeleteBlockRange or GetOldestHeight, so this adapter bridges the gap.
type blockStoreReaderAdapter struct {
	blockStore *block.BlockStore
}

func (a *blockStoreReaderAdapter) GetBlockByHeight(height uint64) (*encoding.Block, error) {
	return a.blockStore.GetBlockByHeight(height)
}

// DeleteBlockRange removes blocks in the [from, to] height range (inclusive).
// Blocks that do not exist (already pruned) are silently skipped.
func (a *blockStoreReaderAdapter) DeleteBlockRange(from, to uint64) (uint64, error) {
	var deleted uint64
	for h := from; h <= to; h++ {
		if err := a.blockStore.DeleteBlockAtHeight(h); err != nil {
			continue // block may not exist (already pruned); skip silently
		}
		deleted++
	}
	return deleted, nil
}

func (a *blockStoreReaderAdapter) GetLatestHeight() uint64 {
	height, err := a.blockStore.GetLatestHeight()
	if err != nil {
		return 0
	}
	return height
}

// GetOldestHeight returns the oldest block height known to the store.
// BlockStore does not track this explicitly, so we return 0 (genesis)
// as the conservative lower bound.
func (a *blockStoreReaderAdapter) GetOldestHeight() uint64 {
	return 0
}

// forkRecoveryBackend adapts Node to rpc.ForkRecoveryManager.
//
// R45-FORKRECOVERY-API (2026-08-12): Used by the debug_rollbackChainToHeight
// RPC endpoint to manually resolve a persistent chain fork that the
// syncer-side OnForkRollback cannot (in particular: when the local chain
// tip is a self-signed "ghost" block produced during the brief window of
// the buggy R45-WARMUP-EXPAND-FIX sealer schedule, and the canonical
// peer chain has propagated beyond it — syncer logic alone can't
// reconcile because it trusts parentHash continuity and rejects a
// candidate fork when local tip height == peer tip height but hash
// differs).
type forkRecoveryBackend struct {
	node *Node
}

func newForkRecoveryBackend(n *Node) *forkRecoveryBackend {
	return &forkRecoveryBackend{node: n}
}

// RollbackToFork deletes all blocks at or above forkHeight from the block
// store and rewinds stateDB to the same height. After this returns, the
// syncer resumes from peers — only accepting canonical (peer-signed)
// blocks, eliminating the locally-poisoned branch.
func (a *forkRecoveryBackend) RollbackToFork(forkHeight uint64) (int, error) {
	if a.node == nil {
		return 0, fmt.Errorf("node unavailable")
	}
	if a.node.blockStore == nil {
		return 0, fmt.Errorf("blockStore unavailable")
	}
	if forkHeight == 0 {
		return 0, fmt.Errorf("refusing to rollback to height 0 (genesis re-seed protection)")
	}

	// First, truncate block store at/above forkHeight.
	deleted, err := a.node.blockStore.DeleteBlocksFromHeight(forkHeight)
	if err != nil {
		nodeLog.Error("ForkRecovery: DeleteBlocksFromHeight(%d) failed: %v", forkHeight, err)
		return 0, fmt.Errorf("DeleteBlocksFromHeight: %w", err)
	}
	nodeLog.Info("ForkRecovery: deleted %d blocks from blockStore at/above height %d", deleted, forkHeight)

	// Roll back stateDB to the same forkHeight so balances, contract
	// storage, and nonces are reset to their state at forkHeight-1.
	if a.node.stateDB != nil {
		if err := a.node.stateDB.RollbackToHeight(forkHeight); err != nil {
			nodeLog.Error("ForkRecovery: stateDB.RollbackToHeight(%d) failed: %v", forkHeight, err)
			return deleted, fmt.Errorf("stateDB.RollbackToHeight: %w", err)
		}
		nodeLog.Info("ForkRecovery: stateDB rolled back to height %d", forkHeight)
	}

	// R45-WARMUP-REVERT-FIX (2026-08-12): Clear the QPOS cold-start epoch
	// flags since the local schedule was poisoned by the buggy placeholder
	// accumulator pre-load earlier. After rollback, the syncer will
	// re-import canonical blocks and SetEpochVRFAccumulator will re-build
	// the schedule from the authoritative on-chain values.
	if a.node.blockProducer != nil && a.node.blockProducer.QPOS() != nil {
		if cleared := a.node.blockProducer.QPOS().ClearColdStartEpochs(); cleared > 0 {
			nodeLog.Info("ForkRecovery: cleared %d stale QPOS cold-start epoch flags after rollback", cleared)
		}
	}

	// Reset syncer's cached tip so the next requestBlocks call starts
	// from the new tip and not the stale cached height. ClearPendingBlocks
	// also drops any queued fork-candidate blocks that were filtered
	// during the rollback.
	if a.node.syncer != nil {
		a.node.syncer.ClearPendingBlocks()
		nodeLog.Info("ForkRecovery: syncer pending blocks cleared")
	}

	nodeLog.Info("ForkRecovery: rollback to fork height %d complete. Syncer will resume from peers.", forkHeight)
	return deleted, nil
}

// graphqlReaderAdapter adapts Node's blockStore/stateDB to graphql.BlockchainReader.
// This enables the GraphQL resolver to query blockchain data (blocks, accounts,
// transactions, chain info) through a clean read-only interface.
type graphqlReaderAdapter struct {
	node *Node
}

// GetBlockByNumber retrieves a block by its height number.
func (a *graphqlReaderAdapter) GetBlockByNumber(number uint64) (*encoding.Block, error) {
	return a.node.blockStore.GetBlockByHeight(number)
}

// GetBlockByHash retrieves a block by its hash.
func (a *graphqlReaderAdapter) GetBlockByHash(hash types.Hash) (*encoding.Block, error) {
	return a.node.blockStore.GetBlock(hash)
}

// GetLatestBlock retrieves the latest committed block.
func (a *graphqlReaderAdapter) GetLatestBlock() (*encoding.Block, error) {
	return a.node.blockStore.GetLatestBlock()
}

// GetBlockRange retrieves blocks in the [from, to] height range (inclusive).
// Blocks that cannot be retrieved are silently skipped.
func (a *graphqlReaderAdapter) GetBlockRange(from, to uint64) ([]*encoding.Block, error) {
	if to < from {
		return nil, nil
	}
	// L11-024 + L14-013: Limit the range to prevent excessive resource consumption (DoS).
	// Block range for log queries is capped at 5000 to prevent memory exhaustion
	// from large range queries via GraphQL eth_getLogs.
	const maxBlockRange = 5000
	if to-from+1 > maxBlockRange {
		return nil, fmt.Errorf("block range too large: requested %d, max %d", to-from+1, maxBlockRange)
	}
	blocks := make([]*encoding.Block, 0, to-from+1)
	for h := from; h <= to; h++ {
		blk, err := a.node.blockStore.GetBlockByHeight(h)
		if err != nil {
			continue
		}
		blocks = append(blocks, blk)
	}
	return blocks, nil
}

// GetAccount retrieves the state of an account at a specific block number.
func (a *graphqlReaderAdapter) GetAccount(address types.Address, blockNumber uint64) (*graphql.AccountState, error) {
	sdb := a.node.stateDB
	if sdb == nil {
		return nil, fmt.Errorf("stateDB not available")
	}
	acc, err := sdb.GetAccount(address)
	if err != nil {
		return nil, err
	}
	if acc == nil {
		return nil, nil
	}
	return &graphql.AccountState{
		Address:     address,
		Balance:     acc.Balance,
		Nonce:       acc.Nonce,
		Code:        sdb.GetCode(address),
		CodeHash:    acc.CodeHash,
		StorageRoot: acc.StorageRoot,
	}, nil
}

// GetTransaction retrieves a transaction and its location by hash.
func (a *graphqlReaderAdapter) GetTransaction(hash types.Hash) (*encoding.Transaction, *graphql.TxLocation, error) {
	tx, loc, err := a.node.blockStore.GetTransaction(hash)
	if err != nil {
		return nil, nil, err
	}
	if loc == nil {
		return tx, nil, nil
	}
	return tx, &graphql.TxLocation{
		BlockHash:   loc.BlockHash,
		BlockNumber: loc.BlockNumber,
		Index:       uint64(loc.TxIndex), //nolint:gosec,G115
	}, nil
}

// GetTransactionReceipt retrieves a transaction receipt.
// Receipts are not stored separately in the block store; returning nil
// causes the GraphQL resolver to fall back to tx.GasLimit for gas accounting.
func (a *graphqlReaderAdapter) GetTransactionReceipt(hash types.Hash) (*graphql.Receipt, error) {
	return nil, nil
}

// ChainID returns the chain ID.
func (a *graphqlReaderAdapter) ChainID() uint64 {
	return a.node.chainID
}

// GasPrice returns the current gas price.
//
// AUDIT (2026) R3-NODE-04/05 FIX: Previously returned a hardcoded 1 Gwei
// literal, ignoring the chain's actual base fee and the central default
// constant. Now mirrors the logic of rpc.API.GasPrice:
//  1. If the latest block has a positive BaseFee, return it.
//  2. Otherwise fall back to rpc.DefaultGasPriceWei (the same constant used
//     by the JSON-RPC eth_gasPrice endpoint).
//
// This keeps GraphQL and JSON-RPC consumers observing the same gas price.
func (a *graphqlReaderAdapter) GasPrice() *big.Int {
	if a.node != nil && a.node.blockStore != nil {
		if latestHeight, err := a.node.blockStore.GetLatestHeight(); err == nil && latestHeight > 0 {
			if blk, err := a.node.blockStore.GetBlockByHeight(latestHeight); err == nil && blk != nil {
				if blk.Header.BaseFee != nil && blk.Header.BaseFee.Sign() > 0 {
					return new(big.Int).Set(blk.Header.BaseFee)
				}
			}
		}
	}
	return big.NewInt(rpc.DefaultGasPriceWei)
}

// CurrentBlockNumber returns the latest block height.
func (a *graphqlReaderAdapter) CurrentBlockNumber() uint64 {
	h, err := a.node.blockStore.GetLatestHeight()
	if err != nil {
		return 0
	}
	return h
}
