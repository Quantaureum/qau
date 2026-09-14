// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/quantaureum/qau/types"
)

// SparseMerkleTreeDepth is the depth of the sparse Merkle tree.
// W-P1-6 FIX (2026-07-14): Uses 160 to match the account address bit width
// (types.Address is 20 bytes = 160 bits). Each bit of the address selects
// left (0) or right (1) at each level, so every account has a unique leaf
// position. This enables O(log₂ N) = O(160) inclusion proofs for any
// account, which is the foundation for trust-minimized L2→L1 withdrawals.
const SparseMerkleTreeDepth = 160

// smtZeroHashes caches the root of an all-zero subtree at each depth.
// ZeroHashes[0] = SHA256(empty leaf), ZeroHashes[i] = SHA256(ZeroHashes[i-1] || ZeroHashes[i-1]).
// Pre-computing these avoids recomputing 160 hashes on every Insert/Prove.
// W-P1-6 FIX (2026-07-14)
var smtZeroHashes [SparseMerkleTreeDepth + 1]types.Hash

func init() {
	// Depth 0: empty leaf = SHA256 of nothing (represents a non-existent account).
	smtZeroHashes[0] = sha256.Sum256(nil)
	// Depth i: parent of two zero children.
	for i := 1; i <= SparseMerkleTreeDepth; i++ {
		h := sha256.New()
		h.Write(smtZeroHashes[i-1][:])
		h.Write(smtZeroHashes[i-1][:])
		copy(smtZeroHashes[i][:], h.Sum(nil))
	}
}

// SparseMerkleTree is a binary sparse Merkle tree with fixed depth 160.
//
// Design (W-P1-6 FIX 2026-07-14):
//   - Key space: 2^160 (one leaf per possible account address)
//   - Storage: only non-zero nodes are stored in `nodes` map; zero subtrees
//     are represented by the pre-computed smtZeroHashes cache
//   - Leaf value: SHA256(account data) — set by the caller (StateManager
//     computes this as hash of nonce||balance||codeHash||storageRoot)
//   - Insert cost: O(160) SHA256 operations
//   - Prove cost: O(160) map lookups (one per level)
//   - Verify cost: O(160) SHA256 operations
//   - Memory: O(N * 160) where N = number of non-zero accounts (each Insert
//     touches at most 160 nodes, most shared along the path)
//
// Thread-safety: all public methods acquire smt.mu. Callers MUST NOT hold
// the lock across multiple calls (e.g. batch inserts) — use BatchInsert
// instead, which holds the lock for the entire batch.
type SparseMerkleTree struct {
	mu    sync.RWMutex
	nodes map[smtNodeKey]types.Hash // nodeKey → hash
	root  types.Hash
}

// smtNodeKey is the map key for SparseMerkleTree.nodes.
// It encodes the node's position in the tree: depth + path prefix.
// W-P1-6 FIX (2026-07-14)
type smtNodeKey struct {
	depth uint8
	// path stores the full 20 bytes of the address. The depth field
	// determines how many bits are relevant for this node's position:
	// at depth d, only the first d bits of path are meaningful (the
	// remaining bits are ignored in comparisons because they describe
	// children below this node). This works because Go struct equality
	// compares all fields — two smtNodeKey values are equal only if both
	// depth and the full 20-byte path match, which uniquely identifies
	// a node on the path from root to leaf(addr).
	path [20]byte
}

// NewSparseMerkleTree creates an empty SMT with the all-zero root.
// W-P1-6 FIX (2026-07-14)
func NewSparseMerkleTree() *SparseMerkleTree {
	return &SparseMerkleTree{
		nodes: make(map[smtNodeKey]types.Hash),
		root:  smtZeroHashes[SparseMerkleTreeDepth],
	}
}

// Root returns the current Merkle root.
// W-P1-6 FIX (2026-07-14)
func (smt *SparseMerkleTree) Root() types.Hash {
	smt.mu.RLock()
	defer smt.mu.RUnlock()
	return smt.root
}

// Insert sets the leaf value for the given address key and updates all
// ancestor nodes along the path to the root.
// W-P1-6 FIX (2026-07-14)
func (smt *SparseMerkleTree) Insert(addr types.Address, leafHash types.Hash) {
	smt.mu.Lock()
	defer smt.mu.Unlock()
	smt.insertLocked(addr, leafHash)
}

// insertLocked is the lock-free version of Insert. Caller MUST hold smt.mu.
// W-P1-6 FIX (2026-07-14)
func (smt *SparseMerkleTree) insertLocked(addr types.Address, leafHash types.Hash) {
	// Walk from leaf (depth 160) up to root (depth 0), updating each node.
	currentHash := leafHash
	currentDepth := SparseMerkleTreeDepth
	currentPath := addr // 20 bytes

	// Set the leaf node.
	smt.nodes[smtNodeKey{depth: uint8(currentDepth), path: currentPath}] = currentHash

	// Walk up to the root.
	for currentDepth > 0 {
		currentDepth--
		// Determine if currentPath's bit at currentDepth is 0 (left) or 1 (right).
		// Bit indexing: bit 0 is the MSB of byte 0 (most significant bit first).
		bitIndex := currentDepth // 159 down to 0
		byteIndex := bitIndex / 8
		bitInByte := 7 - (bitIndex % 8)
		isRight := (currentPath[byteIndex] >> bitInByte) & 1

		// Compute sibling path: flip the bit at currentDepth.
		siblingPath := currentPath
		siblingPath[byteIndex] ^= (1 << bitInByte)

		// Get sibling hash (zero if not in map).
		// Bug 3 FIX: smtZeroHashes[k] is the root of a zero subtree k levels
		// tall (from leaf). A missing sibling at depth (currentDepth+1) has
		// (SparseMerkleTreeDepth - (currentDepth+1)) levels below it, so the
		// correct zero hash index is SparseMerkleTreeDepth-(currentDepth+1).
		siblingHash, ok := smt.nodes[smtNodeKey{depth: uint8(currentDepth + 1), path: siblingPath}]
		if !ok {
			siblingHash = smtZeroHashes[SparseMerkleTreeDepth-(currentDepth+1)]
		}

		// Compute parent hash: if isRight, current is right child.
		h := sha256.New()
		if isRight == 1 {
			h.Write(siblingHash[:]) // left
			h.Write(currentHash[:]) // right
		} else {
			h.Write(currentHash[:]) // left
			h.Write(siblingHash[:]) // right
		}
		currentHash = types.Hash{}
		copy(currentHash[:], h.Sum(nil))

		// Bug 2 FIX: Truncate BEFORE storing. The node at depth currentDepth
		// must have bits currentDepth..159 all zeroed in its path (only bits
		// 0..currentDepth-1 are meaningful as the path prefix from root).
		// siblingPath was already computed from the pre-truncation currentPath
		// (which is correct because the sibling at depth currentDepth+1 needs
		// bit currentDepth from the original address), so truncating here is
		// safe. Storing after truncation ensures that lookups from other
		// branches (which construct sibling paths using already-truncated
		// paths) will find this node.
		currentPath[byteIndex] &^= (1 << bitInByte)

		// Store parent node with truncated path.
		smt.nodes[smtNodeKey{depth: uint8(currentDepth), path: currentPath}] = currentHash
	}

	smt.root = currentHash
}

// Get returns the leaf hash for the given address, or the zero leaf hash
// if the account is not in the tree.
// W-P1-6 FIX (2026-07-14)
func (smt *SparseMerkleTree) Get(addr types.Address) (types.Hash, bool) {
	smt.mu.RLock()
	defer smt.mu.RUnlock()
	h, ok := smt.nodes[smtNodeKey{depth: uint8(SparseMerkleTreeDepth), path: addr}]
	return h, ok
}

// MerkleProof is a compact inclusion proof for a leaf in the SMT.
// Siblings[i] is the hash of the sibling node at depth (SparseMerkleTreeDepth - i),
// for i = 0..SparseMerkleTreeDepth-1 (leaf-to-root order).
// W-P1-6 FIX (2026-07-14)
type MerkleProof struct {
	LeafHash types.Hash
	Siblings []types.Hash // length = SparseMerkleTreeDepth (160)
}

// Prove generates a Merkle inclusion proof for the given address.
// Returns the proof and the leaf hash. If the account is not in the tree,
// returns a proof for the zero leaf (which proves non-inclusion when
// verified against the zero leaf hash).
// W-P1-6 FIX (2026-07-14)
func (smt *SparseMerkleTree) Prove(addr types.Address) (*MerkleProof, error) {
	smt.mu.RLock()
	defer smt.mu.RUnlock()

	leafHash, ok := smt.nodes[smtNodeKey{depth: uint8(SparseMerkleTreeDepth), path: addr}]
	if !ok {
		leafHash = smtZeroHashes[0] // non-inclusion proof
	}

	proof := &MerkleProof{
		LeafHash: leafHash,
		Siblings: make([]types.Hash, SparseMerkleTreeDepth),
	}

	currentPath := addr
	for depth := SparseMerkleTreeDepth; depth > 0; depth-- {
		// Sibling is at depth, with sibling path.
		bitIndex := depth - 1 // bit at this level
		byteIndex := bitIndex / 8
		bitInByte := 7 - (bitIndex % 8)

		siblingPath := currentPath
		siblingPath[byteIndex] ^= (1 << bitInByte)

		siblingHash, ok := smt.nodes[smtNodeKey{depth: uint8(depth), path: siblingPath}]
		if !ok {
			// Bug 3 FIX: sibling at depth `depth` has (SparseMerkleTreeDepth -
			// depth) levels below it, so the zero hash is indexed by height
			// from leaf = SparseMerkleTreeDepth - depth.
			siblingHash = smtZeroHashes[SparseMerkleTreeDepth-depth]
		}
		proof.Siblings[SparseMerkleTreeDepth-depth] = siblingHash

		// Progressive path truncation: zero the bit at (depth-1) so
		// that on the next iteration, currentPath has bits
		// (depth-1)..159 zeroed, matching the truncated paths used by
		// insertLocked. Without this, sibling lookups use full-address
		// paths that don't match the truncated keys in the nodes map.
		currentPath[byteIndex] &^= (1 << bitInByte)
	}

	return proof, nil
}

// VerifyMerkleProof verifies a Merkle inclusion proof against the expected root.
// Returns true if the proof is valid (leafHash + siblings hash up to expectedRoot).
// W-P1-6 FIX (2026-07-14)
func VerifyMerkleProof(addr types.Address, proof *MerkleProof, expectedRoot types.Hash) bool {
	if proof == nil || len(proof.Siblings) != SparseMerkleTreeDepth {
		return false
	}

	currentHash := proof.LeafHash
	currentPath := addr

	for i := 0; i < SparseMerkleTreeDepth; i++ {
		depth := SparseMerkleTreeDepth - i // depth of the sibling
		bitIndex := depth - 1
		byteIndex := bitIndex / 8
		bitInByte := 7 - (bitIndex % 8)
		isRight := (currentPath[byteIndex] >> bitInByte) & 1

		sibling := proof.Siblings[i]

		h := sha256.New()
		if isRight == 1 {
			h.Write(sibling[:])     // left
			h.Write(currentHash[:]) // right
		} else {
			h.Write(currentHash[:]) // left
			h.Write(sibling[:])     // right
		}
		currentHash = types.Hash{}
		copy(currentHash[:], h.Sum(nil))
	}

	return currentHash == expectedRoot
}

// BatchInsert inserts multiple (addr, leafHash) pairs in a single lock
// acquisition. More efficient than calling Insert N times when updating
// many accounts (e.g. after ProcessBatch).
// W-P1-6 FIX (2026-07-14)
func (smt *SparseMerkleTree) BatchInsert(entries map[types.Address]types.Hash) {
	smt.mu.Lock()
	defer smt.mu.Unlock()
	for addr, leafHash := range entries {
		smt.insertLocked(addr, leafHash)
	}
}

// Clone returns a deep copy of the SMT. Used by StateManager to snapshot
// the tree for historical state (SimulateBatch / fraud proofs).
// W-P1-6 FIX (2026-07-14)
func (smt *SparseMerkleTree) Clone() *SparseMerkleTree {
	smt.mu.RLock()
	defer smt.mu.RUnlock()
	clone := &SparseMerkleTree{
		nodes: make(map[smtNodeKey]types.Hash, len(smt.nodes)),
		root:  smt.root,
	}
	for k, v := range smt.nodes {
		clone.nodes[k] = v
	}
	return clone
}

// Size returns the number of non-zero nodes in the tree (for diagnostics).
// W-P1-6 FIX (2026-07-14)
func (smt *SparseMerkleTree) Size() int {
	smt.mu.RLock()
	defer smt.mu.RUnlock()
	return len(smt.nodes)
}

// --- Leaf hash computation ---

// ComputeAccountLeafHash computes the SMT leaf hash for an L2 account.
// The leaf hash covers: addr || nonce || balanceLen || balance || codeHash || storageRoot
// W-P1-6 FIX (2026-07-14)
func ComputeAccountLeafHash(addr types.Address, acc *RollupAccount) types.Hash {
	if acc == nil {
		return smtZeroHashes[0]
	}
	return computeAccountLeafHashWithStorageRoot(addr, acc, computeStorageRoot(acc.Storage))
}

// computeAccountLeafHashWithStorageRoot computes the SMT leaf hash for an
// L2 account using a caller-supplied storage root. This is used by the
// L1 bridge withdrawal verification (audit R4-BRDG-02) where the storage
// root is attested in the MerkleWithdrawalProof rather than recomputed
// from the in-memory storage map (which the L1 side does not have).
func computeAccountLeafHashWithStorageRoot(addr types.Address, acc *RollupAccount, storageRoot types.Hash) types.Hash {
	if acc == nil {
		return smtZeroHashes[0]
	}
	h := sha256.New()
	h.Write(addr[:])

	// Nonce (8 bytes BE)
	var nonceBuf [8]byte
	binary.BigEndian.PutUint64(nonceBuf[:], acc.Nonce)
	h.Write(nonceBuf[:])

	// Balance (length-prefixed)
	var balanceBytes []byte
	if acc.Balance != nil {
		balanceBytes = acc.Balance.Bytes()
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(balanceBytes)))
	h.Write(lenBuf[:])
	h.Write(balanceBytes)

	// CodeHash (32 bytes)
	h.Write(acc.CodeHash[:])

	// Storage root (Merkle root of the account's storage, or zero hash if empty)
	h.Write(storageRoot[:])

	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// computeStorageRoot computes a Merkle-like root over the account's storage.
// For simplicity, this is a sorted-key SHA256 (not a full Merkle tree) —
// storage proofs are not needed for L2→L1 withdrawals (only account-level
// inclusion proofs are required). If storage-level proofs become needed,
// this can be upgraded to a nested SMT.
// W-P1-6 FIX (2026-07-14)
//
// RLLP-FIX (2026-07-17): Previously used O(N²) insertion sort which
// allowed a high-storage account (e.g. a contract with 10^5 slots) to DoS
// the sequencer by inflating batchBuildDuration. Replaced with sort.Slice
// (O(N log N)) — for N=10^5 this cuts work from ~10^10 ops to ~1.7×10^6.
func computeStorageRoot(storage map[types.Hash]types.Hash) types.Hash {
	if len(storage) == 0 {
		return smtZeroHashes[0]
	}

	// Collect and sort keys.
	keys := make([]types.Hash, 0, len(storage))
	for k := range storage {
		keys = append(keys, k)
	}
	// RLLP- O(N log N) sort instead of O(N²) insertion sort.
	sort.Slice(keys, func(i, j int) bool {
		return compareHash(keys[i], keys[j]) < 0
	})

	h := sha256.New()
	for _, k := range keys {
		h.Write(k[:])
		v := storage[k]
		h.Write(v[:])
	}
	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// compareHash returns -1/0/1 comparing two types.Hash lexicographically.
// W-P1-6 FIX (2026-07-14)
func compareHash(a, b types.Hash) int {
	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// VerifyMerkleProofForAccount is a convenience wrapper that verifies a
// proof for a specific account against the expected root.
// W-P1-6 FIX (2026-07-14)
func VerifyMerkleProofForAccount(addr types.Address, proof *MerkleProof, expectedRoot types.Hash) error {
	if !VerifyMerkleProof(addr, proof, expectedRoot) {
		return fmt.Errorf("merkle proof verification failed for account %x", addr[:8])
	}
	return nil
}

// --- Dedicated withdrawal tree (audit R4-BRDG-02) ---
//
// SECURITY (audit R4-BRDG-02): The account-state SMT proves that a withdrawer's
// account exists in the finalized L2 state, but it does NOT bind the withdrawal
// `amount` to the proof — an attacker with any non-empty account could produce a
// valid inclusion proof and claim an arbitrary amount up to the bridge's total
// liquidity.
//
// The fix is a DEDICATED withdrawal Merkle tree per batch. Each leaf is a
// commitment to a specific withdrawal:
//
//	leaf = SHA256(withdrawer || amount[32] || txIndex[4])
//
// The tree root (WithdrawalRoot) is recorded on L1 when the batch is finalized.
// The L1 bridge reconstructs the expected leaf from the calldata (withdrawer,
// amount, txIndex — all already in the calldata) and verifies:
//
//	1. expectedLeaf == proof.LeafHash  (binds amount to the leaf)
//	2. VerifyMerkleProof(treeKey, proof, withdrawalRoot)  (authenticates the leaf)
//
// This makes it impossible to claim a different amount than what was actually
// in the batch, because the leaf hash changes if any of (withdrawer, amount,
// txIndex) is tampered with.

// ComputeWithdrawalLeafHash computes the leaf hash for a withdrawal record in
// the dedicated withdrawal tree.
// leaf = SHA256(withdrawer[20] || amount[32 left-padded] || txIndex[4 BE])
//
// AUDIT R4-BRDG-02 (2026-07-15)
func ComputeWithdrawalLeafHash(withdrawer types.Address, amount *big.Int, txIndex int) types.Hash {
	h := sha256.New()
	h.Write(withdrawer[:])
	// Amount as 32-byte big-endian (left-padded), matching calldata layout.
	var amountBuf [32]byte
	if amount != nil {
		amountBytes := amount.Bytes()
		copy(amountBuf[32-len(amountBytes):], amountBytes)
	}
	h.Write(amountBuf[:])
	// txIndex as 4-byte big-endian.
	var idxBuf [4]byte
	binary.BigEndian.PutUint32(idxBuf[:], uint32(txIndex))
	h.Write(idxBuf[:])
	var leaf types.Hash
	copy(leaf[:], h.Sum(nil))
	return leaf
}

// ComputeWithdrawalTreeKey derives the SMT key (path) for a withdrawal record.
// key = SHA256(withdrawer || txIndex)[:20]
//
// Using hash(withdrawer || txIndex) instead of the raw withdrawer address
// ensures each (withdrawer, txIndex) pair maps to a unique leaf position,
// even if a user has multiple withdrawals in the same batch.
//
// AUDIT R4-BRDG-02 (2026-07-15)
func ComputeWithdrawalTreeKey(withdrawer types.Address, txIndex int) types.Address {
	h := sha256.New()
	h.Write(withdrawer[:])
	var idxBuf [4]byte
	binary.BigEndian.PutUint32(idxBuf[:], uint32(txIndex))
	h.Write(idxBuf[:])
	var key types.Address
	copy(key[:], h.Sum(nil)[:20])
	return key
}
