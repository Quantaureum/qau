// Quantaureum Node source, version 1.0.0.
// Package lightclient provides SPV (Simplified Payment Verification) proof support.
package lightclient

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/qaudb/trie"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// TxInclusionProof represents a proof that a transaction is included in a block
type TxInclusionProof struct {
	// Transaction hash
	TxHash types.Hash
	// Block header containing the transaction
	BlockHeader *encoding.BlockHeader
	// Transaction index in the block
	TxIndex uint32
	// Merkle proof path from transaction to TxRoot
	MerkleProof []types.Hash
	// Sibling positions (0 = left, 1 = right)
	ProofPositions []byte
}

// StateProof represents a proof of account/storage state
type StateProof struct {
	// Address being proved
	Address types.Address
	// Block header at which the proof is valid
	BlockHeader *encoding.BlockHeader
	// Account data (nil if account doesn't exist)
	Account *state.Account
	// Verkle proof for the account
	AccountProof *trie.VerkleProof
	// Storage proofs (key -> proof)
	StorageProofs map[types.Hash]*StorageProofEntry
}

// StorageProofEntry represents a single storage proof
type StorageProofEntry struct {
	Key   types.Hash
	Value types.Hash
	Proof *trie.VerkleProof
}

// SPVProver generates SPV proofs for light clients
type SPVProver struct {
	blockStore *block.BlockStore
	stateDB    *state.StateDB
}

// NewSPVProver creates a new SPV prover
func NewSPVProver(blockStore *block.BlockStore, stateDB *state.StateDB) *SPVProver {
	return &SPVProver{
		blockStore: blockStore,
		stateDB:    stateDB,
	}
}

// GenerateTxInclusionProof generates a proof that a transaction is included in a block
func (p *SPVProver) GenerateTxInclusionProof(txHash types.Hash) (*TxInclusionProof, error) {
	if p.blockStore == nil {
		return nil, ErrTxNotFound
	}

	// Get transaction location
	loc, err := p.blockStore.GetTransactionLocation(txHash)
	if err != nil {
		return nil, ErrTxNotFound
	}

	// Get block
	blk, err := p.blockStore.GetBlock(loc.BlockHash)
	if err != nil {
		return nil, ErrTxNotFound
	}

	// Generate Merkle proof
	merkleProof, positions := generateTxMerkleProof(blk.Transactions, int(loc.TxIndex))

	return &TxInclusionProof{
		TxHash:         txHash,
		BlockHeader:    blk.Header,
		TxIndex:        loc.TxIndex,
		MerkleProof:    merkleProof,
		ProofPositions: positions,
	}, nil
}

// VerifyTxInclusionProof verifies a transaction inclusion proof
// SECURITY FIX: Uses constant-time comparison to prevent timing attacks
//
// AUDIT (2026) BRDG-07: This function trusts the BlockHeader embedded in
// the proof. A malicious prover could supply a fake header whose TxRoot
// matches a forged proof. For security-critical verification, use
// VerifyTxInclusionProofWithTrustedRoot instead, which accepts a trusted
// TxRoot obtained from a checkpoint or sync committee.
func VerifyTxInclusionProof(proof *TxInclusionProof) bool {
	if proof == nil || proof.BlockHeader == nil {
		return false
	}

	// Compute the Merkle root from the proof
	computedRoot, err := computeMerkleRootFromProof(proof.TxHash, proof.TxIndex, proof.MerkleProof, proof.ProofPositions)
	if err != nil {
		return false
	}

	// SECURITY FIX: Use constant-time comparison to prevent timing attacks
	// A timing attack could reveal whether the computed root matches partially
	return subtle.ConstantTimeCompare(computedRoot[:], proof.BlockHeader.TxRoot[:]) == 1
}

// VerifyTxInclusionProofWithTrustedRoot verifies a transaction inclusion proof
// against a trusted Merkle root, rather than the header embedded in the proof.
// AUDIT (2026) BRDG-07: The header in TxInclusionProof is attacker-controlled.
// Callers should obtain the TxRoot from a trusted source (checkpoint, sync
// committee, or locally-verified header chain) and pass it here.
func VerifyTxInclusionProofWithTrustedRoot(proof *TxInclusionProof, trustedTxRoot types.Hash) bool {
	if proof == nil || trustedTxRoot.IsEmpty() {
		return false
	}

	computedRoot, err := computeMerkleRootFromProof(proof.TxHash, proof.TxIndex, proof.MerkleProof, proof.ProofPositions)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(computedRoot[:], trustedTxRoot[:]) == 1
}

// generateTxMerkleProof generates a Merkle proof for a transaction at the given index
func generateTxMerkleProof(txs []*encoding.Transaction, index int) ([]types.Hash, []byte) {
	if len(txs) == 0 || index < 0 || index >= len(txs) {
		return nil, nil
	}

	// AUDIT (2026) BRDG-07: Use domain-separated leaf hashing (0x00 prefix)
	// to match the block builder's computeMerkleRoot. Without domain separation,
	// an attacker could substitute a leaf node for an internal node (second
	// preimage attack), forging a valid-looking proof for a fake transaction.
	hashes := make([]types.Hash, len(txs))
	for i, tx := range txs {
		hashes[i] = hashLeaf(block.ComputeTransactionHash(tx))
	}

	// Build Merkle tree and collect proof
	var proof []types.Hash
	var positions []byte

	for len(hashes) > 1 {
		// Determine sibling index
		siblingIndex := index ^ 1
		if siblingIndex < len(hashes) {
			proof = append(proof, hashes[siblingIndex])
			if index%2 == 0 {
				positions = append(positions, 0) // sibling is on the right
			} else {
				positions = append(positions, 1) // sibling is on the left
			}
		}

		// Move to next level
		newHashes := make([]types.Hash, (len(hashes)+1)/2)
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				newHashes[i/2] = hashPair(hashes[i], hashes[i+1])
			} else {
				// AUDIT (2026) BRDG-07: Hash the odd node with itself
				// instead of passing it through unchanged. Passing through
				// allows a leaf hash to appear as an internal node at the
				// next level, enabling forgery. Duplicating and hashing
				// matches the block builder's behavior and ensures every
				// node above the leaf layer is an internal (0x01) node.
				newHashes[i/2] = hashPair(hashes[i], hashes[i])
			}
		}
		hashes = newHashes
		index = index / 2
	}

	return proof, positions
}

// computeMerkleRootFromProof computes the Merkle root from a proof.
//
// AUDIT (2026) BRDG-10 FIX: Validate that proof and positions arrays
// have equal length and that each position bit matches the corresponding
// bit of txIndex. Previously, mismatched lengths were silently truncated
// (via `if i >= len(positions) { break }`), allowing an attacker to supply
// extra proof elements or mismatched positions to manipulate the computed
// root. The txIndex consistency check ensures the proof path actually
// corresponds to the claimed leaf index — without it, an attacker could
// reuse a valid proof for one index to "prove" inclusion at a different
// index by flipping position bits.
func computeMerkleRootFromProof(txHash types.Hash, txIndex uint32, proof []types.Hash, positions []byte) (types.Hash, error) {
	// AUDIT (2026) BRDG-10: Proof and positions must have equal length.
	if len(proof) != len(positions) {
		return types.Hash{}, fmt.Errorf("merkle proof length %d does not match positions length %d", len(proof), len(positions))
	}

	// AUDIT (2026) BRDG-10: A uint32 index has at most 32 bits, so a
	// valid Merkle proof for a uint32 index has at most 32 levels.
	if len(positions) > 32 {
		return types.Hash{}, fmt.Errorf("merkle proof depth %d exceeds maximum of 32 for uint32 index", len(positions))
	}

	// AUDIT (2026) BRDG-07: Apply leaf domain separator to the tx hash
	// before walking the proof path. This matches the block builder's leaf
	// hashing (0x00 prefix) and prevents leaf/internal node substitution.
	current := hashLeaf(txHash)

	for i, sibling := range proof {
		// AUDIT (2026) BRDG-10: Validate that the position bit matches
		// the corresponding bit of txIndex. This ensures the proof path is
		// consistent with the claimed leaf index. Bit 0 (LSB) of txIndex
		// corresponds to level 0, bit 1 to level 1, etc.
		expectedPos := byte((txIndex >> uint(i)) & 1)
		if positions[i] != expectedPos {
			return types.Hash{}, fmt.Errorf("merkle proof position %d (=%d) does not match expected bit %d of txIndex %d", i, positions[i], expectedPos, txIndex)
		}

		if positions[i] == 0 {
			// sibling is on the right
			current = hashPair(current, sibling)
		} else {
			// sibling is on the left
			current = hashPair(sibling, current)
		}
	}

	return current, nil
}

// hashLeaf hashes a transaction hash with a 0x00 domain separator.
// AUDIT (2026) BRDG-07: Domain separation prevents second-preimage
// attacks where an internal node is substituted for a leaf. This MUST
// match the block builder's leaf hashing in core/block_builder.go.
func hashLeaf(txHash types.Hash) types.Hash {
	data := make([]byte, 1+32)
	data[0] = 0x00
	copy(data[1:], txHash[:])
	return sha3.Sum256(data)
}

// hashPair hashes two hashes together with a 0x01 domain separator.
// AUDIT (2026) BRDG-07: Domain separation prevents second-preimage
// attacks where a leaf node is substituted for an internal node. This MUST
// match the block builder's internal node hashing in core/block_builder.go.
func hashPair(left, right types.Hash) types.Hash {
	data := make([]byte, 1+64)
	data[0] = 0x01
	copy(data[1:33], left[:])
	copy(data[33:65], right[:])
	return sha3.Sum256(data)
}

// GenerateStateProof generates a state-root-bound proof for one account.
//
// R6-02 (2026-10-21 sixth-round audit): this used to be assembled from
// StateDB.GetAccountWithProof / GetStateWithProof, both of which fill
// VerkleProof.Proof with the literal placeholder `[][]byte{}, // Simplified`.
// A placeholder carries no path from the root, so trie.VerifyProof rejects it
// (validateStructure needs len(Path) == len(Siblings)+1) and every consumer of
// VerifyStateProof -- SPVVerifier.VerifyAccountExists, the
// qau_light_verifyStateProof RPC, the serialized-proof helpers -- could never
// confirm the "proof" it had just been handed. Storage lookups were worse still:
// a failing GetStateWithProof was swallowed by `continue`, so a slot the node
// could not prove simply vanished from the response. And the account came from
// the dirty overlay, so mid-block the reported data could differ from the
// committed leaf while the attached header was the last sealed block.
//
// The proof now comes from the canonical trie (StateDB.ProveAccount, whose
// Path[0] is the state root -- pinned by
// rpc/r38_p2_04_deep_proof_state_bound_test.go), and the reported account is
// read back out of the proved leaf. A backend that cannot prove, a proof that
// does not verify against the live root, or a tip header that disagrees with
// that root is an error -- never a pseudo-proof.
//
// R6-05 (2026-10-21): storage slot requests are refused outright. Committed
// storage goes to BoltDB under storagePrefix ++ addr ++ 0xFF ++ slot and NEVER
// into the Verkle state trie -- every stateTrie.Put key on both the Commit
// path (verkleUpdates carries account addresses only) and the
// RecoverConsistency rebuild is an account address. StateDB.ProveStorage can
// therefore only ever return an EXCLUSION proof for a slot the node reads back
// non-zero: a proof that contradicts its own value field. Shipping that to a
// light client is worse than admitting "cannot prove", so the prover refuses
// until storage becomes part of the state trie.
func (p *SPVProver) GenerateStateProof(addr types.Address, storageKeys []types.Hash) (*StateProof, error) {
	if p.stateDB == nil {
		return nil, ErrStateNotFound
	}
	if len(storageKeys) > 0 {
		return nil, fmt.Errorf("%w: %d storage slot(s) requested for %x: committed storage is not part of the Verkle state trie on this node, so no state-root-bound storage proof exists",
			ErrProofNotSupported, len(storageKeys), addr[:8])
	}

	root := p.stateDB.Root()

	// Get latest block header
	var header *encoding.BlockHeader
	if p.blockStore != nil {
		blk, err := p.blockStore.GetLatestBlock()
		if err == nil && blk != nil && blk.Header != nil {
			if blk.Header.StateRoot != root {
				return nil, fmt.Errorf("%w: tip header state root %x does not match the live state root %x",
					ErrInvalidStateProof, blk.Header.StateRoot[:], root[:])
			}
			header = blk.Header
		}
	}

	accountProof, err := p.stateDB.ProveAccount(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProofNotSupported, err)
	}
	if !trie.VerifyProof(root, accountProof) {
		return nil, fmt.Errorf("%w: account proof does not verify against the live state root %x",
			ErrInvalidStateProof, root[:])
	}

	proof := &StateProof{
		Address:       addr,
		BlockHeader:   header,
		AccountProof:  accountProof,
		StorageProofs: make(map[types.Hash]*StorageProofEntry),
	}

	// Report the account the proof binds to, not the overlay copy. An exclusion
	// proof legitimately means "this address is absent from committed state",
	// so Account stays nil and VerifyAccountExists fails closed on it.
	if !accountProof.IsExclusion {
		if len(accountProof.Value) == 0 {
			return nil, fmt.Errorf("%w: inclusion proof for %x carries no account leaf",
				ErrInvalidStateProof, addr[:8])
		}
		account, err := state.DecodeAccount(accountProof.Value)
		if err != nil {
			return nil, fmt.Errorf("%w: proved account leaf for %x does not decode: %v",
				ErrInvalidStateProof, addr[:8], err)
		}
		proof.Account = account
	}

	return proof, nil
}

// VerifyStateProof verifies a state proof against a state root
func VerifyStateProof(stateRoot types.Hash, proof *StateProof) bool {
	if proof == nil || proof.AccountProof == nil {
		return false
	}

	// R6-02: the envelope claims an address; the path it carries must be for
	// that address. Without this binding a valid proof for one account could be
	// presented as another account's state.
	if !bytes.Equal(proof.AccountProof.Key, proof.Address[:]) {
		return false
	}

	// Verify account proof
	if !trie.VerifyProof(stateRoot, proof.AccountProof) {
		return false
	}

	// R6-02: storage slots live in the SAME flat key space as accounts --
	// StateDB.ProveStorage walks the state trie with
	// storagePrefix ++ addr ++ 0xFF ++ slot -- so a storage proof is bound to
	// the state root. The previous version verified entries against
	// proof.Account.StorageRoot, which no honest prover can satisfy, and skipped
	// the whole loop when the account was absent, so an envelope could claim any
	// number of "storage proofs" without a single one being checked.
	for key, entry := range proof.StorageProofs {
		if entry == nil || entry.Proof == nil {
			return false
		}
		if !bytes.Equal(entry.Proof.Key, state.StorageProofKey(proof.Address, key)) {
			return false
		}
		if !trie.VerifyProof(stateRoot, entry.Proof) {
			return false
		}
	}

	return true
}

// MarshalTxInclusionProof serializes a transaction inclusion proof
func MarshalTxInclusionProof(proof *TxInclusionProof) ([]byte, error) {
	if proof == nil {
		return nil, ErrInvalidProof
	}

	// Serialize block header
	headerData, err := encoding.MarshalBlockHeader(proof.BlockHeader)
	if err != nil {
		return nil, err
	}

	// Calculate total size
	proofCount := len(proof.MerkleProof)
	totalSize := 32 + 4 + len(headerData) + 4 + 4 + (proofCount * 32) + len(proof.ProofPositions)

	buf := make([]byte, totalSize)
	offset := 0

	// TxHash (32 bytes)
	copy(buf[offset:offset+32], proof.TxHash[:])
	offset += 32

	// TxIndex (4 bytes)
	binary.BigEndian.PutUint32(buf[offset:offset+4], proof.TxIndex)
	offset += 4

	// Header length and data
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(headerData))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	copy(buf[offset:offset+len(headerData)], headerData)
	offset += len(headerData)

	// Proof count
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(proofCount)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4

	// Merkle proof hashes
	for _, h := range proof.MerkleProof {
		copy(buf[offset:offset+32], h[:])
		offset += 32
	}

	// Proof positions
	copy(buf[offset:], proof.ProofPositions)

	return buf, nil
}

// Maximum proof elements to prevent OOM from untrusted data.
const (
	// audit-fix NEW-26: a Merkle tree over 10 000 txs has at most ~14 levels,
	// so 256 proof elements is extremely generous.
	MaxMerkleProofElements = 256

	// audit-fix NEW-27: Verkle proofs — path depth and sibling count caps.
	MaxVerklePathDepth    = 256
	MaxVerkleSiblings     = 256
	MaxVerkleSiblingWidth = 256

	// audit-fix NEW-28: storage proof count cap per state proof.
	MaxStorageProofCount = 1024
)

// UnmarshalTxInclusionProof deserializes a transaction inclusion proof
func UnmarshalTxInclusionProof(data []byte) (*TxInclusionProof, error) {
	if len(data) < 44 { // minimum: 32 + 4 + 4 + 4
		return nil, ErrInvalidProof
	}

	proof := &TxInclusionProof{}
	offset := 0

	// TxHash
	copy(proof.TxHash[:], data[offset:offset+32])
	offset += 32

	// TxIndex
	proof.TxIndex = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Header length and data
	headerLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data) < offset+int(headerLen)+4 {
		return nil, ErrInvalidProof
	}

	header, err := encoding.UnmarshalBlockHeader(data[offset : offset+int(headerLen)])
	if err != nil {
		return nil, err
	}
	proof.BlockHeader = header
	offset += int(headerLen)

	// Proof count
	proofCount := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// audit-fix NEW-26: cap proof count to prevent OOM from crafted data
	if proofCount > MaxMerkleProofElements {
		return nil, ErrInvalidProof
	}

	if len(data) < offset+int(proofCount)*32+int(proofCount) {
		return nil, ErrInvalidProof
	}

	// Merkle proof hashes
	proof.MerkleProof = make([]types.Hash, proofCount)
	for i := uint32(0); i < proofCount; i++ {
		copy(proof.MerkleProof[i][:], data[offset:offset+32])
		offset += 32
	}

	// Proof positions
	proof.ProofPositions = make([]byte, proofCount)
	copy(proof.ProofPositions, data[offset:offset+int(proofCount)])

	return proof, nil
}

// ComputeTxRoot computes the transaction Merkle root from a list of transactions.
// AUDIT (2026) BRDG-07: Uses domain-separated hashing (0x00 for leaf,
// 0x01 for internal) to match the block builder's computeMerkleRoot.
// Without domain separation, second-preimage attacks could forge a valid
// Merkle root from a different set of transactions.
func ComputeTxRoot(txs []*encoding.Transaction) types.Hash {
	if len(txs) == 0 {
		return types.Hash{}
	}

	// Leaf layer: hash each transaction hash with 0x00 domain separator
	hashes := make([]types.Hash, len(txs))
	for i, tx := range txs {
		hashes[i] = hashLeaf(block.ComputeTransactionHash(tx))
	}

	// Build Merkle tree
	for len(hashes) > 1 {
		// If odd number of nodes, duplicate the last one
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		newHashes := make([]types.Hash, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			newHashes[i/2] = hashPair(hashes[i], hashes[i+1])
		}
		hashes = newHashes
	}

	return hashes[0]
}

// VerifyTxInBlock verifies that a transaction is in a block using the TxRoot.
// SECURITY FIX: Uses constant-time comparison to prevent timing attacks.
//
// AUDIT (2026) BRDG-10: Added txIndex parameter to validate that the
// Merkle proof path is consistent with the claimed leaf index. Without this
// check, an attacker could reuse a valid proof for one index to "prove"
// inclusion at a different index by flipping position bits.
func VerifyTxInBlock(txHash types.Hash, txIndex uint32, txRoot types.Hash, proof []types.Hash, positions []byte) bool {
	computedRoot, err := computeMerkleRootFromProof(txHash, txIndex, proof, positions)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(computedRoot[:], txRoot[:]) == 1
}

// MarshalStateProof serializes a state proof
func MarshalStateProof(proof *StateProof) ([]byte, error) {
	if proof == nil {
		return nil, ErrInvalidStateProof
	}

	// Serialize block header if present
	var headerData []byte
	var err error
	if proof.BlockHeader != nil {
		headerData, err = encoding.MarshalBlockHeader(proof.BlockHeader)
		if err != nil {
			return nil, err
		}
	}

	// Serialize account if present
	var accountData []byte
	if proof.Account != nil {
		accountData = proof.Account.Encode()
	}

	// Serialize account proof
	var accountProofData []byte
	if proof.AccountProof != nil {
		accountProofData = marshalVerkleProof(proof.AccountProof)
	}

	// Calculate total size
	// Format: [address(20)] [headerLen(4)] [header] [accountLen(4)] [account]
	//         [accountProofLen(4)] [accountProof] [storageCount(4)] [storageProofs...]
	storageCount := len(proof.StorageProofs)
	totalSize := 20 + 4 + len(headerData) + 4 + len(accountData) + 4 + len(accountProofData) + 4

	// Calculate storage proofs size
	storageProofsData := make([][]byte, 0, storageCount)
	for key, entry := range proof.StorageProofs {
		entryData := marshalStorageProofEntry(key, entry)
		storageProofsData = append(storageProofsData, entryData)
		totalSize += 4 + len(entryData) // length prefix + data
	}

	buf := make([]byte, totalSize)
	offset := 0

	// Address (20 bytes)
	copy(buf[offset:offset+20], proof.Address[:])
	offset += 20

	// Header length and data
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(headerData))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	if len(headerData) > 0 {
		copy(buf[offset:offset+len(headerData)], headerData)
		offset += len(headerData)
	}

	// Account length and data
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(accountData))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	if len(accountData) > 0 {
		copy(buf[offset:offset+len(accountData)], accountData)
		offset += len(accountData)
	}

	// Account proof length and data
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(accountProofData))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	if len(accountProofData) > 0 {
		copy(buf[offset:offset+len(accountProofData)], accountProofData)
		offset += len(accountProofData)
	}

	// Storage proofs count
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(storageCount)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4

	// Storage proofs
	for _, entryData := range storageProofsData {
		binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(entryData))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		offset += 4
		copy(buf[offset:offset+len(entryData)], entryData)
		offset += len(entryData)
	}

	return buf, nil
}

// UnmarshalStateProof deserializes a state proof
func UnmarshalStateProof(data []byte) (*StateProof, error) {
	if len(data) < 36 { // minimum: 20 + 4 + 4 + 4 + 4
		return nil, ErrInvalidStateProof
	}

	proof := &StateProof{
		StorageProofs: make(map[types.Hash]*StorageProofEntry),
	}
	offset := 0

	// Address
	copy(proof.Address[:], data[offset:offset+20])
	offset += 20

	// Header
	headerLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if headerLen > 0 {
		if len(data) < offset+int(headerLen) {
			return nil, ErrInvalidStateProof
		}
		header, err := encoding.UnmarshalBlockHeader(data[offset : offset+int(headerLen)])
		if err != nil {
			return nil, err
		}
		proof.BlockHeader = header
		offset += int(headerLen)
	}

	// Account
	if len(data) < offset+4 {
		return nil, ErrInvalidStateProof
	}
	accountLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if accountLen > 0 {
		if len(data) < offset+int(accountLen) {
			return nil, ErrInvalidStateProof
		}
		account, err := state.DecodeAccount(data[offset : offset+int(accountLen)])
		if err != nil {
			return nil, err
		}
		proof.Account = account
		offset += int(accountLen)
	}

	// Account proof
	if len(data) < offset+4 {
		return nil, ErrInvalidStateProof
	}
	accountProofLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if accountProofLen > 0 {
		if len(data) < offset+int(accountProofLen) {
			return nil, ErrInvalidStateProof
		}
		proof.AccountProof = unmarshalVerkleProof(data[offset : offset+int(accountProofLen)])
		offset += int(accountProofLen)
	}

	// Storage proofs count
	if len(data) < offset+4 {
		return nil, ErrInvalidStateProof
	}
	storageCount := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// audit-fix NEW-28: cap storage proof count to prevent OOM from crafted data
	if storageCount > MaxStorageProofCount {
		return nil, ErrInvalidStateProof
	}

	// Storage proofs
	for i := uint32(0); i < storageCount; i++ {
		if len(data) < offset+4 {
			return nil, ErrInvalidStateProof
		}
		entryLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		if len(data) < offset+int(entryLen) {
			return nil, ErrInvalidStateProof
		}
		key, entry := unmarshalStorageProofEntry(data[offset : offset+int(entryLen)])
		proof.StorageProofs[key] = entry
		offset += int(entryLen)
	}

	return proof, nil
}

// verkleProofWireVersion tags the full-fidelity Verkle proof encoding.
//
// R6-04 (2026-10-21 sixth-round audit): version 1 carried only
// Key/Value/Path/Siblings. VerkleProof.Verify also reads IsExclusion,
// ExtensionStems, StemHash, InclusionLeaf and ExclusionEvidence; without them an
// exclusion proof decodes as a failed inclusion attempt, an extension level
// loses the stem the verifier has to match against the query key, and a
// suffix-indexed leaf cannot be recomputed at all. So a proof that verified on
// the prover's machine was un-verifiable for the light client it was shipped
// to, even once the prover was honest about what it produced (R6-02). Untagged
// (version 1) input is rejected rather than half-decoded.
const verkleProofWireVersion byte = 0x02

// marshalVerkleProof serializes a Verkle proof
func marshalVerkleProof(proof *trie.VerkleProof) []byte {
	if proof == nil {
		return nil
	}

	// Commitments mark an IPA-backed proof. trie.VerkleProof.Verify fails closed
	// on those (IPA verification is still a stub), so encoding one would hand
	// the caller material that promises more than it can prove.
	if len(proof.Commitments) > 0 {
		return nil
	}

	// Format: [version(1)] [keyLen(4)] [key] [valueLen(4)] [value]
	//         [pathCount(4)] [path...] [siblingsCount(4)] [width(4)] [idx(4) hash(32)]...
	//         [extCount(4)] [stem(31) stemLen(4)]... [isExclusion(1)] [stemHash(32)]
	//         [leafLen(4)] [leaf] [hasEvidence(1)]
	//         [evidenceType(1) extStem(31) extStemLen(4) child(32) leafLen(4) leaf]
	buf := make([]byte, 0, 256)
	putU32 := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		buf = append(buf, b[:]...)
	}
	putBytes := func(b []byte) {
		putU32(uint32(len(b))) // #nosec G115 -- length of a slice that is about to be appended
		buf = append(buf, b...)
	}
	putHash := func(h types.Hash) {
		buf = append(buf, h[:]...)
	}

	buf = append(buf, verkleProofWireVersion)
	putBytes(proof.Key)
	putBytes(proof.Value)

	putU32(uint32(len(proof.Path))) // #nosec G115 -- bounded by MaxVerklePathDepth on both sides
	for _, h := range proof.Path {
		putHash(h)
	}

	putU32(uint32(len(proof.Siblings))) // #nosec G115 -- bounded by MaxVerkleSiblings on both sides
	for _, siblings := range proof.Siblings {
		putU32(uint32(len(siblings))) // #nosec G115 -- bounded by MaxVerkleSiblingWidth on both sides
		for _, sib := range siblings {
			putU32(uint32(sib.Idx)) // #nosec G115 -- branch index in [0, BranchingFactor)
			putHash(sib.Hash)
		}
	}

	putU32(uint32(len(proof.ExtensionStems))) // #nosec G115 -- one entry per tree level
	for _, ext := range proof.ExtensionStems {
		buf = append(buf, ext.Stem[:]...)
		putU32(uint32(ext.StemLen)) // #nosec G115 -- stem length in [0, trie.StemSize]
	}

	if proof.IsExclusion {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	putHash(proof.StemHash)
	putBytes(proof.InclusionLeaf)

	if proof.ExclusionEvidence == nil {
		buf = append(buf, 0)
	} else {
		evidence := proof.ExclusionEvidence
		buf = append(buf, 1, byte(evidence.Type))
		buf = append(buf, evidence.ExtensionStem[:]...)
		putU32(uint32(evidence.ExtensionStemLen)) // #nosec G115 -- stem length in [0, trie.StemSize]
		putHash(evidence.ExtensionChild)
		putBytes(evidence.EncodedLeaf)
	}

	return buf
}

// unmarshalVerkleProof deserializes a Verkle proof. Malformed, oversized or
// unsupported input yields nil so that callers fail closed instead of
// half-restoring a proof that would then be checked against a state root.
func unmarshalVerkleProof(data []byte) *trie.VerkleProof {
	if len(data) < 1 || data[0] != verkleProofWireVersion {
		return nil
	}
	data = data[1:]

	offset := 0

	putBounds := func(n uint32) bool { return uint64(offset)+uint64(n) <= uint64(len(data)) }

	nextU32 := func() (uint32, bool) {
		if len(data) < offset+4 {
			return 0, false
		}
		v := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		return v, true
	}
	nextBytes := func(maxLen uint64) ([]byte, bool) {
		v, ok := nextU32()
		if !ok || uint64(v) > maxLen || !putBounds(v) {
			return nil, false
		}
		out := make([]byte, v)
		copy(out, data[offset:offset+int(v)])
		offset += int(v)
		return out, true
	}
	nextHash := func() (types.Hash, bool) {
		var h types.Hash
		if !putBounds(32) {
			return h, false
		}
		copy(h[:], data[offset:offset+32])
		offset += 32
		return h, true
	}
	nextFlag := func() (bool, bool) {
		if len(data) < offset+1 {
			return false, false
		}
		set := data[offset] != 0
		offset++
		return set, true
	}

	proof := &trie.VerkleProof{}

	key, ok := nextBytes(uint64(len(data)))
	if !ok {
		return nil
	}
	proof.Key = key

	value, ok := nextBytes(uint64(len(data)))
	if !ok {
		return nil
	}
	proof.Value = value

	pathCount, ok := nextU32()
	if !ok || pathCount > MaxVerklePathDepth {
		return nil
	}
	proof.Path = make([]types.Hash, pathCount)
	for i := uint32(0); i < pathCount; i++ {
		h, ok := nextHash()
		if !ok {
			return nil
		}
		proof.Path[i] = h
	}

	siblingsCount, ok := nextU32()
	if !ok || siblingsCount > MaxVerkleSiblings {
		return nil
	}
	proof.Siblings = make([][]trie.SiblingWithIdx, siblingsCount)
	for i := uint32(0); i < siblingsCount; i++ {
		siblingCount, ok := nextU32()
		if !ok || siblingCount > MaxVerkleSiblingWidth {
			return nil
		}
		level := make([]trie.SiblingWithIdx, siblingCount)
		for j := uint32(0); j < siblingCount; j++ {
			idx, ok := nextU32()
			if !ok {
				return nil
			}
			h, ok := nextHash()
			if !ok {
				return nil
			}
			level[j] = trie.SiblingWithIdx{Idx: int(idx), Hash: h} // #nosec G115 -- branch index fits in int
		}
		proof.Siblings[i] = level
	}

	extCount, ok := nextU32()
	if !ok || extCount > MaxVerkleSiblings {
		return nil
	}
	if extCount > 0 {
		proof.ExtensionStems = make([]trie.ExtensionLevelData, extCount)
		for i := uint32(0); i < extCount; i++ {
			if !putBounds(trie.StemSize) {
				return nil
			}
			copy(proof.ExtensionStems[i].Stem[:], data[offset:offset+trie.StemSize])
			offset += trie.StemSize
			stemLen, ok := nextU32()
			if !ok {
				return nil
			}
			proof.ExtensionStems[i].StemLen = int(stemLen) // #nosec G115 -- stem length in [0, trie.StemSize]
		}
	}

	isExclusion, ok := nextFlag()
	if !ok {
		return nil
	}
	proof.IsExclusion = isExclusion

	stemHash, ok := nextHash()
	if !ok {
		return nil
	}
	proof.StemHash = stemHash

	// Bound the carried leaf material the way trie.VerkleProof.Verify does, so
	// a crafted envelope cannot make this node allocate beyond the proof limits.
	leaf, ok := nextBytes(trie.MaxProofTotalBytes)
	if !ok {
		return nil
	}
	proof.InclusionLeaf = leaf

	hasEvidence, ok := nextFlag()
	if !ok {
		return nil
	}
	if hasEvidence {
		if len(data) < offset+1 {
			return nil
		}
		evidence := &trie.ExclusionEvidence{Type: trie.ExclusionType(data[offset])}
		offset++
		if !putBounds(trie.StemSize) {
			return nil
		}
		copy(evidence.ExtensionStem[:], data[offset:offset+trie.StemSize])
		offset += trie.StemSize
		stemLen, ok := nextU32()
		if !ok {
			return nil
		}
		evidence.ExtensionStemLen = int(stemLen) // #nosec G115 -- stem length in [0, trie.StemSize]
		child, ok := nextHash()
		if !ok {
			return nil
		}
		evidence.ExtensionChild = child
		encodedLeaf, ok := nextBytes(trie.MaxProofTotalBytes)
		if !ok {
			return nil
		}
		evidence.EncodedLeaf = encodedLeaf
		proof.ExclusionEvidence = evidence
	}

	if offset != len(data) {
		// Trailing bytes mean the sender and receiver disagree about the format;
		// accepting them would silently verify a truncated proof.
		return nil
	}

	return proof
}

// marshalStorageProofEntry serializes a storage proof entry
func marshalStorageProofEntry(key types.Hash, entry *StorageProofEntry) []byte {
	if entry == nil {
		return nil
	}

	var proofData []byte
	if entry.Proof != nil {
		proofData = marshalVerkleProof(entry.Proof)
	}

	// Format: [key(32)] [value(32)] [proofLen(4)] [proof]
	buf := make([]byte, 32+32+4+len(proofData))
	offset := 0

	copy(buf[offset:offset+32], key[:])
	offset += 32
	copy(buf[offset:offset+32], entry.Value[:])
	offset += 32
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(proofData))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	if len(proofData) > 0 {
		copy(buf[offset:], proofData)
	}

	return buf
}

// unmarshalStorageProofEntry deserializes a storage proof entry
func unmarshalStorageProofEntry(data []byte) (types.Hash, *StorageProofEntry) {
	if len(data) < 68 { // 32 + 32 + 4
		return types.Hash{}, nil
	}

	var key types.Hash
	copy(key[:], data[0:32])

	entry := &StorageProofEntry{
		Key: key,
	}
	copy(entry.Value[:], data[32:64])

	proofLen := binary.BigEndian.Uint32(data[64:68])
	if proofLen > 0 && len(data) >= 68+int(proofLen) {
		entry.Proof = unmarshalVerkleProof(data[68 : 68+int(proofLen)])
	}

	return key, entry
}

// SPVVerifier provides verification utilities for light clients
type SPVVerifier struct{}

// NewSPVVerifier creates a new SPV verifier
func NewSPVVerifier() *SPVVerifier {
	return &SPVVerifier{}
}

// VerifyTxProof verifies a transaction inclusion proof
func (v *SPVVerifier) VerifyTxProof(proof *TxInclusionProof) bool {
	return VerifyTxInclusionProof(proof)
}

// VerifyStateProofAgainstRoot verifies a state proof against a given state root
func (v *SPVVerifier) VerifyStateProofAgainstRoot(stateRoot types.Hash, proof *StateProof) bool {
	return VerifyStateProof(stateRoot, proof)
}

// VerifyAccountExists verifies that an account exists at the given state root
func (v *SPVVerifier) VerifyAccountExists(stateRoot types.Hash, addr types.Address, proof *StateProof) bool {
	if proof == nil || proof.Address != addr {
		return false
	}
	return VerifyStateProof(stateRoot, proof) && proof.Account != nil
}

// VerifyAccountBalance verifies an account's balance at the given state root
func (v *SPVVerifier) VerifyAccountBalance(stateRoot types.Hash, addr types.Address, expectedBalance *big.Int, proof *StateProof) bool {
	if proof == nil || proof.Address != addr || proof.Account == nil {
		return false
	}
	if !VerifyStateProof(stateRoot, proof) {
		return false
	}
	return proof.Account.Balance.Cmp(expectedBalance) == 0
}

// VerifyStorageValue verifies a storage value at the given state root
func (v *SPVVerifier) VerifyStorageValue(stateRoot types.Hash, addr types.Address, key types.Hash, expectedValue types.Hash, proof *StateProof) bool {
	if proof == nil || proof.Address != addr || proof.Account == nil {
		return false
	}
	if !VerifyStateProof(stateRoot, proof) {
		return false
	}

	storageEntry, exists := proof.StorageProofs[key]
	if !exists {
		return false
	}

	return storageEntry.Value == expectedValue
}

// GenerateMultiTxProof generates proofs for multiple transactions in the same block
func (p *SPVProver) GenerateMultiTxProof(txHashes []types.Hash) ([]*TxInclusionProof, error) {
	proofs := make([]*TxInclusionProof, 0, len(txHashes))

	for _, txHash := range txHashes {
		proof, err := p.GenerateTxInclusionProof(txHash)
		if err != nil {
			continue // Skip transactions that can't be found
		}
		proofs = append(proofs, proof)
	}

	if len(proofs) == 0 {
		return nil, ErrTxNotFound
	}

	return proofs, nil
}

// GenerateMultiStateProof generates proofs for multiple accounts.
//
// R6-02: failures are propagated instead of skipped. The previous `continue`
// with the comment "Skip accounts that can't be found" silently shrank the
// response, so a caller could not tell "this account is absent from state"
// (which is provable, as an exclusion proof) apart from "this node could not
// prove it" -- and an RPC layer that mapped the resulting short list to
// "states not found" turned a backend failure into a false statement about
// chain state.
func (p *SPVProver) GenerateMultiStateProof(addresses []types.Address, storageKeys map[types.Address][]types.Hash) ([]*StateProof, error) {
	proofs := make([]*StateProof, 0, len(addresses))

	for _, addr := range addresses {
		keys := storageKeys[addr]
		proof, err := p.GenerateStateProof(addr, keys)
		if err != nil {
			return nil, fmt.Errorf("account %x: %w", addr[:8], err)
		}
		proofs = append(proofs, proof)
	}

	if len(proofs) == 0 {
		return nil, ErrStateNotFound
	}

	return proofs, nil
}
