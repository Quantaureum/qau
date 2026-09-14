// Quantaureum Node source, version 1.0.0.
// Package lightclient provides SPV (Simplified Payment Verification) proof support.
package lightclient

import (
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

// GenerateStateProof generates a proof of account state
func (p *SPVProver) GenerateStateProof(addr types.Address, storageKeys []types.Hash) (*StateProof, error) {
	if p.stateDB == nil {
		return nil, ErrStateNotFound
	}

	// Get latest block header
	var header *encoding.BlockHeader
	if p.blockStore != nil {
		blk, err := p.blockStore.GetLatestBlock()
		if err == nil {
			header = blk.Header
		}
	}

	// Get account with proof
	account, accountProof, err := p.stateDB.GetAccountWithProof(addr)
	if err != nil && err != state.ErrAccountNotFound {
		return nil, err
	}

	proof := &StateProof{
		Address:       addr,
		BlockHeader:   header,
		Account:       account,
		AccountProof:  accountProof,
		StorageProofs: make(map[types.Hash]*StorageProofEntry),
	}

	// Generate storage proofs if requested
	for _, key := range storageKeys {
		value, storageProof, err := p.stateDB.GetStateWithProof(addr, key)
		if err != nil {
			continue
		}

		proof.StorageProofs[key] = &StorageProofEntry{
			Key:   key,
			Value: value,
			Proof: storageProof,
		}
	}

	return proof, nil
}

// VerifyStateProof verifies a state proof against a state root
func VerifyStateProof(stateRoot types.Hash, proof *StateProof) bool {
	if proof == nil || proof.AccountProof == nil {
		return false
	}

	// Verify account proof
	if !trie.VerifyProof(stateRoot, proof.AccountProof) {
		return false
	}

	// If account exists, verify storage proofs
	if proof.Account != nil {
		for _, entry := range proof.StorageProofs {
			if entry.Proof != nil {
				if !trie.VerifyProof(proof.Account.StorageRoot, entry.Proof) {
					return false
				}
			}
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

// marshalVerkleProof serializes a Verkle proof
func marshalVerkleProof(proof *trie.VerkleProof) []byte {
	if proof == nil {
		return nil
	}

	// Format: [keyLen(4)] [key] [valueLen(4)] [value] [pathCount(4)] [path...] [siblingsCount(4)] [siblings...]
	pathCount := len(proof.Path)
	siblingsCount := len(proof.Siblings)

	// Calculate size
	size := 4 + len(proof.Key) + 4 + len(proof.Value) + 4 + (pathCount * 32) + 4
	for _, siblings := range proof.Siblings {
		size += 4 + (len(siblings) * 32)
	}

	buf := make([]byte, size)
	offset := 0

	// Key
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(proof.Key))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	copy(buf[offset:offset+len(proof.Key)], proof.Key)
	offset += len(proof.Key)

	// Value
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(proof.Value))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	copy(buf[offset:offset+len(proof.Value)], proof.Value)
	offset += len(proof.Value)

	// Path
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(pathCount)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	for _, h := range proof.Path {
		copy(buf[offset:offset+32], h[:])
		offset += 32
	}

	// Siblings
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(siblingsCount)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	for _, siblings := range proof.Siblings {
		binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(siblings))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		offset += 4
		for _, sib := range siblings {
			binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(sib.Idx)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
			offset += 4
			copy(buf[offset:offset+32], sib.Hash[:])
			offset += 32
		}
	}

	return buf
}

// unmarshalVerkleProof deserializes a Verkle proof
func unmarshalVerkleProof(data []byte) *trie.VerkleProof {
	if len(data) < 16 {
		return nil
	}

	proof := &trie.VerkleProof{}
	offset := 0

	// Key
	keyLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if len(data) < offset+int(keyLen) {
		return nil
	}
	proof.Key = make([]byte, keyLen)
	copy(proof.Key, data[offset:offset+int(keyLen)])
	offset += int(keyLen)

	// Value
	if len(data) < offset+4 {
		return nil
	}
	valueLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if len(data) < offset+int(valueLen) {
		return nil
	}
	proof.Value = make([]byte, valueLen)
	copy(proof.Value, data[offset:offset+int(valueLen)])
	offset += int(valueLen)

	// Path
	if len(data) < offset+4 {
		return nil
	}
	pathCount := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	// audit-fix NEW-27: cap path count to prevent OOM from crafted data
	if pathCount > MaxVerklePathDepth {
		return nil
	}
	proof.Path = make([]types.Hash, pathCount)
	for i := uint32(0); i < pathCount; i++ {
		if len(data) < offset+32 {
			return nil
		}
		copy(proof.Path[i][:], data[offset:offset+32])
		offset += 32
	}

	// Siblings
	if len(data) < offset+4 {
		return nil
	}
	siblingsCount := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	// audit-fix NEW-27: cap siblings count to prevent OOM from crafted data
	if siblingsCount > MaxVerkleSiblings {
		return nil
	}
	proof.Siblings = make([][]trie.SiblingWithIdx, siblingsCount)
	for i := uint32(0); i < siblingsCount; i++ {
		if len(data) < offset+4 {
			return nil
		}
		siblingCount := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		// audit-fix NEW-27: cap inner sibling width
		if siblingCount > MaxVerkleSiblingWidth {
			return nil
		}
		proof.Siblings[i] = make([]trie.SiblingWithIdx, siblingCount)
		for j := uint32(0); j < siblingCount; j++ {
			if len(data) < offset+36 {
				return nil
			}
			proof.Siblings[i][j].Idx = int(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4
			copy(proof.Siblings[i][j].Hash[:], data[offset:offset+32])
			offset += 32
		}
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

// GenerateMultiStateProof generates proofs for multiple accounts
func (p *SPVProver) GenerateMultiStateProof(addresses []types.Address, storageKeys map[types.Address][]types.Hash) ([]*StateProof, error) {
	proofs := make([]*StateProof, 0, len(addresses))

	for _, addr := range addresses {
		keys := storageKeys[addr]
		proof, err := p.GenerateStateProof(addr, keys)
		if err != nil {
			continue // Skip accounts that can't be found
		}
		proofs = append(proofs, proof)
	}

	if len(proofs) == 0 {
		return nil, ErrStateNotFound
	}

	return proofs, nil
}
