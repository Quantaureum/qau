// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

const (
	merkleLeafPrefix  = 0x00
	merkleNodePrefix  = 0x01
	merkleDomainSep   = "QAU-BRIDGE-MERKLE-V1"
	maxMerkleLeaves   = 1 << 20
	maxLeafSize       = 64
	maxProofDepth     = 32
	maxNeighborHashes = 20 //  [MEDIUM] FIX: reduced from 32 to limit Merkle proof size
)

type MerkleProof struct {
	LeafHash  types.Hash   `json:"leaf_hash"`
	Neighbors []types.Hash `json:"neighbors"`
	LeafIndex int          `json:"leaf_index"`
	Root      types.Hash   `json:"root"`
}

type MerkleTree struct {
	leaves []types.Hash
	root   types.Hash
	layers [][]types.Hash
}

func hashLeaf(data []byte) types.Hash {
	h := sha3.New256()
	h.Write([]byte{merkleLeafPrefix})
	h.Write([]byte(merkleDomainSep))
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	h.Write(lenBuf)
	h.Write(data)
	var hash types.Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

func hashNode(left, right types.Hash) types.Hash {
	h := sha3.New256()
	h.Write([]byte{merkleNodePrefix})
	h.Write([]byte(merkleDomainSep))
	h.Write(left[:])
	h.Write(right[:])
	var hash types.Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

func NewMerkleTree(msgIDs []string) (*MerkleTree, error) {
	if len(msgIDs) == 0 {
		emptyRoot := types.Hash{}
		return &MerkleTree{
			leaves: nil,
			root:   emptyRoot,
			layers: nil,
		}, nil
	}
	if len(msgIDs) > maxMerkleLeaves {
		return nil, fmt.Errorf("message ID batch exceeds maximum merkle tree capacity (%d): got %d — batch must be split into smaller chunks", maxMerkleLeaves, len(msgIDs))
	}

	leaves := make([]types.Hash, len(msgIDs))
	// AUDIT (2026 security review) R4-DATA-08 FIX: Reject duplicate message IDs. Bridge
	// message IDs are externally provided and are NOT protected by blockchain
	// nonce uniqueness, so the CVE-2012-2459 duplicate-last malleability is
	// more directly relevant here than for TxRoot. A duplicate ID would produce
	// identical leaf hashes, which (a) enables the duplicate-last root collision
	// and (b) silently breaks proof generation for the second occurrence
	// (GenerateProof's leaf lookup returns the FIRST match). Reject up-front.
	seenIDs := make(map[string]struct{}, len(msgIDs))
	for i, id := range msgIDs {
		if len(id) > maxLeafSize {
			return nil, fmt.Errorf("message ID exceeds maximum size of %d bytes: id len=%d", maxLeafSize, len(id))
		}
		if _, dup := seenIDs[id]; dup {
			return nil, fmt.Errorf("duplicate message ID at index %d: %q — duplicate leaves enable CVE-2012-2459 Merkle root malleability", i, id)
		}
		seenIDs[id] = struct{}{}
		leaves[i] = hashLeaf([]byte(id))
	}

	t := &MerkleTree{
		leaves: leaves,
	}
	t.root, t.layers = t.buildTree()
	return t, nil
}

// hashLeafMessage computes a Merkle leaf hash that binds the FULL bridge
// message payload (not just the message ID).
//
// BRDG- (2026-07-16): The legacy hashLeaf([]byte(msg.ID)) path committed
// only the message ID into the Merkle tree, so a Merkle membership proof
// attested "this ID was committed" but NOT "this ID corresponds to this
// amount/recipient/data". The Go-side disbursement path additionally relies
// on HasQuorumForHash (which binds signatures to computeMessageHash), so the
// current Go path is safe in isolation. However, any future code that treats
// "Merkle proof verified" as "payload trusted" would re-open payload
// substitution. Fix the latent risk at the root: the Merkle leaf itself
// becomes hashLeaf(computeMessageHash(msg)), so membership inherently binds
// the payload.
//
// computeMessageHash covers ID + chain IDs + addresses + asset type/ID +
// amount + token ID + data + nonce + timestamp + message type + MaxAmount +
// SlippageTolerance + Deadline + GasLimit (see ethereum_adapter.go:1431).
// Two distinct payloads with the same ID therefore produce distinct leaves,
// defeating payload substitution at the Merkle layer.
func hashLeafMessage(msg *BridgeMessage) types.Hash {
	return hashLeaf(computeMessageHash(msg))
}

// NewMerkleTreeFromMessages builds a Merkle tree whose leaves are
// hashLeaf(computeMessageHash(msg)) for each message — i.e. each leaf
// commits to the full payload, not just the message ID.
//
// BRDG- (2026-07-16): This is the production-recommended constructor.
// NewMerkleTree(msgIDs []string) is retained for backward compatibility with
// governance callers that only know message IDs, but trees built via that
// constructor commit only to IDs — verifyMessageInclusion now expects
// payload-bound leaves (hashLeafMessage), so any tree built via the legacy
// constructor will fail verification. Callers must migrate to
// CommitMessagesByPayload / NewMerkleTreeFromMessages.
//
// Duplicate messages are rejected by computing computeMessageHash(msg) for
// each entry and rejecting duplicates — this preserves the CVE-2012-2459
// defense (a duplicate leaf would enable duplicate-last root malleability
// and break proof generation for the second occurrence).
func NewMerkleTreeFromMessages(msgs []*BridgeMessage) (*MerkleTree, error) {
	if len(msgs) == 0 {
		emptyRoot := types.Hash{}
		return &MerkleTree{
			leaves: nil,
			root:   emptyRoot,
			layers: nil,
		}, nil
	}
	if len(msgs) > maxMerkleLeaves {
		return nil, fmt.Errorf("message batch exceeds maximum merkle tree capacity (%d): got %d — batch must be split into smaller chunks", maxMerkleLeaves, len(msgs))
	}

	leaves := make([]types.Hash, len(msgs))
	// BRDG- dedup on the payload commitment (computeMessageHash), not
	// on the message ID. Two distinct messages with the same payload hash
	// would otherwise produce identical leaves and enable the CVE-2012-2459
	// duplicate-last root collision.
	seenHashes := make(map[types.Hash]struct{}, len(msgs))
	for i, msg := range msgs {
		if msg == nil {
			return nil, fmt.Errorf("message at index %d is nil — cannot build Merkle tree from nil messages", i)
		}
		if len(msg.ID) > maxLeafSize {
			return nil, fmt.Errorf("message ID exceeds maximum size of %d bytes: id len=%d", maxLeafSize, len(msg.ID))
		}
		leaf := hashLeafMessage(msg)
		if _, dup := seenHashes[leaf]; dup {
			return nil, fmt.Errorf("duplicate message payload at index %d (id=%q) — duplicate leaves enable CVE-2012-2459 Merkle root malleability", i, msg.ID)
		}
		seenHashes[leaf] = struct{}{}
		leaves[i] = leaf
	}

	t := &MerkleTree{
		leaves: leaves,
	}
	t.root, t.layers = t.buildTree()
	return t, nil
}

// buildTree constructs the Merkle tree layers from the leaf hashes.
//
// AUDIT (2026 security review) R4-DATA-08 (CVE-2012-2459 — LATENT): Uses duplicate-last
// padding for odd leaf counts (line 115). See core/block_builder.go
// computeMerkleRoot for the full analysis. Bridge message IDs are externally
// provided and are NOT subject to blockchain nonce-uniqueness, so the
// duplicate-last malleability is more directly relevant here than for TxRoot.
// Active defense: NewMerkleTree rejects duplicate message IDs at construction
// (see seenIDs check above), so no duplicate leaf can enter this tree builder.
func (t *MerkleTree) buildTree() (types.Hash, [][]types.Hash) {
	if len(t.leaves) == 0 {
		return types.Hash{}, nil
	}
	if len(t.leaves) == 1 {
		return t.leaves[0], [][]types.Hash{t.leaves}
	}

	layers := [][]types.Hash{t.leaves}
	current := t.leaves

	for len(current) > 1 {
		var next []types.Hash
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, hashNode(current[i], current[i+1]))
			} else {
				next = append(next, hashNode(current[i], current[i]))
			}
		}
		layers = append(layers, next)
		current = next
	}

	return current[0], layers
}

func (t *MerkleTree) Root() types.Hash {
	return t.root
}

func (t *MerkleTree) GenerateProof(leafHash types.Hash) (*MerkleProof, error) {
	if len(t.layers) == 0 {
		return nil, fmt.Errorf("empty Merkle tree")
	}

	leafIndex := -1
	for i, l := range t.leaves {
		if l == leafHash {
			leafIndex = i
			break
		}
	}
	if leafIndex == -1 {
		return nil, fmt.Errorf("leaf not found in Merkle tree")
	}

	var neighbors []types.Hash
	idx := leafIndex

	// AUDIT (2026 security review) BRDG-08: Iterate only up to (but NOT including) the
	// root layer. The previous code iterated over ALL layers including the
	// root layer (which has exactly 1 element). At the root layer, idx=0,
	// sibling=1 (out of bounds), so the code appended layer[0] (the root
	// itself) as an extra neighbor. This caused VerifyMerkleProof to
	// compute one extra hash level, making legitimately generated proofs
	// ALWAYS fail verification. Fix: stop at len-1 to exclude the root.
	for layerIdx := 0; layerIdx < len(t.layers)-1; layerIdx++ {
		layer := t.layers[layerIdx]
		sibling := idx ^ 1
		if sibling < len(layer) {
			neighbors = append(neighbors, layer[sibling])
		} else {
			neighbors = append(neighbors, layer[idx])
		}
		idx = idx / 2
	}

	return &MerkleProof{
		LeafHash:  leafHash,
		Neighbors: neighbors,
		LeafIndex: leafIndex,
		Root:      t.root,
	}, nil
}

func VerifyMerkleProof(proof *MerkleProof) bool {
	if proof == nil {
		return false
	}

	if len(proof.Neighbors) > maxNeighborHashes {
		return false
	}

	// P2-2 FIX (2026-07-14): A 0-neighbor proof is valid for a single-leaf
	// Merkle tree where the leaf IS the root. In that case, no hashing is
	// needed — VerifyMerkleProof simply checks LeafHash == Root. Previously
	// 0-neighbor proofs were unconditionally rejected, making single-message
	// batches unprocessable (the production GenerateProof correctly emits a
	// 0-neighbor proof for a 1-leaf tree, but verification rejected it).
	if proof.LeafIndex < 0 || proof.LeafIndex >= (1<<len(proof.Neighbors)) {
		return false
	}

	current := proof.LeafHash
	idx := proof.LeafIndex

	for _, sibling := range proof.Neighbors {
		if idx%2 == 0 {
			current = hashNode(current, sibling)
		} else {
			current = hashNode(sibling, current)
		}
		idx = idx / 2
	}

	return current == proof.Root
}

func EncodeMerkleProof(proof *MerkleProof) []byte {
	data, err := json.Marshal(proof)
	if err != nil {
		return nil
	}
	return data
}

func DecodeMerkleProof(data []byte) (*MerkleProof, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty Merkle proof data")
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("merkle proof data too large: %d bytes", len(data))
	}

	var proof MerkleProof
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, fmt.Errorf("invalid Merkle proof encoding: %w", err)
	}

	// P2-2 FIX (2026-07-14): Allow 0-neighbor proofs — they are valid for
	// single-leaf Merkle trees where the leaf IS the root. The LeafIndex
	// bound check below still rejects invalid indices for 0-neighbor proofs
	// (only LeafIndex 0 is allowed when Neighbors is empty).
	if len(proof.Neighbors) > maxNeighborHashes {
		return nil, fmt.Errorf("too many neighbor hashes: %d (max %d)", len(proof.Neighbors), maxNeighborHashes)
	}
	if proof.LeafIndex < 0 {
		return nil, fmt.Errorf("invalid leaf index: %d", proof.LeafIndex)
	}
	if proof.LeafIndex >= (1 << len(proof.Neighbors)) {
		return nil, fmt.Errorf("leaf index %d exceeds maximum for proof depth %d", proof.LeafIndex, len(proof.Neighbors))
	}

	emptyHash := types.Hash{}
	if proof.LeafHash == emptyHash {
		return nil, fmt.Errorf("empty leaf hash in Merkle proof")
	}
	if proof.Root == emptyHash {
		return nil, fmt.Errorf("empty root hash in Merkle proof")
	}

	return &proof, nil
}
