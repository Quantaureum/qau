// Quantaureum Node source, version 1.0.0.
// Package trie provides Verkle tree proof support for Quantaureum blockchain.
// Verkle trees combine Vector commitments with Merkle trees for efficient state proofs.
//
// This implementation provides a proper 256-ary Patricia Merkle Trie with:
// - Deterministic root computation via sorted node hashing
// - Path compression via extension nodes
// - Proof generation with actual sibling hashes
// - Future-ready interface for Pedersen commitment migration
package trie

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"

	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

var verkleLog = logging.Global()

// Node types for the Verkle tree
const (
	NodeTypeEmpty     = 0
	NodeTypeLeaf      = 1
	NodeTypeInternal  = 2
	NodeTypeExtension = 3

	maxLeafKeySize   = 1 << 20
	maxLeafValueSize = 1 << 24

	// TRIE- Encoding magic byte prepended to all persisted/cached
	// Verkle node bytes. Allows forward-compatible format migrations: a
	// future bump to the magic value lets decodeNode reject incompatible
	// encodings explicitly instead of silently returning nil.
	// Value 'V' (0x56) is distinct from all NodeType values (0x00-0x03),
	// so legacy data (which starts with a NodeType byte) is unambiguous.
	VerkleEncodingMagic byte = 0x56
)

// Tree parameters
const (
	BranchingFactor = 256 // 256-ary tree (byte-level branching)
	MaxTreeDepth    = 32  // Max depth for 32-byte keys
	StemSize        = 31  // Stem size (31 bytes)

	// TRIE- Canonical Verkle key size (31-byte stem + 1-byte suffix).
	// Keys of this length use the fast path in keyToStem/keyToSuffix (direct
	// byte copy). Keys of other lengths are accepted but routed through a
	// domain-separated SHA-256 hash to eliminate stem collisions.
	VerkleKeySize = 32

	// R32-P2-06 FIX (2026-07-28): Hard recursion depth limit for all tree
	// traversal functions (walk/insert/delete/proveWalk). The LOGICAL depth
	// is bounded by StemSize (31) for InternalNode descents, but
	// ExtensionNode descents advance depth by n.StemLen per recursion. If a
	// corrupted or maliciously-crafted tree contains an ExtensionNode with
	// StemLen == 0 (or a cycle of nodes pointing back to each other), the
	// logical depth check `depth >= StemSize` never fires, and recursion
	// continues until the Go stack overflows (~100k+ frames → crash).
	//
	// maxVerkleRecursionDepth is a DEFENSE-IN-DEPTH backstop: it is larger
	// than any legitimate tree depth (StemSize=31, so even pathological
	// ExtensionNode layouts stay well under 64 levels), but small enough
	// that hitting it cannot overflow the stack. On hitting this limit the
	// traversal returns nil / the current node instead of recursing
	// further, and logs a warning so operators can detect tree corruption.
	maxVerkleRecursionDepth = 256
)

// Errors
var (
	ErrInvalidProof = errors.New("invalid proof")
	ErrKeyNotFound  = errors.New("key not found")
	ErrProofTooLong = errors.New("proof exceeds maximum depth")
	ErrInvalidNode  = errors.New("invalid node encoding")
	ErrNodeNotFound = errors.New("node not found in tree")
	// TRIE- reject keys longer than the canonical Verkle key size.
	ErrInvalidKey = errors.New("invalid key: length must be <= VerkleKeySize (32 bytes)")
)

// Node hasher interface for future Pedersen commitment migration
type NodeHasher interface {
	HashLeaf(key, value []byte) types.Hash
	HashInternal(children [BranchingFactor]types.Hash) types.Hash
	HashExtension(stem [StemSize]byte, child types.Hash) types.Hash
}

// sha3Hasher implements NodeHasher using SHA3-256
type sha3Hasher struct{}

func (h *sha3Hasher) HashLeaf(key, value []byte) types.Hash {
	hasher := sha3.New256()
	hasher.Write([]byte{0x00}) // Leaf prefix
	hasher.Write(key)
	hasher.Write(value)
	var hash types.Hash
	copy(hash[:], hasher.Sum(nil))
	return hash
}

func (h *sha3Hasher) HashInternal(children [BranchingFactor]types.Hash) types.Hash {
	hasher := sha3.New256()
	hasher.Write([]byte{0x01}) // Internal node prefix
	for i := 0; i < BranchingFactor; i++ {
		hasher.Write(children[i][:])
	}
	var hash types.Hash
	copy(hash[:], hasher.Sum(nil))
	return hash
}

func (h *sha3Hasher) HashExtension(stem [StemSize]byte, child types.Hash) types.Hash {
	hasher := sha3.New256()
	hasher.Write([]byte{0x02}) // Extension prefix
	hasher.Write(stem[:])
	hasher.Write(child[:])
	var hash types.Hash
	copy(hash[:], hasher.Sum(nil))
	return hash
}

// defaultHasher is the global SHA3-256 hasher instance
var defaultHasher NodeHasher = &sha3Hasher{}

// TreeNode is the interface for all Verkle tree nodes
type TreeNode interface {
	Hash() types.Hash
	NodeType() byte
	Encode() []byte
}

// LeafNode represents a leaf containing actual data.
// AUDIT (2026) R3-DATA-01: In standard Verkle trees (EIP-6800), a leaf
// holds up to 256 values for the same 31-byte stem, indexed by the 32nd key
// byte (suffix). Previously, LeafNode held a single (Key, Value) pair, so
// two keys sharing a 31-byte stem but differing in the suffix would collide
// — the second Put silently overwrote the first. SuffixValues now stores
// same-stem entries; Key/Value remain as the "primary" entry for backward
// compatibility with callers that iterate or encode leaves.
type LeafNode struct {
	Key   []byte
	Value []byte
	// SuffixValues stores values for keys that share the same 31-byte stem
	// as Key but differ in the 32nd byte (suffix). Keyed by suffix byte.
	SuffixValues map[byte][]byte
	hash         types.Hash
}

// NewLeafNode creates a new leaf node.
// R37-P3-09 FIX (2026-07-31): key and value are defensively copied so
// callers cannot mutate the tree's internal state through the original
// slices. Without this, a caller who reuses a byte buffer after Put
// would corrupt the tree, and a caller who modifies the slice returned
// by Get would corrupt the tree from the outside.
func NewLeafNode(key, value []byte) *LeafNode {
	var keyCopy, valCopy []byte
	if len(key) > 0 {
		keyCopy = append([]byte(nil), key...)
	}
	if len(value) > 0 {
		valCopy = append([]byte(nil), value...)
	}
	return &LeafNode{
		Key:   keyCopy,
		Value: valCopy,
		hash:  defaultHasher.HashLeaf(keyCopy, valCopy),
	}
}

// recomputeHash recalculates the leaf's hash, including suffix values.
// AUDIT (2026) R3-DATA-01: SuffixValues must be part of the hash to
// prevent tampering with same-stem entries without affecting the root.
func (n *LeafNode) recomputeHash() {
	hasher := sha3.New256()
	hasher.Write([]byte{0x00}) // Leaf prefix
	hasher.Write(n.Key)
	hasher.Write(n.Value)
	// Include suffix values in sorted order for determinism.
	for suffix := 0; suffix < 256; suffix++ {
		if val, ok := n.SuffixValues[byte(suffix)]; ok {
			hasher.Write([]byte{byte(suffix)})
			hasher.Write(val)
		}
	}
	copy(n.hash[:], hasher.Sum(nil))
}

func (n *LeafNode) Hash() types.Hash {
	return n.hash
}

func (n *LeafNode) NodeType() byte {
	return NodeTypeLeaf
}

func (n *LeafNode) Encode() []byte {
	// Encoding: type(1) | key_len(4) | key | value_len(4) | value
	//          | suffix_count(4) | [suffix(1) + val_len(4) + val]*
	// FIX: Validate key/value sizes before encoding to prevent
	// oversized allocations and ensure DecodeLeafNode can round-trip the
	// data. Without validation, a caller could set an arbitrarily large
	// Key or Value, causing Encode to allocate a huge buffer and
	// DecodeLeafNode to reject it on read (wasted work + potential OOM).
	// AUDIT (2026) R3-DATA-01: SuffixValues are appended after the
	// primary value. Old-format leaves (without suffix data) decode fine
	// because suffix_count will be 0 when no extra data is present.
	keyLen := len(n.Key)
	valueLen := len(n.Value)
	if keyLen > maxLeafKeySize {
		return nil
	}
	if valueLen > maxLeafValueSize {
		return nil
	}

	// Calculate suffix block size
	suffixCount := 0
	suffixBlockSize := 0
	if n.SuffixValues != nil {
		for _, v := range n.SuffixValues {
			if len(v) > maxLeafValueSize {
				return nil
			}
			suffixCount++
			suffixBlockSize += 1 + 4 + len(v)
		}
	}

	totalLen := 1 + 4 + keyLen + 4 + valueLen + 4 + suffixBlockSize
	buf := make([]byte, totalLen)
	buf[0] = NodeTypeLeaf
	offset := 1
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(keyLen)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	copy(buf[offset:offset+keyLen], n.Key)
	offset += keyLen
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(valueLen)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	copy(buf[offset:offset+valueLen], n.Value)
	offset += valueLen

	// AUDIT (2026) R3-DATA-01: Write suffix count + entries
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(suffixCount))
	offset += 4
	// Write suffix entries in sorted order for determinism
	for suffix := 0; suffix < 256; suffix++ {
		if val, ok := n.SuffixValues[byte(suffix)]; ok {
			buf[offset] = byte(suffix)
			offset++
			binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(val)))
			offset += 4
			copy(buf[offset:offset+len(val)], val)
			offset += len(val)
		}
	}

	return buf
}

// DecodeLeafNode decodes a leaf node from bytes
func DecodeLeafNode(data []byte) (*LeafNode, error) {
	if len(data) < 10 || data[0] != NodeTypeLeaf {
		return nil, ErrInvalidNode
	}
	offset := 1
	keyLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	if keyLen < 0 || keyLen > maxLeafKeySize {
		return nil, ErrInvalidNode
	}
	offset += 4
	if len(data) < offset+keyLen+4 {
		return nil, ErrInvalidNode
	}
	key := make([]byte, keyLen)
	copy(key, data[offset:offset+keyLen])
	offset += keyLen
	valueLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	if valueLen < 0 || valueLen > maxLeafValueSize {
		return nil, ErrInvalidNode
	}
	offset += 4
	if len(data) < offset+valueLen {
		return nil, ErrInvalidNode
	}
	value := make([]byte, valueLen)
	copy(value, data[offset:offset+valueLen])
	offset += valueLen
	node := NewLeafNode(key, value)

	// AUDIT (2026) R3-DATA-01: Decode suffix values if present.
	// Old-format leaves (without suffix data) have no bytes left here,
	// so suffixCount defaults to 0 and SuffixValues remains nil.
	if len(data) >= offset+4 {
		suffixCount := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
		if suffixCount > 0 && suffixCount <= 256 {
			node.SuffixValues = make(map[byte][]byte, suffixCount)
			for i := 0; i < suffixCount; i++ {
				if len(data) < offset+1+4 {
					return nil, ErrInvalidNode
				}
				suffix := data[offset]
				offset++
				sValLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
				if sValLen < 0 || sValLen > maxLeafValueSize {
					return nil, ErrInvalidNode
				}
				offset += 4
				if len(data) < offset+sValLen {
					return nil, ErrInvalidNode
				}
				sVal := make([]byte, sValLen)
				copy(sVal, data[offset:offset+sValLen])
				offset += sValLen
				node.SuffixValues[suffix] = sVal
			}
			node.recomputeHash()
		}
	}

	return node, nil
}

// InternalNode represents an internal node with 256 children
type InternalNode struct {
	Children [BranchingFactor]types.Hash
	hash     types.Hash
}

// NewInternalNode creates a new internal node with zero hashes
func NewInternalNode() *InternalNode {
	return &InternalNode{}
}

func (n *InternalNode) Hash() types.Hash {
	return n.hash
}

func (n *InternalNode) NodeType() byte {
	return NodeTypeInternal
}

func (n *InternalNode) Encode() []byte {
	// Encoding: type(1) | child1_hash(32) | ... | child256_hash(32)
	buf := make([]byte, 1+BranchingFactor*32)
	buf[0] = NodeTypeInternal
	offset := 1
	for i := 0; i < BranchingFactor; i++ {
		copy(buf[offset:offset+32], n.Children[i][:])
		offset += 32
	}
	return buf
}

// DecodeInternalNode decodes an internal node from bytes
func DecodeInternalNode(data []byte) (*InternalNode, error) {
	expectedLen := 1 + BranchingFactor*32
	if len(data) < expectedLen || data[0] != NodeTypeInternal {
		return nil, ErrInvalidNode
	}
	node := NewInternalNode()
	offset := 1
	for i := 0; i < BranchingFactor; i++ {
		var hash types.Hash
		copy(hash[:], data[offset:offset+32])
		node.Children[i] = hash
		offset += 32
	}
	node.recomputeHash()
	return node, nil
}

// recomputeHash recalculates the node's hash
func (n *InternalNode) recomputeHash() {
	n.hash = defaultHasher.HashInternal(n.Children)
}

// ExtensionNode compresses a path with a single non-empty child
type ExtensionNode struct {
	Stem      [StemSize]byte
	StemLen   int
	Child     TreeNode
	childHash types.Hash
	hash      types.Hash
}

// NewExtensionNode creates a new extension node
// NewExtensionNode creates a new ExtensionNode.
//
// R32-P2-06 FIX (2026-07-28): Validate StemLen range. An ExtensionNode
// with StemLen <= 0 represents an extension with no stem — semantically
// meaningless and the root cause of zero-progress recursion in walk/
// insert/delete/proveWalk (the depth check `depth >= StemSize` never
// fires because depth doesn't advance). StemLen > StemSize would cause
// n.Stem[:n.StemLen] to slice out of bounds. Reject both at construction
// time so corruption cannot be introduced via the public constructor.
//
// Returns nil for invalid StemLen. All in-tree callers pass StemLen
// derived from existing nodes or from divergence-point arithmetic
// (which is provably in [1, StemSize]); nil return is a defensive
// backstop for future callers.
func NewExtensionNode(stem [StemSize]byte, stemLen int, child TreeNode) *ExtensionNode {
	if stemLen <= 0 || stemLen > StemSize {
		verkleLog.Warn("NewExtensionNode: rejected invalid StemLen",
			map[string]any{"stemLen": stemLen, "maxStemSize": StemSize})
		return nil
	}
	node := &ExtensionNode{
		Stem:    stem,
		StemLen: stemLen,
		Child:   child,
	}
	if child != nil {
		node.childHash = child.Hash()
	}
	node.recomputeHash()
	return node
}

func (n *ExtensionNode) Hash() types.Hash {
	return n.hash
}

func (n *ExtensionNode) NodeType() byte {
	return NodeTypeExtension
}

func (n *ExtensionNode) Encode() []byte {
	buf := make([]byte, 1+4+StemSize+32)
	buf[0] = NodeTypeExtension
	binary.BigEndian.PutUint32(buf[1:5], uint32(n.StemLen))
	copy(buf[5:5+StemSize], n.Stem[:])
	if n.Child != nil {
		childHash := n.Child.Hash()
		copy(buf[5+StemSize:5+StemSize+32], childHash[:])
	}
	return buf
}

func DecodeExtensionNode(data []byte) (*ExtensionNode, error) {
	expectedLen := 1 + 4 + StemSize + 32
	if len(data) < expectedLen || data[0] != NodeTypeExtension {
		return nil, ErrInvalidNode
	}
	stemLen := int(binary.BigEndian.Uint32(data[1:5]))
	if stemLen < 0 || stemLen > StemSize {
		return nil, ErrInvalidNode
	}
	var stem [StemSize]byte
	copy(stem[:], data[5:5+StemSize])
	var childHash types.Hash
	copy(childHash[:], data[5+StemSize:5+StemSize+32])
	node := &ExtensionNode{
		Stem:      stem,
		StemLen:   stemLen,
		childHash: childHash,
	}
	node.hash = defaultHasher.HashExtension(stem, childHash)
	return node, nil
}

// recomputeHash recalculates the extension node's hash
func (n *ExtensionNode) recomputeHash() {
	var childHash types.Hash
	if n.Child != nil {
		childHash = n.Child.Hash()
	}
	n.hash = defaultHasher.HashExtension(n.Stem, childHash)
}

// EmptyNode represents an empty/non-existent node
type EmptyNode struct{}

func (n *EmptyNode) Hash() types.Hash {
	return types.Hash{}
}

func (n *EmptyNode) NodeType() byte {
	return NodeTypeEmpty
}

func (n *EmptyNode) Encode() []byte {
	return []byte{NodeTypeEmpty}
}

// SiblingWithIdx represents a sibling hash with its position index
type SiblingWithIdx struct {
	Idx  int
	Hash types.Hash
}

// ExtensionLevelData carries the Stem prefix for an Extension node level
// in a Verkle proof.
//
// TRIE-/002 (2026-07-20): Previously the verifier had no way to
// check that an Extension node's Stem prefix actually matched the query
// key — it only saw an empty Siblings entry and skipped the level. This
// allowed a forged proof to substitute a different Stem and produce a
// valid-looking recomputed root for a wrong key. ExtensionLevelData
// carries the Stem and StemLen from the Extension node so the verifier
// can (a) recompute HashExtension(Stem, child) and (b) verify that the
// query key's stem has Stem prefix == proof.Stem[:StemLen].
type ExtensionLevelData struct {
	Stem    [StemSize]byte
	StemLen int
}

// ExclusionType enumerates the reasons a key may be absent from the tree.
//
// TRIE- (2026-07-20): The previous verifier recomputed the parent
// upward from a zero hash and accepted any result that matched the root,
// which made it impossible to distinguish "key absent because the slot
// is empty" from "key absent because the slot holds a different key".
// Each ExclusionType below carries the minimal data the verifier needs to
// prove the key is genuinely absent at the fork point.
type ExclusionType byte

const (
	// ExclusionTypeEmptySlot indicates the path child slot at the fork
	// point is the zero hash (no child node exists).
	ExclusionTypeEmptySlot ExclusionType = 0x01
	// ExclusionTypeExtensionMismatch indicates the fork point's path
	// child is an ExtensionNode whose Stem prefix does NOT match the
	// query key's stem at the fork depth. The verifier recomputes the
	// extension hash from ExtensionStem/ExtensionChild and verifies it
	// matches Path[last], then checks Stem does not prefix-match.
	ExclusionTypeExtensionMismatch ExclusionType = 0x02
	// ExclusionTypeLeafMismatch indicates the fork point's path child is
	// a LeafNode whose Key does not equal the query key. The verifier
	// recomputes the leaf hash from LeafKey and verifies it matches
	// Path[last], then checks LeafKey != query key (and that no
	// SuffixValues entry matches the query suffix).
	ExclusionTypeLeafMismatch ExclusionType = 0x03
)

// ExclusionEvidence carries the data needed to verify that a key is
// genuinely absent at the proof's fork point.
//
// For ExclusionTypeEmptySlot, no extra data is needed: the verifier
// checks that the recomputed parent (with the path child set to zero
// hash) matches Path[last].
//
// For ExclusionTypeExtensionMismatch, the verifier uses ExtensionStem
// and ExtensionChild to recompute the extension hash and verify it
// matches Path[last]; it then checks that Stem does NOT prefix-match
// the query key's stem at the fork depth (otherwise the proof is
// fraudulent — the key should have been included).
//
// For ExclusionTypeLeafMismatch, the verifier decodes EncodedLeaf to
// obtain a LeafNode, recomputes its hash, and verifies it matches
// Path[last]. It then checks LeafNode.Key != query key and that no
// SuffixValues entry matches the query key's suffix. Including the
// full encoded leaf (rather than just Key+Hash) is required because
// LeafNode.Hash() incorporates Key, Value, and SuffixValues — a
// malicious prover could otherwise lie about LeafKey while keeping
// LeafHash correct, tricking the verifier into accepting an exclusion
// proof for a key that actually exists.
type ExclusionEvidence struct {
	Type ExclusionType

	// For ExclusionTypeExtensionMismatch:
	ExtensionStem    [StemSize]byte
	ExtensionStemLen int
	ExtensionChild   types.Hash

	// For ExclusionTypeLeafMismatch: encoded LeafNode bytes.
	EncodedLeaf []byte
}

// VerkleProof represents a proof of inclusion/exclusion in a Verkle tree
type VerkleProof struct {
	// Key being proved
	Key []byte

	// Value at the key (nil for exclusion proofs)
	Value []byte

	// Proof path from root to leaf (list of hashes at each level).
	//
	// TRIE-/002 (2026-07-20) invariant: len(Path) == len(Siblings) + 1.
	//   - Path[0] is the root hash.
	//   - Path[i+1] is the hash of the path child at level i (the next node
	//     down toward the leaf / fork point).
	//   - Path[len(Path)-1] is the leaf hash (inclusion) or the fork-point
	//     child hash (exclusion: zero for empty slot, extension hash for
	//     extension mismatch, leaf hash for leaf mismatch).
	Path []types.Hash

	// Siblings at each level of the tree
	// siblings[i] contains the sibling hashes with their indices at level i
	// This allows proper reconstruction of parent hashes in 256-ary tree
	Siblings [][]SiblingWithIdx

	// ExtensionStems carries Stem data for Extension node levels.
	// Indexed in parallel to Siblings (ExtensionStems[i] corresponds to
	// level i). An entry with StemLen == 0 means level i is an
	// InternalNode level (Siblings[i] carries the actual siblings). A
	// non-zero StemLen means level i is an ExtensionNode level
	// (Siblings[i] is empty, and the parent hash is computed via
	// HashExtension(Stem, childHash) instead of HashInternal).
	//
	// TRIE- (2026-07-20): Without this field the verifier could
	// not distinguish an Extension level from an Internal level with no
	// siblings, nor verify the Stem prefix matches the query key.
	ExtensionStems []ExtensionLevelData

	// ExclusionEvidence carries the fork-point evidence for exclusion
	// proofs. Nil for inclusion proofs.
	//
	// TRIE- (2026-07-20): Without this field the verifier could
	// not prove that the key is actually absent — recomputing parent
	// upward from a zero hash only proves the path was traversed, not
	// that the leaf slot is genuinely empty.
	ExclusionEvidence *ExclusionEvidence

	// InclusionLeaf carries the encoded LeafNode for inclusion proofs.
	//
	// TRIE- (2026-07-20): When a leaf stores SuffixValues (multiple
	// values indexed by the 32nd key byte under the same 31-byte stem),
	// the simple HashLeaf(Key, Value) recompute path does NOT match the
	// leaf's actual hash (which incorporates Key + Value + all
	// SuffixValues entries). Without the full encoded leaf, the verifier
	// cannot recompute the leaf hash and cannot verify that the queried
	// suffix actually exists in the leaf. We carry the full encoded leaf
	// (parallel to ExclusionEvidence.EncodedLeaf for exclusion proofs)
	// so the verifier can:
	//   1. Decode the leaf and recompute leaf.Hash().
	//   2. Verify leaf.Hash() == Path[last] (cryptographic binding).
	//   3. Verify the query key is present in the leaf (either
	//      leaf.Key == proof.Key, or leaf.SuffixValues[suffix] exists).
	//   4. Verify the returned Value matches what's in the leaf.
	// A malicious prover cannot forge the leaf data because the hash
	// would not match Path[last].
	InclusionLeaf []byte

	// Commitment at each level (for 256-ary, this is the parent hash at each level)
	Commitments []types.Hash

	// Stem hash (hash of the 31-byte stem)
	StemHash types.Hash

	// Whether this is an exclusion proof
	IsExclusion bool

	// Alternative proof format (for compatibility)
	Proof [][]byte
}

// NewVerkleProof creates a new Verkle proof
func NewVerkleProof(key, value []byte, proof [][]byte) *VerkleProof {
	return &VerkleProof{
		Key:   key,
		Value: value,
		Proof: proof,
	}
}

// Verify verifies the Verkle proof against a root commitment
func (p *VerkleProof) Verify(root types.Hash) bool {
	if p == nil {
		return false
	}
	// TRIE- (2026-07-20) FIX: Hardening for placeholder IPA proof.
	// Previously Verify trusted the Siblings field directly without any
	// structural validation — an attacker could supply malformed proofs
	// (out-of-range indices, duplicate indices, oversized depth) that
	// would either panic or waste CPU before failing. We now:
	//   1. Enforce proof size limits (depth, key length, sibling count).
	//   2. Validate every SiblingWithIdx.Idx is in [0, BranchingFactor).
	//   3. Reject duplicate sibling indices at the same level (an attacker
	//      could otherwise overwrite the path-child slot and force a
	//      fake recomputed root).
	//   4. Fail-closed when the proof claims to carry IPA commitments
	//      (Commitments field non-empty) — IPA verification is still a
	//      stub () and MUST NOT be accepted in production until
	//      implemented. Without this, a proof could pass the simple
	//      hash-recompute check while claiming IPA backing it does not
	//      have, misleading downstream verifiers.
	//   5. Reject zero-value root (callers must pass a real root), EXCEPT
	//      for the empty-tree exclusion proof where zero IS the
	//      legitimate root (Path == nil && Siblings == nil && IsExclusion).
	if root == (types.Hash{}) {
		// Allow zero root only for the legitimate empty-tree exclusion
		// proof: a tree with no nodes has a zero root, and any key is
		// trivially absent. Any other proof shape with a zero root is
		// either a caller bug (default zero root) or a forgery attempt.
		if !(p.IsExclusion && len(p.Path) == 0 && len(p.Siblings) == 0) {
			return false
		}
	}
	if !p.validateStructure() {
		return false
	}
	if p.IsExclusion {
		return p.verifyExclusion(root)
	}
	return p.verifyInclusion(root)
}

// MaxProofDepth bounds how deep a Verkle proof may go. For 32-byte keys
// in a 256-ary tree, depth is at most 32. Anything deeper is malformed.
const MaxProofDepth = MaxTreeDepth

// MaxSiblingsPerLevel bounds how many sibling entries a single tree level
// may carry. In a 256-ary tree there are at most 255 siblings (one slot is
// the path child itself). We allow the full 256 for symmetry and to give
// room for an "empty siblings" sentinel slot, but no more.
const MaxSiblingsPerLevel = BranchingFactor

// MaxProofTotalBytes bounds the total encoded size of a Verkle proof to
// prevent DoS via gigantic in-memory proofs. 32 levels * 256 siblings *
// 32 bytes/hash = 256 KB. We round up to 1 MB to allow future commitment
// formats (IPA proofs) without immediate resizing.
const MaxProofTotalBytes = 1 << 20 // 1 MB

// MaxNodesToLoad bounds how many vnode entries loadFromDB() will pull into
// memory at startup. Without this cap, a grown chain (millions of nodes)
// would cause startup OOM. When the cap is hit, loadFromDB stops loading
// further nodes and logs a warning; the tree falls back to on-demand lookups
// via persistentDB for the unloaded tail.
// TRIE- (2026-07-20): 100K nodes * ~256 bytes/value ~ 25 MB worst case.
const MaxNodesToLoad = 100_000

// validateStructure performs the TRIE- + TRIE-/002 hardening
// checks:
//   - key length <= MaxTreeDepth
//   - Siblings depth <= MaxProofDepth
//   - per-level sibling count <= MaxSiblingsPerLevel
//   - every SiblingWithIdx.Idx in [0, BranchingFactor)
//   - no duplicate Idx within a single level
//   - total proof byte size <= MaxProofTotalBytes
//   - if Commitments is non-empty, IPA verification is required (and
//     currently fails-closed because IPA is stubbed)
//   - len(Siblings) == len(Path) - 1 (TRIE- exact depth match)
//   - len(ExtensionStems) == len(Siblings) (parallel arrays)
//   - ExtensionStems entries with StemLen > 0 must correspond to empty
//     Siblings entries (Extension levels carry no siblings)
func (p *VerkleProof) validateStructure() bool {
	if len(p.Key) > MaxProofDepth {
		return false
	}
	if len(p.Siblings) > MaxProofDepth {
		return false
	}
	// TRIE- (2026-07-20): Siblings are organized per tree level
	// along the key path. There cannot be more sibling levels than key
	// bytes — a proof with extra levels is malformed (or an attempt to
	// force a negative path index). Reject up-front as defense-in-depth
	// alongside the per-iteration idx<0 check in verifyInclusion/
	// verifyExclusion.
	if len(p.Siblings) > len(p.Key) {
		return false
	}

	// TRIE-/002 (2026-07-20): Enforce the structural invariant
	//   len(Path) == len(Siblings) + 1
	// so the verifier can walk Path top-down (or bottom-up) with a
	// well-defined child hash at every level. The only exception is the
	// empty-tree exclusion proof (Path and Siblings both empty), which
	// is a valid exclusion for a tree with no root.
	if len(p.Path) != len(p.Siblings)+1 {
		// Allow the empty-tree exclusion proof: Path == nil &&
		// Siblings == nil && IsExclusion. Any other mismatch is malformed.
		if !(len(p.Path) == 0 && len(p.Siblings) == 0 && p.IsExclusion) {
			return false
		}
	}

	// TRIE- (2026-07-20): ExtensionStems must be parallel to
	// Siblings (one entry per level). If ExtensionStems is non-empty
	// but a different length, the proof is malformed. If empty, all
	// levels are assumed to be InternalNode levels (backward compat
	// for proofs generated before this field was added — though Prove
	// now always populates it).
	if len(p.ExtensionStems) != 0 && len(p.ExtensionStems) != len(p.Siblings) {
		return false
	}

	// TRIE- (2026-07-20): Extension levels (StemLen > 0) must
	// have empty Siblings entries (an ExtensionNode has only one child,
	// no siblings at its level). Conversely, an InternalNode level
	// (StemLen == 0) MAY have an empty Siblings entry (a 1-child
	// InternalNode), so we only enforce the Extension direction.
	for i, ext := range p.ExtensionStems {
		if ext.StemLen > 0 {
			if ext.StemLen > StemSize {
				return false
			}
			if len(p.Siblings[i]) != 0 {
				return false
			}
		}
	}

	totalBytes := len(p.Key) + len(p.Value)
	for _, lvl := range p.Siblings {
		if len(lvl) > MaxSiblingsPerLevel {
			return false
		}
		seenIdx := make(map[int]struct{}, len(lvl))
		for _, sib := range lvl {
			if sib.Idx < 0 || sib.Idx >= BranchingFactor {
				return false
			}
			if _, dup := seenIdx[sib.Idx]; dup {
				// Duplicate sibling index — this is malformed. In a
				// legitimate proof each sibling occupies a distinct
				// slot in the 256-ary node; duplicates would silently
				// overwrite each other in recomputeParent.
				return false
			}
			seenIdx[sib.Idx] = struct{}{}
			totalBytes += 32 + 8 // hash + idx encoding overhead
		}
	}
	for _, c := range p.Commitments {
		totalBytes += len(c[:])
	}
	for _, pr := range p.Proof {
		totalBytes += len(pr)
	}
	if totalBytes > MaxProofTotalBytes {
		return false
	}

	// IPA commitment verification is NOT implemented ().
	// If a proof carries IPA commitments, fail closed — do not silently
	// fall through to the simple hash-recompute path that ignores them.
	if len(p.Commitments) > 0 {
		verkleLog.Errorf("TRIE- proof carries IPA commitments but IPA verification is stubbed (); rejecting")
		return false
	}
	return true
}

// verifyInclusion verifies an inclusion proof by walking Path top-down
// from root to leaf, recomputing each level's parent hash from the
// recorded child hash + siblings (or Extension Stem), and verifying it
// matches Path[level]. Finally, the leaf hash is recomputed from
// Key+Value and verified against Path[last].
//
// TRIE- (2026-07-20): Previously this function iterated
// bottom-up starting from leafHash, ignored Path entirely, and used
// the broken `len(p.Key) - 1 - i` formula for the path index — which
// was wrong whenever the tree contained Extension nodes (depth jumps
// by StemLen, not 1). The new implementation walks Path top-down so
// the path index is derived from the actual depth advanced at each
// level (1 for Internal, StemLen for Extension), making Extension
// handling correct.
func (p *VerkleProof) verifyInclusion(root types.Hash) bool {
	if len(p.Value) == 0 {
		return false
	}

	// leafHashAndValueCheck verifies the leaf hash matches Path[last]
	// and that the query key + value are genuinely present in the leaf.
	//
	// TRIE- (2026-07-20): For leaves that carry SuffixValues
	// (multiple values indexed by the 32nd key byte under the same
	// 31-byte stem), the simple HashLeaf(Key, Value) recompute path
	// does NOT match the leaf's actual hash. We must decode the
	// encoded leaf from InclusionLeaf, recompute leaf.Hash() (which
	// includes SuffixValues), and verify:
	//   1. leaf.Hash() == Path[last] (cryptographic binding to path).
	//   2. The query key is present in the leaf (either leaf.Key ==
	//      proof.Key, or leaf.SuffixValues[suffix] exists).
	//   3. The returned Value matches what's in the leaf (prevents a
	//      prover from returning a different value for the same key).
	// A malicious prover cannot forge the leaf data because the hash
	// would not match Path[last].
	leafHashAndValueCheck := func(pathLast types.Hash) bool {
		if len(p.InclusionLeaf) > 0 {
			leaf, err := DecodeLeafNode(p.InclusionLeaf)
			if err != nil || leaf == nil {
				return false
			}
			if leaf.Hash() != pathLast {
				return false
			}
			// Verify the query key is genuinely present in the leaf.
			if bytes.Equal(leaf.Key, p.Key) {
				// Primary key — verify returned Value matches.
				if !bytes.Equal(leaf.Value, p.Value) {
					return false
				}
				return true
			}
			// Otherwise, the query key must be a suffix-indexed entry.
			if leaf.SuffixValues == nil {
				return false
			}
			suffix := keyToSuffix(p.Key)
			storedVal, exists := leaf.SuffixValues[suffix]
			if !exists {
				return false
			}
			if !bytes.Equal(storedVal, p.Value) {
				return false
			}
			return true
		}
		// Legacy path (no InclusionLeaf): recompute via HashLeaf. This
		// only works for leaves without SuffixValues. If the prover
		// generated InclusionLeaf but the verifier is using a stale
		// code path, this still produces the correct hash for simple
		// leaves. For leaves with SuffixValues, this path is insecure
		// and MUST NOT be used — but Prove now always sets InclusionLeaf.
		leafHash := defaultHasher.HashLeaf(p.Key, p.Value)
		return leafHash == pathLast
	}

	// Empty-tree case: a single-leaf tree where the root IS the leaf.
	// Prove generates Path = [leaf.Hash()], Siblings = [], so the
	// validateStructure len(Path) == len(Siblings) + 1 check passes
	// (1 == 0 + 1). Verify leaf hash matches root.
	if len(p.Siblings) == 0 {
		if len(p.Path) != 1 {
			return false
		}
		if p.Path[0] != root {
			return false
		}
		return leafHashAndValueCheck(p.Path[0])
	}

	// Non-empty tree: Path[0] must equal root, Path[last] must equal
	// the recomputed leaf hash.
	if p.Path[0] != root {
		return false
	}
	if !leafHashAndValueCheck(p.Path[len(p.Path)-1]) {
		return false
	}

	// Walk Path top-down. At each level i (0 <= i < len(Siblings)):
	//   - The parent node is Path[i].
	//   - The path child is Path[i+1].
	//   - If ExtensionStems[i].StemLen > 0: this is an Extension level.
	//     Verify the query key's stem prefix matches ExtensionStems[i].Stem
	//     (otherwise the proof was generated for a different key) and
	//     recompute parent = HashExtension(Stem, child). The depth advances
	//     by StemLen.
	//   - Else: this is an Internal level. Recompute parent =
	//     recomputeParent(child, Siblings[i], pathIndex). The path index
	//     is stem[depth] where depth is the accumulated depth so far.
	//     The depth advances by 1.
	//   - Verify recomputed parent == Path[i].
	depth := 0
	stem := keyToStem(p.Key)
	for i := 0; i < len(p.Siblings); i++ {
		child := p.Path[i+1]
		var parent types.Hash
		if len(p.ExtensionStems) > 0 && p.ExtensionStems[i].StemLen > 0 {
			ext := p.ExtensionStems[i]
			// Verify the query key's stem prefix matches the Extension's
			// Stem. If it doesn't match, the proof was generated for a
			// key whose path diverges from this Extension — the prover
			// is either buggy or malicious.
			if depth+ext.StemLen > StemSize {
				return false
			}
			if !bytes.Equal(stem[depth:depth+ext.StemLen], ext.Stem[:ext.StemLen]) {
				return false
			}
			parent = defaultHasher.HashExtension(ext.Stem, child)
			depth += ext.StemLen
		} else {
			// Internal level. The path index is stem[depth].
			if depth >= StemSize {
				return false
			}
			pathIndex := int(stem[depth]) // #nosec G115 -- byte value 0..255 fits in int
			parent = recomputeParent(child, p.Siblings[i], pathIndex)
			depth++
		}
		if parent != p.Path[i] {
			return false
		}
	}
	return true
}

// verifyExclusion verifies an exclusion proof. Like verifyInclusion it
// walks Path top-down, recomputing each level's parent and verifying it
// matches Path[i]. At the leaf level, instead of comparing to a leaf
// hash, it consults ExclusionEvidence to verify the key is genuinely
// absent at the fork point:
//
//   - ExclusionTypeEmptySlot: the path child slot in the parent
//     (InternalNode) is the zero hash. Verifier recomputes parent with
//     child = zero hash and verifies == Path[last-1].
//   - ExclusionTypeExtensionMismatch: the path child is an ExtensionNode
//     whose Stem prefix does NOT match the query key's stem at the fork
//     depth. Verifier recomputes the extension hash from ExtensionStem
//     and ExtensionChild, verifies it matches Path[last], and checks
//     that Stem does NOT prefix-match the query key's stem (otherwise
//     the proof is fraudulent — the key should have been included).
//   - ExclusionTypeLeafMismatch: the path child is a LeafNode whose Key
//     does not equal the query key. Verifier recomputes the leaf hash
//     from LeafKey, verifies it matches Path[last], and checks that
//     LeafKey != query key.
//
// TRIE- (2026-07-20): Previously this function started from
// types.Hash{} (zero) and recomputed upward, accepting any result that
// matched root. This made it impossible to distinguish "key absent
// because slot is empty" from "key absent because slot holds a
// different key" — an attacker could forge an exclusion proof for a
// key that actually exists by claiming the slot was empty.
func (p *VerkleProof) verifyExclusion(root types.Hash) bool {
	// Empty-tree exclusion: a tree with no root trivially excludes
	// every key. validateStructure allows Path == nil && Siblings == nil
	// only when IsExclusion is true. This is only valid against a zero
	// root — a non-zero root means the tree is not empty, so the proof
	// must not be accepted.
	if len(p.Siblings) == 0 && len(p.Path) == 0 {
		return root == (types.Hash{}) && len(p.Value) == 0
	}
	// Single-level case: tree has a root node (leaf or extension) that
	// does not match the query key. Path = [forkChildHash], Siblings = [].
	if len(p.Siblings) == 0 {
		if len(p.Path) != 1 {
			return false
		}
		// The fork child hash must equal root (since there are no
		// sibling levels above to recompute).
		if p.Path[0] != root {
			return false
		}
		return p.verifyExclusionEvidence(0)
	}

	// Multi-level case: Path[0] = root, walk top-down verifying each
	// level matches Path[i]. The last level's parent is Path[len-2],
	// and Path[len-1] is the fork-point child hash.
	if p.Path[0] != root {
		return false
	}
	depth := 0
	stem := keyToStem(p.Key)
	for i := 0; i < len(p.Siblings); i++ {
		child := p.Path[i+1]
		var parent types.Hash
		if len(p.ExtensionStems) > 0 && p.ExtensionStems[i].StemLen > 0 {
			ext := p.ExtensionStems[i]
			if depth+ext.StemLen > StemSize {
				return false
			}
			// For exclusion, the Extension's Stem MUST match the query
			// key's stem prefix at the fork depth — otherwise the proof
			// traversed the wrong path and the actual exclusion reason
			// lies at a higher level. (If the Extension's Stem didn't
			// match, the prover should have stopped here with an
			// ExclusionTypeExtensionMismatch evidence instead of
			// continuing into the Extension.)
			if !bytes.Equal(stem[depth:depth+ext.StemLen], ext.Stem[:ext.StemLen]) {
				return false
			}
			parent = defaultHasher.HashExtension(ext.Stem, child)
			depth += ext.StemLen
		} else {
			if depth >= StemSize {
				return false
			}
			pathIndex := int(stem[depth]) // #nosec G115 -- byte value 0..255 fits in int
			parent = recomputeParent(child, p.Siblings[i], pathIndex)
			depth++
		}
		if parent != p.Path[i] {
			return false
		}
	}

	// Now verify the fork-point evidence: the path child at
	// Path[len(Path)-1] must prove the key is absent.
	return p.verifyExclusionEvidence(depth)
}

// verifyExclusionEvidence verifies the fork-point evidence for an
// exclusion proof. forkDepth is the accumulated stem depth at the fork
// point (used for Extension prefix and leaf key comparisons).
func (p *VerkleProof) verifyExclusionEvidence(forkDepth int) bool {
	if p.ExclusionEvidence == nil {
		// Without explicit evidence, we cannot prove the key is
		// genuinely absent. Fail closed.
		return false
	}
	ev := p.ExclusionEvidence
	lastPath := p.Path[len(p.Path)-1]
	switch ev.Type {
	case ExclusionTypeEmptySlot:
		// The fork-point child slot in the parent (InternalNode at
		// Path[len-2]) must be the zero hash. We verify by recomputing
		// the parent with child = zero hash and checking it matches
		// Path[len-2]. This is already done by the main loop above
		// (since Path[len-1] is the zero hash, recomputeParent with
		// child=zero produces the parent). Here we just verify Path
		// last entry is indeed zero.
		if lastPath != (types.Hash{}) {
			return false
		}
		return true

	case ExclusionTypeExtensionMismatch:
		// Recompute the extension hash from ExtensionStem and
		// ExtensionChild, verify it matches Path[last].
		extHash := defaultHasher.HashExtension(ev.ExtensionStem, ev.ExtensionChild)
		if extHash != lastPath {
			return false
		}
		// Verify the Extension's Stem does NOT prefix-match the query
		// key's stem at the fork depth. If it did, the proof would be
		// fraudulent (the key should have been included).
		stem := keyToStem(p.Key)
		// R37-P3-07 FIX (2026-07-31): ExtensionStemLen must be non-negative
		// and bounded. A negative value would cause a slice bounds panic on
		// stem[forkDepth:forkDepth+ExtensionStemLen].
		if ev.ExtensionStemLen < 0 || ev.ExtensionStemLen > StemSize {
			return false
		}
		if forkDepth+ev.ExtensionStemLen > StemSize {
			// Extension extends beyond stem size — can't match by
			// definition, so the key is genuinely absent.
			return true
		}
		if bytes.Equal(stem[forkDepth:forkDepth+ev.ExtensionStemLen], ev.ExtensionStem[:ev.ExtensionStemLen]) {
			// Stem matches — the proof should have continued into the
			// Extension, not stopped here. Reject.
			return false
		}
		return true

	case ExclusionTypeLeafMismatch:
		// Decode the encoded leaf, recompute its hash, and verify it
		// matches Path[last]. This is the cryptographic binding that
		// prevents a malicious prover from lying about LeafKey.
		if len(ev.EncodedLeaf) == 0 {
			return false
		}
		leaf, err := DecodeLeafNode(ev.EncodedLeaf)
		if err != nil || leaf == nil {
			return false
		}
		if leaf.Hash() != lastPath {
			return false
		}
		// Verify the leaf's key does NOT equal the query key. If it
		// did, the proof is fraudulent (the key should have been
		// included).
		if bytes.Equal(leaf.Key, p.Key) {
			return false
		}
		// Also check that no SuffixValues entry matches the query
		// key's suffix. A leaf may store multiple values under the
		// same 31-byte stem indexed by the 32nd byte (suffix); if the
		// query key's suffix matches one of these, the key actually
		// exists.
		if leaf.SuffixValues != nil {
			suffix := keyToSuffix(p.Key)
			if _, exists := leaf.SuffixValues[suffix]; exists {
				return false
			}
		}
		return true

	default:
		return false
	}
}

// recomputeParent reconstructs a parent hash from child and siblings.
// For a 256-ary tree, siblings must include all 256 child hashes at their correct indices.
// Empty slots are represented as zero hashes.
// The pathIndex indicates where the child is positioned.
func recomputeParent(child types.Hash, siblings []SiblingWithIdx, pathIndex int) types.Hash {
	// Build full children array with 256 entries
	var children [BranchingFactor]types.Hash
	// Place the child at its position
	children[pathIndex] = child
	// Place siblings at their correct positions
	for _, sib := range siblings {
		if sib.Idx >= 0 && sib.Idx < BranchingFactor {
			children[sib.Idx] = sib.Hash
		}
	}
	// Hash the full 256-ary internal node
	return defaultHasher.HashInternal(children)
}

// Size returns the size of the proof in bytes
func (p *VerkleProof) Size() int {
	size := len(p.Key) + len(p.Value)
	for _, path := range p.Path {
		size += len(path)
	}
	for _, siblings := range p.Siblings {
		size += len(siblings) * (4 + 32) // each sibling: idx (4 bytes) + hash (32 bytes)
	}
	return size
}

// R6-DB-1 FIX: node key prefix for persistent database storage
const vnodePrefix = "vnode:"

// VerkleTree is a proper 256-ary Patricia Merkle Trie
type VerkleTree struct {
	mu       sync.RWMutex
	dbMu     *sync.RWMutex // protects db map (shared between copies)
	root     types.Hash
	rootNode TreeNode
	db       map[string][]byte // node hash -> encoded node (in-memory cache)
	maxDepth int

	// R6-DB-1 FIX: persistent database for node storage across restarts
	persistentDB db.Database

	// R39-P1-05 (2026-08-02) FIX: shared mutex serializing Flush()
	// invocations against the shared persistentDB. Copy() propagates this
	// POINTER to the copy so that the original tree and any tree derived
	// from it via Copy() all serialize their final batch.Write() through
	// the SAME mutex — preventing two Flush() calls from concurrent tree
	// instances racing into the same bbolt instance (bbolt itself does
	// serialize transactions internally, but the cross-tree write ORDER
	// is non-deterministic without this gate, and the audit (R39-P1-05)
	// calls out that "commit pending marker" sequencing and other
	// ordering assumptions mediated by external state_ndb.go depend on
	// tree.Flush() having an observably stable with-respect-to-other-tree
	// order). The mutex is initialized in NewVerkleTree to a fresh
	// &sync.Mutex{} for a brand-new tree and inherited (pointer copied)
	// through Copy(); tests that build the struct directly MUST set this
	// field themselves if they exercise the Flush() path.
	//
	// Lock ordering: persistentFlushMu is acquired BEFORE pendingBatchMu
	// (see Flush / recordPendingWrite). A goroutine that already holds
	// pendingBatchMu MUST NOT acquire persistentFlushMu while under it —
	// recordPendingWrite's ErrBatchFull-internal Flush acquires
	// persistentFlushMu while ALREADY holding pendingBatchMu, but
	// persistentFlushMu never tries to acquire pendingBatchMu, so this
	// establishes a consistent single-direction lock order
	// (persistentFlushMu → pendingBatchMu) with no cycle.
	persistentFlushMu *sync.Mutex

	// STORAGE-P0-01 FIX (R31, 2026-07-27): pendingBatch accumulates ALL node
	// writes (including the root) within a logical operation so they can be
	// committed atomically via Flush(). Previously, every storeNode and
	// recomputeRoot call issued an independent persistentDB.Put — a crash
	// between calls could leave the on-disk tree half-written (root present
	// but children missing, or vice-versa), permanently corrupting the trie
	// and causing state-root divergence across nodes.
	//
	// pendingBatchErr captures the FIRST error encountered while appending
	// (e.g., batch full, OOM). It is returned by Flush() so callers can
	// surface persistence failures instead of silently logging them.
	// Reset on Flush() / Reset().
	//
	// pendingBatchMu protects pendingBatch and pendingBatchErr because
	// storeNode may be reached from multiple goroutines in future uses
	// (today the tree is single-writer, but defensive locking prevents
	// future regressions).
	pendingBatchMu  sync.Mutex
	pendingBatch    db.Batch
	pendingBatchErr error
}

// NewVerkleTree creates a new Verkle tree.
// R6-DB-1 FIX: accepts optional db.Database for persistent storage.
// When a persistentDB is provided, nodes are loaded from disk on startup
// and written to disk on every storeNode call.
//
// STORAGE-P0-01 FIX (R31, 2026-07-27): When persistentDB is provided, a
// pendingBatch is created so all subsequent node writes are buffered for
// atomic commit via Flush(). Callers that use the tree with persistence
// MUST call Flush() at logical boundaries (e.g., end of block commit).
func NewVerkleTree(maxDepth int, persistentDB ...db.Database) *VerkleTree {
	if maxDepth <= 0 {
		maxDepth = MaxTreeDepth
	}
	t := &VerkleTree{
		dbMu:     &sync.RWMutex{},
		db:       make(map[string][]byte),
		maxDepth: maxDepth,
	}
	if len(persistentDB) > 0 && persistentDB[0] != nil {
		t.persistentDB = persistentDB[0]
		// R39-P1-05 (2026-08-02) FIX: brand-new tree gets its own fresh
		// persistentFlushMu. Copy() propagates this POINTER so original
		// and copy serialize against each other through the same mutex.
		// Trees that never call Copy() have an isolated mutex — no cross-
		// tree contention, same single-tree Flush() behavior as before.
		t.persistentFlushMu = &sync.Mutex{}
		// STORAGE-P0-01 FIX: pre-allocate the pending batch so storeNode
		// can append to it without checking nil on the hot path.
		t.pendingBatch = persistentDB[0].NewBatch()
		t.loadFromDB()
	}
	return t
}

// R6-DB-1 FIX: loadFromDB loads all persisted nodes from the database into memory.
//
// TRIE- (2026-07-20): cap in-memory load at MaxNodesToLoad entries.
// Without this cap, a chain that has grown to millions of verkle nodes
// would cause startup OOM as loadFromDB iterates the entire vnode: prefix
// and materializes every value into t.db. When the cap is reached the
// remaining nodes stay on disk and are fetched on demand via persistentDB
// lookups (Get/Has paths already consult persistentDB on cache miss).
func (t *VerkleTree) loadFromDB() {
	if t.persistentDB == nil {
		return
	}
	prefix := []byte(vnodePrefix)
	iter := t.persistentDB.NewIterator(prefix, nil)
	defer iter.Release()

	count := 0
	capped := false
	for iter.Next() {
		if count >= MaxNodesToLoad {
			capped = true
			break
		}
		key := iter.Key()
		if len(key) <= len(prefix) {
			continue
		}
		hashKey := string(key[len(prefix):])
		value := iter.Value()
		nodeData := make([]byte, len(value))
		copy(nodeData, value)
		t.dbMu.Lock()
		t.db[hashKey] = nodeData
		t.dbMu.Unlock()
		count++
	}
	// DB- (2026-07-20): Surface genuine iterator errors (not the
	// MaxNodesToLoad cap, which is intentional and handled below). A real
	// iterator.Error() here would indicate BoltDB corruption or I/O failure.
	if err := iter.Error(); err != nil {
		verkleLog.Warnf("TRIE- loadFromDB iterator error after %d nodes: %v", count, err)
	}

	if capped {
		verkleLog.Warnf("TRIE- loadFromDB hit MaxNodesToLoad=%d cap; %d nodes loaded into memory, remaining nodes served on-demand from persistentDB", MaxNodesToLoad, count)
	}

	if count > 0 {
		// Reconstruct root node from loaded nodes
		t.rebuildRootFromDB()
	}
}

// R6-DB-1 FIX: rebuildRootFromDB reconstructs the root node from loaded nodes.
// TRIE- decodeNode now returns (node, error); ignore corrupted root.
func (t *VerkleTree) rebuildRootFromDB() {
	// The root node is stored with a special key
	rootKey := append([]byte(vnodePrefix), []byte("_root_")...)
	if rootData, err := t.persistentDB.Get(rootKey); err == nil {
		if node, derr := decodeNode(rootData); derr == nil && node != nil {
			t.rootNode = node
			t.root = t.rootNode.Hash()
		}
	}
}

// Root returns the root hash of the tree
func (t *VerkleTree) Root() types.Hash {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.root
}

// keyToStem converts a key to a 31-byte stem.
// TRIE- The previous padding-marker scheme had collisions between
// keys of different lengths (e.g., "abc" and "abc\x80" produced the same
// stem [0x61,0x62,0x63,0x80,0,...]; "" and "\x00"*31 both produced the
// all-zero stem). The new scheme uses a domain-separated SHA-256 hash for
// non-canonical key lengths, which makes collisions cryptographically
// negligible.
//
// Canonical key size is VerkleKeySize (32 bytes). Callers SHOULD
// canonicalize to 32-byte keys for the fast path (direct byte copy, no
// hashing) and to ensure cross-node deterministic root computation.
//
// Keys longer than VerkleKeySize are rejected at the Put/Get/Delete API
// boundary with ErrInvalidKey.
func keyToStem(key []byte) [StemSize]byte {
	if len(key) == VerkleKeySize {
		// Fast path: canonical 32-byte key. Use first 31 bytes directly.
		var stem [StemSize]byte
		copy(stem[:], key[:StemSize])
		return stem
	}
	// Slow path: variable-length key. Use SHA-256 with a domain-separation
	// prefix and 4-byte length suffix to ensure injectivity up to hash
	// collision (cryptographically negligible).
	//
	// Domain separator: "verkle_key_v1\0" (14 bytes) ensures this hash
	// never collides with any other use of SHA-256 in the codebase.
	// 4-byte length suffix: ensures keys of different lengths always
	// produce different hashes (no length-extension ambiguity).
	h := sha3.New256()
	h.Write([]byte("verkle_key_v1\x00"))
	h.Write(key)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(key)))
	h.Write(lenBuf[:])
	sum := h.Sum(nil)
	var stem [StemSize]byte
	copy(stem[:], sum[:StemSize])
	return stem
}

// R6-TRIE-2 FIX: keyToSuffix extracts the suffix (32nd byte) from a key.
// In Verkle trees, the suffix distinguishes different values stored under
// the same 31-byte stem.
// TRIE- For canonical 32-byte keys, returns key[31]. For variable-
// length keys, returns 0xFF (a sentinel). Because variable-length keys
// use SHA-256-derived stems (see keyToStem), they cannot collide with
// 32-byte keys unless a SHA-256 collision occurs (cryptographically
// negligible). Two variable-length keys of different lengths always
// produce different stems, so they never compete for the same suffix slot.
//
// R33 TRIE-05 FIX (2026-07-28): Previously this silently returned 0xFF for
// any non-32-byte key, with no log or warning. While the SHA-256-derived
// stem prevents cryptographically-meaningful collisions, the silent 0xFF
// fallback masks a real operational risk: if a caller accidentally passes
// a truncated or malformed key (e.g., due to a serialization bug), the
// key would be stored under suffix 0xFF with no indication that anything
// went wrong. A subsequent 32-byte key with key[31]==0xFF and a
// matching stem would then overwrite it. Fix: log a warning the first
// time a non-32-byte key is seen, so operators can detect accidental
// misuse. The return value is unchanged to preserve backward
// compatibility with existing callers and tests.
// R35-P2-STATE-01 FIX (2026-07-29): Previously `warnedNonCanonicalKey` was a
// plain bool accessed from multiple goroutines via the non-atomic
// read-modify-write pattern `if !warnedNonCanonicalKey { ...; warnedNonCanonicalKey = true }`.
// This is a DATA RACE — concurrent callers could all read false, all log the
// warning, and all write true, or interleave reads/writes arbitrarily.
// Replace with sync.Once which provides atomic "execute exactly once" semantics
// without any explicit locking on the hot path.
var warnedNonCanonicalKeyOnce sync.Once

func keyToSuffix(key []byte) byte {
	if len(key) == VerkleKeySize {
		return key[StemSize]
	}
	// R33 TRIE-05 FIX: Warn once on non-canonical key. sync.Once guarantees
	// the warning fires exactly once even under concurrent access, eliminating
	// the data race on the previous warnedNonCanonicalKey bool.
	warnedNonCanonicalKeyOnce.Do(func() {
		verkleLog.Warn("verkle: non-canonical key length detected — keyToSuffix returning 0xFF sentinel. "+
			"Callers should canonicalize to 32-byte keys to avoid suffix collisions.",
			map[string]any{"key_len": len(key), "expected": VerkleKeySize})
	})
	return 0xFF
}

// Get retrieves a value from the tree
func (t *VerkleTree) Get(key []byte) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.rootNode == nil {
		return nil, ErrKeyNotFound
	}

	stem := keyToStem(key)
	node := t.walk(t.rootNode, stem, 0)
	if node == nil {
		return nil, ErrKeyNotFound
	}

	if leaf, ok := node.(*LeafNode); ok {
		if bytes.Equal(leaf.Key, key) {
			// R37-P3-09 FIX (2026-07-31): return a defensive copy so callers
			// cannot mutate the tree's internal state through the returned slice.
			return append([]byte(nil), leaf.Value...), nil
		}
		// AUDIT (2026) R3-DATA-01: Check suffix-indexed values for
		// same-stem keys that differ in the 32nd byte.
		if leaf.SuffixValues != nil {
			suffix := keyToSuffix(key)
			if val, exists := leaf.SuffixValues[suffix]; exists {
				// R37-P3-09 FIX (2026-07-31): defensive copy — see above.
				return append([]byte(nil), val...), nil
			}
		}
		return nil, ErrKeyNotFound
	}

	return nil, ErrKeyNotFound
}

// walk traverses the tree following the stem
//
// R32-P2-06 FIX (2026-07-28): Added hard recursion depth backstop
// (maxVerkleRecursionDepth). The logical depth check `depth >= StemSize`
// protects legitimate trees, but a corrupted or maliciously-crafted tree
// with an ExtensionNode cycle (StemLen == 0, or child → ancestor) would
// never reach StemSize and recurse until stack overflow. The hard limit
// returns nil on overflow and logs a warning so corruption is detectable.
// StemLen == 0 is also rejected explicitly since it cannot represent a
// valid extension (an extension with zero-length stem is meaningless and
// would cause zero-progress recursion).
func (t *VerkleTree) walk(node TreeNode, stem [StemSize]byte, depth int) TreeNode {
	if node == nil || depth >= StemSize {
		return node
	}
	// R32-P2-06: Hard backstop — catches cycles / StemLen==0 corruption
	// that the logical StemSize check cannot.
	if depth >= maxVerkleRecursionDepth {
		verkleLog.Warn("verkle walk: hit hard recursion depth limit (tree may be corrupted)",
			map[string]any{"depth": depth, "limit": maxVerkleRecursionDepth})
		return nil
	}

	switch n := node.(type) {
	case *LeafNode:
		// TRIE- Compare the leaf's derived stem against the input
		// stem (full 31 bytes). Previously this compared n.Key bytes against
		// stem[:cmpLen], which only worked when stems were derived by direct
		// byte copy from keys. With SHA-256-derived stems for variable-length
		// keys, n.Key bytes no longer equal stem bytes, so the comparison
		// silently returned nil for every non-canonical key. Recomputing the
		// leaf's stem here is symmetric with the insert() path (line ~994),
		// which already uses keyToStem(n.Key) to detect same-stem collisions.
		leafStem := keyToStem(n.Key)
		if bytes.Equal(leafStem[:], stem[:]) {
			return n
		}
		return nil

	case *InternalNode:
		if depth >= StemSize {
			return nil
		}
		idx := int(stem[depth]) // #nosec G602 -- slice bounds verified by surrounding logic
		childHash := n.Children[idx]
		if childHash == (types.Hash{}) {
			return nil
		}
		childNode := t.getNode(childHash)
		return t.walk(childNode, stem, depth+1)

	case *ExtensionNode:
		// R32-P2-06: StemLen == 0 is invalid — it represents an extension
		// with no stem, which makes no semantic sense and would cause
		// zero-progress recursion (depth+n.StemLen == depth). Treat as
		// corruption and stop descent.
		if n.StemLen <= 0 || n.StemLen > StemSize {
			verkleLog.Warn("verkle walk: ExtensionNode has invalid StemLen (tree corrupted)",
				map[string]any{"stemLen": n.StemLen})
			return nil
		}
		// R33 TRIE-02 FIX: Use relative prefix (stem[depth:]) to match
		// proveWalk() semantics. Previously this used absolute prefix
		// (stem[:]) which only worked when depth == 0. With depth > 0,
		// the extension's relative Stem (stored from splitLeaf) would
		// not match the absolute comparison, causing walk to fail and
		// Get to return ErrKeyNotFound for keys under nested extensions.
		if bytes.HasPrefix(stem[depth:], n.Stem[:n.StemLen]) {
			child := n.Child
			if child == nil && n.childHash != (types.Hash{}) {
				child = t.getNode(n.childHash)
			}
			return t.walk(child, stem, depth+n.StemLen)
		}
		return nil
	}

	return nil
}

// Put inserts or updates a key-value pair
// TRIE- reject empty and oversized keys. Empty keys previously
// produced an all-zero stem that collided with "\x00"*31; oversized keys
// (len > 32) cannot be injectively encoded into a 31+1 byte stem+suffix.
func (t *VerkleTree) Put(key, value []byte) error {
	if len(key) == 0 {
		return ErrInvalidKey
	}
	if len(key) > VerkleKeySize {
		return ErrInvalidKey
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	stem := keyToStem(key)
	t.rootNode = t.insert(t.rootNode, stem, key, value, 0)
	t.recomputeRoot()
	return nil
}

// insert recursively inserts a key-value pair
//
// R32-P2-06 FIX (2026-07-28): Added hard recursion depth backstop
// (maxVerkleRecursionDepth). The InternalNode case already checks
// `depth >= StemSize`, but the ExtensionNode case advances depth by
// n.StemLen — a corrupted node with StemLen == 0 (or a cycle) would
// recurse without bound. The hard limit returns the current node
// unchanged on overflow and logs a warning.
func (t *VerkleTree) insert(node TreeNode, stem [StemSize]byte, key, value []byte, depth int) TreeNode {
	// Base case: empty tree
	if node == nil {
		leaf := NewLeafNode(key, value)
		t.storeNode(leaf)
		return leaf
	}
	// R32-P2-06: Hard backstop — see walk() docs for rationale.
	if depth >= maxVerkleRecursionDepth {
		verkleLog.Warn("verkle insert: hit hard recursion depth limit (tree may be corrupted)",
			map[string]any{"depth": depth, "limit": maxVerkleRecursionDepth})
		return node
	}

	switch n := node.(type) {
	case *LeafNode:
		// Leaf exists - either update or split
		if bytes.Equal(n.Key, key) {
			// Same key - update
			leaf := NewLeafNode(key, value)
			// AUDIT (2026) R4-DATA-04 FIX: Preserve SuffixValues from
			// the old leaf. The old leaf may have SuffixValues entries for
			// other keys sharing the same 31-byte stem. Creating a new leaf
			// without them would silently drop those entries, causing data
			// loss and a root hash that doesn't reflect the true state.
			if len(n.SuffixValues) > 0 {
				leaf.SuffixValues = make(map[byte][]byte, len(n.SuffixValues))
				for k, v := range n.SuffixValues {
					leaf.SuffixValues[k] = v
				}
				leaf.recomputeHash()
			}
			t.storeNode(leaf)
			return leaf
		}
		// AUDIT (2026) R3-DATA-01: If the keys share the same 31-byte
		// stem but differ in the suffix (32nd byte), store as a suffix-
		// indexed entry instead of splitting. This prevents the collision
		// where the second Put would overwrite the first.
		existingStem := keyToStem(n.Key)
		if bytes.Equal(existingStem[:], stem[:]) {
			if n.SuffixValues == nil {
				n.SuffixValues = make(map[byte][]byte)
			}
			suffix := keyToSuffix(key)
			// R37-P3-09 FIX (2026-07-31): defensive copy of suffix value so
			// callers cannot mutate the tree's internal state.
			if len(value) > 0 {
				n.SuffixValues[suffix] = append([]byte(nil), value...)
			} else {
				n.SuffixValues[suffix] = nil
			}
			n.recomputeHash()
			t.storeNode(n)
			return n
		}
		// Different stem - create extension + two leaves
		return t.splitLeaf(n, stem, key, value, depth)

	case *InternalNode:
		if depth >= StemSize {
			return n
		}
		idx := int(stem[depth]) // #nosec G602 -- slice bounds verified by surrounding logic
		childHash := n.Children[idx]
		var childNode TreeNode
		if childHash != (types.Hash{}) {
			childNode = t.getNode(childHash)
		}
		newChild := t.insert(childNode, stem, key, value, depth+1)
		// R33 TRIE-03 FIX: Removed the "absorb" logic that previously
		// stripped 1 byte from an ExtensionNode returned by splitLeaf.
		// In the relative-stem world (TRIE-02/03 fix), splitLeaf returns
		// an ExtensionNode whose Stem is already relative to depth+1
		// (the depth at which splitLeaf was called). Stripping 1 byte
		// would shift the stem to start at depth+2, causing walk()'s
		// HasPrefix(stem[depth+1:], ext.Stem[:StemLen]) check to compare
		// the wrong byte positions → Get returns ErrKeyNotFound for all
		// keys under the extension. With relative stems, no stripping is
		// needed — the ExtensionNode is stored as-is at Children[idx].
		newChildHash := types.Hash{}
		if newChild != nil {
			newChildHash = newChild.Hash()
		}
		if newChildHash != childHash {
			n.Children[idx] = t.storeAndGetHash(newChild)
			n.recomputeHash()
			t.storeNode(n)
		}
		return n

	case *ExtensionNode:
		// R32-P2-06: Reject invalid StemLen. StemLen <= 0 means zero-progress
		// recursion; StemLen > StemSize means the stem slice n.Stem[:n.StemLen]
		// is invalid. Either case indicates tree corruption — abort insert.
		if n.StemLen <= 0 || n.StemLen > StemSize {
			verkleLog.Warn("verkle insert: ExtensionNode has invalid StemLen (tree corrupted)",
				map[string]any{"stemLen": n.StemLen})
			return node
		}
		// R33 TRIE-02 FIX: Use relative prefix (stem[depth:]) to match
		// proveWalk()/walk() semantics. The ExtensionNode's Stem is stored
		// as a RELATIVE prefix (starting from depth), so the comparison
		// must also be relative.
		if !bytes.HasPrefix(stem[depth:], n.Stem[:n.StemLen]) {
			// R32-P0-4 FIX (2026-07-28): Complete rewrite of ExtensionNode
			// split logic. The previous code had two critical bugs:
			//
			// BUG 1 (Children overwrite): oldIdx=n.Stem[0] and newIdx=stem[depth]
			// were used as InternalNode child indices. But the ExtensionNode's
			// Stem is an ABSOLUTE prefix from position 0 (see splitLeaf line
			// ~1680: extStem = oldStem[:diffIdx]). When the divergence point
			// is > 0, n.Stem[0] == stem[0] (they share a prefix), so
			// oldIdx == newIdx → the new leaf overwrites the old subtree,
			// silently losing all keys under the old extension.
			//
			// BUG 2 (stem stripping mismatch): When StemLen > 1, the code
			// stripped the FIRST byte (n.Stem[1:]) and created a shorter
			// extension. But walk() checks HasPrefix(stem, ext.Stem[:StemLen])
			// from position 0 — the stripped extension's stem no longer
			// matches what walk() expects, so Get() returns ErrKeyNotFound
			// for all keys under the old extension.
			//
			// CORRECT ALGORITHM (mirrors splitLeaf):
			// 1. Find the divergence point `div` — the first position where
			//    stem[depth+div] != n.Stem[div] (relative comparison, since
			//    n.Stem is relative to depth). Since !HasPrefix is true,
			//    div < n.StemLen is guaranteed.
			// 2. oldIdx = n.Stem[div], newIdx = stem[depth+div] — these are
			//    GUARANTEED different (by definition of div).
			// 3. The old extension's remaining stem (after div) becomes a
			//    shorter ExtensionNode wrapping n.Child. If div+1 ==
			//    n.StemLen, the remaining stem is empty → use n.Child directly.
			// 4. The new key becomes a leaf at position depth+div.
			// 5. If div > 0, wrap the InternalNode in a new ExtensionNode
			//    with stem n.Stem[:div] (the shared relative prefix).
			//
			// R33 TRIE-02 FIX: div comparison uses stem[depth+div] (relative)
			// instead of stem[div] (absolute), since n.Stem is now relative.
			div := 0
			for div < n.StemLen {
				if stem[depth+div] != n.Stem[div] {
					break
				}
				div++
			}
			// div < n.StemLen is guaranteed by !HasPrefix above.
			if div >= n.StemLen {
				// Defensive: should be unreachable due to HasPrefix check.
				// If it happens, fall through to the prefix-match path below
				// rather than corrupting the tree.
				verkleLog.Warn("verkle: extension split reached unexpected state",
					map[string]any{"div": div, "stemLen": n.StemLen})
				child := n.Child
				if child == nil && n.childHash != (types.Hash{}) {
					child = t.getNode(n.childHash)
				}
				oldChildHash := types.Hash{}
				if child != nil {
					oldChildHash = child.Hash()
				}
				newChild := t.insert(child, stem, key, value, depth+n.StemLen)
				if newChild != nil && newChild.Hash() != oldChildHash {
					n.Child = newChild
					n.childHash = newChild.Hash()
					n.recomputeHash()
					t.storeNode(n)
				}
				return n
			}

			oldIdx := int(n.Stem[div])     // #nosec G115 -- 0..255 fits in int
			newIdx := int(stem[depth+div]) // R33 TRIE-02 FIX: relative position

			// Build the old child: shorten the extension's stem to n.Stem[div+1:].
			child := n.Child
			if child == nil && n.childHash != (types.Hash{}) {
				child = t.getNode(n.childHash)
			}
			var oldChild TreeNode
			remainingLen := n.StemLen - div - 1
			if remainingLen == 0 {
				// No stem left after stripping the prefix → use child directly.
				oldChild = child
			} else {
				var remainingStem [StemSize]byte
				copy(remainingStem[:], n.Stem[div+1:n.StemLen])
				adjusted := NewExtensionNode(remainingStem, remainingLen, child)
				t.storeNode(adjusted)
				oldChild = adjusted
			}

			newInternal := NewInternalNode()
			newInternal.Children[oldIdx] = t.storeAndGetHash(oldChild)

			newLeaf := NewLeafNode(key, value)
			t.storeNode(newLeaf)
			newInternal.Children[newIdx] = t.storeAndGetHash(newLeaf)
			newInternal.recomputeHash()
			t.storeNode(newInternal)

			// If there's a shared prefix (div > 0), wrap the InternalNode
			// in a new ExtensionNode with the shared prefix stem.
			if div > 0 {
				var sharedStem [StemSize]byte
				copy(sharedStem[:], n.Stem[:div])
				wrapper := NewExtensionNode(sharedStem, div, newInternal)
				t.storeNode(wrapper)
				return wrapper
			}
			return newInternal
		}
		child := n.Child
		if child == nil && n.childHash != (types.Hash{}) {
			child = t.getNode(n.childHash)
		}
		oldChildHash := types.Hash{}
		if child != nil {
			oldChildHash = child.Hash()
		}
		newChild := t.insert(child, stem, key, value, depth+n.StemLen)
		if newChild != nil && newChild.Hash() != oldChildHash {
			n.Child = newChild
			n.childHash = newChild.Hash()
			n.recomputeHash()
			t.storeNode(n)
		}
		return n
	}

	return node
}

// splitLeaf creates an extension node when two keys diverge
func (t *VerkleTree) splitLeaf(oldLeaf *LeafNode, stem [StemSize]byte, newKey, newValue []byte, depth int) TreeNode {
	// TRIE- All tree path decisions (InternalNode child indices,
	// ExtensionNode stem prefixes, walk descent) are derived from STEM
	// bytes. With SHA-256-derived stems for variable-length keys, KEY
	// bytes no longer correspond to STEM bytes — comparing keys to find
	// the divergence point produces incorrect indices and extension
	// prefixes, causing subsequent Get/walk to miss the leaf. Compare
	// STEM bytes instead.
	//
	// Both stems are exactly StemSize (31) bytes long, so the comparison
	// is well-defined. The first `depth` bytes are guaranteed to match
	// because walk/insert descended through `depth` InternalNodes to
	// reach this leaf — so divergence (if any) lies at index >= depth.
	//
	// R33 TRIE-03 FIX: Start scanning from `depth` (not 0) and return a
	// RELATIVE Stem (oldStem[depth:diffIdx]) for the ExtensionNode. This
	// matches walk()/proveWalk() which use HasPrefix(stem[depth:], ...)
	// for prefix matching. Previously, scanning from 0 produced an
	// ABSOLUTE stem (oldStem[:diffIdx]) which only worked when depth == 0.
	// When depth > 0, walk()'s relative check would fail because the
	// absolute stem's bytes [0:depth] don't match stem[depth:depth+StemLen].
	oldStem := keyToStem(oldLeaf.Key)

	// R33 TRIE-03 FIX: Start from depth — bytes [0:depth] are guaranteed
	// to match (descended through depth InternalNodes to get here).
	diffIdx := depth
	for diffIdx < StemSize {
		if oldStem[diffIdx] != stem[diffIdx] {
			break
		}
		diffIdx++
	}

	// AUDIT (2026) R3-DATA-01: Same-stem keys (diffIdx >= StemSize)
	// are handled in insert() via SuffixValues and never reach splitLeaf.
	// Defensive: if a future caller violates this invariant, treat as a
	// same-stem update so we don't silently corrupt the tree.
	if diffIdx >= StemSize {
		leaf := NewLeafNode(newKey, newValue)
		if len(oldLeaf.SuffixValues) > 0 {
			leaf.SuffixValues = make(map[byte][]byte, len(oldLeaf.SuffixValues))
			for k, v := range oldLeaf.SuffixValues {
				leaf.SuffixValues[k] = v
			}
			leaf.recomputeHash()
		}
		t.storeNode(leaf)
		return leaf
	}

	internal := NewInternalNode()

	// TRIE- child indices must be STEM bytes (0..255), not KEY
	// bytes. The old code used a 0x80 sentinel for the shorter key when
	// one was a prefix of the other; with fixed-size 31-byte stems this
	// case never arises.
	oldIdx := int(oldStem[diffIdx]) // #nosec G115 -- 0..255 fits in int
	newIdx := int(stem[diffIdx])    // #nosec G115 -- 0..255 fits in int

	// AUDIT (2026) R4-DATA-04 FIX: Preserve SuffixValues from the old
	// leaf when splitting. The previous code called t.insert(nil, ...) which
	// hits the base case (NewLeafNode(key, value)) and silently dropped any
	// SuffixValues entries the old leaf held for keys sharing its 31-byte
	// stem. Because the re-inserted leaf retains the same stem as oldLeaf,
	// those entries still belong to it and must be migrated. Dropping them
	// would cause data loss and a root hash that doesn't reflect the true
	// state.
	oldChild := NewLeafNode(oldLeaf.Key, oldLeaf.Value)
	if len(oldLeaf.SuffixValues) > 0 {
		oldChild.SuffixValues = make(map[byte][]byte, len(oldLeaf.SuffixValues))
		for k, v := range oldLeaf.SuffixValues {
			oldChild.SuffixValues[k] = v
		}
		oldChild.recomputeHash()
	}
	t.storeNode(oldChild)
	internal.Children[oldIdx] = t.storeAndGetHash(oldChild)

	newStemCopy := stem
	newChild := t.insert(nil, newStemCopy, newKey, newValue, diffIdx+1)
	internal.Children[newIdx] = t.storeAndGetHash(newChild)

	internal.recomputeHash()
	t.storeNode(internal)

	// R33 TRIE-03 FIX: Extension stem must be the RELATIVE shared STEM
	// prefix (from depth to diffIdx), not the absolute prefix (from 0 to
	// diffIdx). walk()/proveWalk() check HasPrefix(stem[depth:], ...)
	// against the extension's Stem, so ext.Stem must be oldStem[depth:diffIdx]
	// (length diffIdx - depth) to match at the correct position.
	var extStem [StemSize]byte
	copy(extStem[:], oldStem[depth:diffIdx])

	// R33 TRIE-03 FIX: diffIdx == depth means no shared prefix beyond what
	// was already descended → no extension needed, return InternalNode.
	if diffIdx == depth {
		return internal
	}

	ext := NewExtensionNode(extStem, diffIdx-depth, internal)
	t.storeNode(ext)
	return ext
}

// Delete removes a key from the tree
// TRIE- reject empty and oversized keys (same as Put).
//
// TRIE- (2026-07-21) NOTE: Delete does NOT automatically invoke
// PruneOrphans() after removing a key. This is an intentional design
// choice: PruneOrphans() performs a full BFS traversal of the tree to
// identify unreachable nodes, which is O(N) per call. Calling it on
// every Delete would make batch deletions O(N²) — unacceptable for
// blockchain state pruning where thousands of keys may be deleted per
// block.
//
// Orphaned nodes (those no longer reachable from rootNode) accumulate
// in the in-memory cache (t.db) and persistent DB until PruneOrphans()
// is called. They do NOT affect correctness — tree operations only
// traverse reachable nodes — but they do consume disk and memory.
//
// Operators SHOULD call PruneOrphans() periodically (e.g., after each
// epoch transition, or when the orphan count exceeds a threshold) to
// reclaim storage. A future enhancement could track an orphan counter
// and auto-trigger pruning when it crosses a configurable threshold,
// but for now the caller is responsible.
func (t *VerkleTree) Delete(key []byte) error {
	if len(key) == 0 {
		return ErrInvalidKey
	}
	if len(key) > VerkleKeySize {
		return ErrInvalidKey
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	stem := keyToStem(key)
	t.rootNode = t.delete(t.rootNode, stem, key, 0)
	t.recomputeRoot()
	return nil
}

// delete recursively removes a key
//
// R32-P2-06 FIX (2026-07-28): Added hard recursion depth backstop
// (maxVerkleRecursionDepth) and StemLen validation. Same rationale as
// walk()/insert(): a corrupted ExtensionNode with StemLen == 0 or a cycle
// would otherwise recurse without bound.
func (t *VerkleTree) delete(node TreeNode, stem [StemSize]byte, key []byte, depth int) TreeNode {
	if node == nil {
		return nil
	}
	// R32-P2-06: Hard backstop — see walk() docs for rationale.
	if depth >= maxVerkleRecursionDepth {
		verkleLog.Warn("verkle delete: hit hard recursion depth limit (tree may be corrupted)",
			map[string]any{"depth": depth, "limit": maxVerkleRecursionDepth})
		return node
	}

	switch n := node.(type) {
	case *LeafNode:
		if bytes.Equal(n.Key, key) {
			// Primary key matches — remove it. If there are suffix values,
			// promote one to the primary slot; otherwise remove the leaf.
			if len(n.SuffixValues) > 0 {
				// R32-P0-3 FIX (2026-07-28): Go map iteration order is
				// randomized. Previously, `for suffix, val := range n.SuffixValues`
				// with `break` picked a NON-DETERMINISTIC suffix on each node,
				// causing different nodes to promote different suffix values
				// after the same delete operation → different tree topology →
				// different state root → consensus fork.
				//
				// Fix: collect all suffixes into a slice, sort them, and
				// deterministically pick the SMALLEST suffix for promotion.
				// This ensures all nodes produce the same tree structure
				// after deleting the same key.
				suffixes := make([]byte, 0, len(n.SuffixValues))
				for suffix := range n.SuffixValues {
					suffixes = append(suffixes, suffix)
				}
				sort.Slice(suffixes, func(i, j int) bool {
					return suffixes[i] < suffixes[j]
				})
				// Promote the smallest suffix to primary.
				suffix := suffixes[0]
				val := n.SuffixValues[suffix]
				// R33 TRIE-04 FIX (2026-07-28): Defensive copy of val before
				// deleting from SuffixValues. Previously n.Value = val assigned
				// the slice header directly — if a future code path retains a
				// reference to the same underlying array (e.g. via a cached
				// proof or a parallel reader), mutations would leak between
				// the promoted primary value and the stale SuffixValues entry.
				// Deep-copy so n.Value owns its own byte slice.
				valCopy := make([]byte, len(val))
				copy(valCopy, val)
				// Reconstruct the full key: same stem as n.Key, with the
				// suffix byte replaced.
				//
				// R33 TRIE-04 FIX: Validate n.Key length. A well-formed
				// Verkle leaf key must be exactly VerkleKeySize (32) bytes.
				// If a corrupted node has a shorter key, reconstruct from
				// the stem + suffix instead of copying a partial key and
				// appending (which would produce a key of the wrong length
				// and break downstream bytes.Equal checks in walk/insert).
				var newKey []byte
				if len(n.Key) >= VerkleKeySize {
					newKey = make([]byte, VerkleKeySize)
					copy(newKey, n.Key[:VerkleKeySize])
					newKey[StemSize] = suffix
				} else {
					// Corrupted key — rebuild from stem + suffix.
					newKey = make([]byte, VerkleKeySize)
					stemBytes := keyToStem(key)
					copy(newKey, stemBytes[:])
					newKey[StemSize] = suffix
				}
				n.Key = newKey
				n.Value = valCopy
				delete(n.SuffixValues, suffix)
				n.recomputeHash()
				t.storeNode(n)
				return n
			}
			return nil // Remove
		}
		// AUDIT (2026) R3-DATA-01: Check suffix-indexed values.
		if n.SuffixValues != nil {
			suffix := keyToSuffix(key)
			if _, exists := n.SuffixValues[suffix]; exists {
				delete(n.SuffixValues, suffix)
				n.recomputeHash()
				t.storeNode(n)
			}
		}
		return n

	case *InternalNode:
		if depth >= StemSize {
			return n
		}
		idx := int(stem[depth]) // #nosec G602 -- slice bounds verified by surrounding logic
		childHash := n.Children[idx]
		if childHash == (types.Hash{}) {
			return n
		}
		childNode := t.getNode(childHash)
		// R14-MED (2026-07-21): Clear stale hash reference when the child
		// node is "lost" (present in Children[idx] but missing from both
		// in-memory cache and persistentDB). Without this guard, the
		// orphaned hash reference stays in n.Children[idx] forever:
		// future Get/Put/Delete operations on this slot silently fail,
		// PruneOrphans cannot reclaim the entry, and later storeNode(n)
		// calls persist the broken reference.
		if childNode == nil {
			verkleLog.Warn("InternalNode.delete: clearing stale child hash reference (child node missing from DB)",
				map[string]any{
					"depth": depth,
					"idx":   idx,
					"hash":  childHash.String(),
				})
			n.Children[idx] = types.Hash{}
			n.recomputeHash()
			t.storeNode(n)
			return n
		}
		newChild := t.delete(childNode, stem, key, depth+1)
		// R33 TRIE-02/03 FIX: Compare HASHES instead of POINTERS. A
		// recursive delete may modify a child node in place (same Go
		// pointer) while changing its hash — e.g., clearing a child
		// slot in a deeply nested InternalNode changes the node's hash
		// but not its address. The old pointer comparison
		// (`newChild != childNode`) would miss this case, leaving
		// n.Children[idx] pointing at the OLD hash. Subsequent Get/
		// walk calls would load the stale node from cache, seeing
		// deleted keys as still present.
		//
		// This mirrors insert()'s hash-comparison pattern (line ~1604).
		// When newChild is nil (key was deleted and leaf had no suffix
		// values), newChildHash stays zero — which differs from the
		// non-zero childHash, so we enter the block and clear the slot.
		newChildHash := types.Hash{}
		if newChild != nil {
			newChildHash = newChild.Hash()
		}
		if newChildHash != childHash {
			if newChild == nil {
				n.Children[idx] = types.Hash{}
			} else {
				n.Children[idx] = t.storeAndGetHash(newChild)
			}
			n.recomputeHash()
			t.storeNode(n)
		}
		// R33 P2-06 FIX (2026-07-28): After deleting from a child, check if
		// the InternalNode now has ALL children empty. An all-empty InternalNode
		// is non-canonical: it contributes nothing to the tree but has a non-zero
		// hash (hash of the node structure, not of any data). Different nodes
		// might represent the "empty" state differently (nil vs. all-zeros
		// InternalNode), causing state root divergence. Return nil to remove
		// the empty InternalNode entirely, allowing the parent to compact.
		allEmpty := true
		for _, ch := range n.Children {
			if ch != (types.Hash{}) {
				allEmpty = false
				break
			}
		}
		if allEmpty {
			return nil
		}
		return n

	case *ExtensionNode:
		// R32-P2-06: Reject invalid StemLen before recursing — same
		// rationale as walk()/insert(). Without this, a StemLen == 0
		// node would recurse with depth+0 → infinite loop until the
		// hard backstop fires.
		if n.StemLen <= 0 || n.StemLen > StemSize {
			verkleLog.Warn("verkle delete: ExtensionNode has invalid StemLen (tree corrupted)",
				map[string]any{"stemLen": n.StemLen})
			return node
		}
		// R33 TRIE-01 FIX (2026-07-28): Check stem prefix match BEFORE
		// recursing, consistent with walk()/insert()/proveWalk(). Without
		// this check, if the key's stem doesn't match the extension's stem,
		// delete() would still recurse into the child and potentially delete
		// a completely unrelated key. This is especially dangerous when the
		// node was loaded from DB (n.Child == nil): the old code called
		// t.delete(nil, ...) which returned nil, causing the entire subtree
		// to be deleted — permanent state loss.
		//
		// Use relative prefix (stem[depth:]) to match proveWalk() semantics.
		// walk() uses absolute prefix (stem[:]) which is a separate bug
		// (TRIE-02) — for delete() we use the correct relative form.
		if depth > len(stem) || !bytes.HasPrefix(stem[depth:], n.Stem[:n.StemLen]) {
			// Stem doesn't match — the key being deleted is NOT in this
			// subtree. Return the node unchanged (no deletion).
			return node
		}
		// R33 TRIE-01 FIX: Lazy-load the child if it's only present as a
		// hash reference (loaded from DB). Without this, n.Child == nil
		// would cause t.delete(nil, ...) → nil return → entire subtree
		// deletion. This mirrors walk()'s lazy-loading pattern.
		child := n.Child
		if child == nil && n.childHash != (types.Hash{}) {
			child = t.getNode(n.childHash)
			if child == nil {
				// Child hash present but node missing from DB — can't
				// recurse. Return unchanged rather than deleting.
				verkleLog.Warn("verkle delete: ExtensionNode child missing from DB (preserving subtree)",
					map[string]any{"childHash": n.childHash.String()})
				return node
			}
		}
		newChild := t.delete(child, stem, key, depth+n.StemLen)
		if newChild == nil {
			// Child subtree became empty — remove the extension entirely.
			return nil
		}
		n.Child = newChild
		n.recomputeHash()
		t.storeNode(n)
		return n
	}

	return node
}

// storeAndGetHash stores a node and returns its hash
func (t *VerkleTree) storeAndGetHash(node TreeNode) types.Hash {
	t.storeNode(node)
	return node.Hash()
}

// storeNode stores a node in the database
// R6-DB-1 FIX: also persists to persistentDB if available
// TRIE- prepend VerkleEncodingMagic to all cached/persisted bytes.
//
// STORAGE-P0-01 FIX (R31, 2026-07-27): When persistentDB is configured,
// appends to pendingBatch instead of issuing individual Put calls. This
// guarantees that all node writes within a logical operation (Put/Delete/
// recomputeRoot) are committed atomically by Flush(), preventing half-
// written trees on crash. Errors are captured in pendingBatchErr and
// surfaced via Flush() — callers MUST check Flush() return value at
// logical boundaries.
func (t *VerkleTree) storeNode(node TreeNode) {
	if node == nil {
		return
	}
	data := encodeNodeWithMagic(node)
	if len(data) == 0 {
		return
	}
	hash := node.Hash()
	t.dbMu.Lock()
	t.db[string(hash[:])] = data
	t.dbMu.Unlock()

	if t.persistentDB != nil {
		key := append([]byte(vnodePrefix), hash[:]...)
		// STORAGE-P0-01/03 FIX: route through pendingBatch for atomicity
		// and error propagation. recordPendingError preserves the first
		// error so Flush() can surface it to the caller.
		t.recordPendingWrite(key, data, hash[:8])
	}
}

// recordPendingWrite appends a key/value pair to the pending batch and
// captures the first error. STORAGE-P0-01 FIX (R31, 2026-07-27).
//
// P1-STATE-04 FIX (2026-07-30, R36): On ErrBatchFull, split the batch
// (Flush commits accumulated ops and resets) then retry the Put in the
// fresh batch. Previously, ANY Put error (including ErrBatchFull) was
// captured into pendingBatchErr and made permanently sticky — Flush()
// would never attempt to Write the retained batch, so the "retained for
// retry" path was unreachable. A single busy block (>10k node writes)
// would permanently disable Verkle tree persistence for the entire
// process lifetime, forcing manual restart. Now ErrBatchFull is handled
// inline so the batch never gets stuck; only genuine I/O failures set
// the sticky error (and Flush now retries those too — see Flush).
//
// R39-P1-05 (2026-08-02): cross-tree flush ordering is serialized by
// persistentFlushMu, taken FIRST (lock order persistentFlushMu →
// pendingBatchMu matches Flush(), no cycle).
//
// AUDIT-FULL ST-02 (2026-08-14) FIX: previously persistentFlushMu was
// acquired at function ENTRY and held across the plain batch-append
// path, globally serializing EVERY node write of ALL trees sharing the
// persistentDB (per-node global mutex — a throughput bottleneck and a
// latency amplifier when one tree hits ErrBatchFull and flushes to
// bbolt while holding the global lock). Now the fast path takes only
// the per-tree pendingBatchMu (each tree's batch is an independent
// object; plain appends need no cross-tree serialization). The global
// persistentFlushMu is taken ONLY on the ErrBatchFull slow path, where
// a real cross-tree-visible bbolt write happens — acquired AFTER
// releasing pendingBatchMu, then re-acquiring both in the Flush()
// order, so the lock hierarchy stays strictly one-directional.
func (t *VerkleTree) recordPendingWrite(key, value []byte, hashShort []byte) {
	// Fast path: per-tree lock only (AUDIT-FULL ST-02).
	putErr := func() error {
		t.pendingBatchMu.Lock()
		defer t.pendingBatchMu.Unlock()

		// If a previous append already failed, keep the first error and
		// skip further appends — the batch is in an indeterminate state.
		if t.pendingBatchErr != nil {
			return nil // already sticky; nothing to do
		}

		// pendingBatch may be nil if persistentDB was set without going
		// through NewVerkleTree (e.g., in tests that build the struct
		// manually). Fall back to direct Put with error capture so the
		// failure is still surfaced via Flush().
		if t.pendingBatch == nil {
			if err := t.persistentDB.Put(key, value); err != nil {
				verkleLog.Errorf("Failed to persist verkle node %x: %v", hashShort, err)
				t.pendingBatchErr = fmt.Errorf("verkle node %x: %w", hashShort, err)
			}
			return nil
		}
		return t.pendingBatch.Put(key, value)
	}()

	if putErr == nil || !errors.Is(putErr, db.ErrBatchFull) {
		if putErr != nil {
			// Genuine append failure: record the sticky first error.
			t.pendingBatchMu.Lock()
			if t.pendingBatchErr == nil {
				verkleLog.Errorf("Failed to append verkle node %x to batch: %v", hashShort, putErr)
				t.pendingBatchErr = fmt.Errorf("verkle node %x: %w", hashShort, putErr)
			}
			t.pendingBatchMu.Unlock()
		}
		return
	}

	// ErrBatchFull slow path: the failing op was NOT appended. Split the
	// batch (Flush commits accumulated ops and resets) then retry the Put
	// in the fresh batch. This path performs a cross-tree-visible bbolt
	// write, so take persistentFlushMu FIRST (Flush() lock order).
	flushMu := t.persistentFlushMu
	if flushMu == nil {
		flushMu = &sync.Mutex{}
	}
	flushMu.Lock()
	defer flushMu.Unlock()

	t.pendingBatchMu.Lock()
	defer t.pendingBatchMu.Unlock()

	if t.pendingBatchErr != nil {
		return
	}
	if flushErr := t.pendingBatch.Flush(); flushErr != nil {
		verkleLog.Errorf("Failed to flush full verkle batch before retry (node %x): %v", hashShort, flushErr)
		t.pendingBatchErr = fmt.Errorf("verkle node %x: flush before retry failed: %w", hashShort, flushErr)
		return
	}
	// Retry in the freshly-reset batch.
	if retryErr := t.pendingBatch.Put(key, value); retryErr != nil {
		verkleLog.Errorf("Failed to append verkle node %x to batch after split: %v", hashShort, retryErr)
		t.pendingBatchErr = fmt.Errorf("verkle node %x: %w", hashShort, retryErr)
	}
}

// Flush atomically commits all pending node writes to persistentDB.
// STORAGE-P0-01 FIX (R31, 2026-07-27): Callers MUST invoke Flush() at
// logical boundaries (e.g., end of StateDB.Commit, end of block
// processing) to ensure on-disk tree consistency. Returns nil when
// persistentDB is not configured. After Flush returns, the pending
// batch is reset (regardless of success/failure) so the next operation
// starts fresh.
//
// R33 TRIE-06 FIX (2026-07-28): Previously, on batch.Write() failure the
// pending batch was Reset(), discarding all queued mutations while the
// in-memory cache (t.db) still held the new node versions. This left
// memory and disk permanently inconsistent: subsequent reads would hit
// the in-memory cache and return the new node, but after eviction the
// disk would only have the old version (or nothing), causing silent
// state root divergence. Fix: on Write failure, do NOT reset the
// pending batch — preserve it so the next Flush() can retry the same
// mutations. The in-memory cache remains authoritative for reads, and
// the persisted state will catch up on the next successful Flush().
// Callers receive the error and can choose to retry, halt, or alert.
//
// R39-P1-05 (2026-08-02) FIX: Serialize Flush() across all trees that
// share the same persistentDB (collection via the shared
// persistentFlushMu POINTER — see Copy()). bbolt already serializes
// transactions internally, but the cross-tree write ORDER is otherwise
// non-deterministic, and the audit calls out that commit-pending marker
// sequencing mediated by external state_db.go depends on tree.Flush()
// having an observably stable with-respect-to-other-tree order. We
// acquire persistentFlushMu FIRST (strict one-direction lock order
// persistentFlushMu → pendingBatchMu, no cycle) so concurrent Flush()
// calls from sibling trees block on this mutex instead of racing into
// bbolt's internal WaitGroup. Tests that build VerkleTree structurally
// without going through NewVerkleTree and forgot to set
// persistentFlushMu are covered by a defensive nil-guard below that
// synthesizes a per-tree mutex on the fly (no-op for the single tree
// case since there's no sibling to contend with; production paths
// through NewVerkleTree/Copy() always have the shared pointer set).
func (t *VerkleTree) Flush() error {
	if t.persistentDB == nil {
		return nil
	}

	// R39-P1-05: lock persistentFlushMu FIRST. Defensive nil-guard: if a
	// test built the struct manually and never set persistentFlushMu (via
	// NewVerkleTree or Copy()), the tree has no sibling to serialize
	// against and a per-call mutex would suffice. We avoid a nil deref
	// by detecting this and installing a dedicated mutex on the spot.
	// This fallback does not protect against a manually-constructed pair
	// of trees that BOTH forgot to set persistentFlushMu — but assigning a
	// per-call fresh mutex to each can't help in that case anyway (the
	// two trees would get two different fresh mutexes); the audit's fix
	// path is "use NewVerkleTree / Copy()".
	flushMu := t.persistentFlushMu
	if flushMu == nil {
		flushMu = &sync.Mutex{}
	}
	flushMu.Lock()
	defer flushMu.Unlock()

	t.pendingBatchMu.Lock()
	defer t.pendingBatchMu.Unlock()

	// If pendingBatch was never initialized (manual struct construction),
	// there's nothing to flush — direct-Put errors are already captured.
	if t.pendingBatch == nil {
		err := t.pendingBatchErr
		t.pendingBatchErr = nil
		return err
	}

	// R35-P1-03 FIX: If an append error occurred, surface the error but
	// do NOT reset pendingBatch and do NOT clear pendingBatchErr.
	// The previous code called Reset() (discarding successfully-queued
	// entries) and cleared pendingBatchErr, causing the next Flush() to
	// see an empty batch and return silent success — while t.db (the
	// in-memory cache) was already updated with the new node versions.
	// This created permanent memory/disk divergence: after restart, t.db
	// is gone and disk is missing nodes, causing state root mismatch.
	//
	// P1-STATE-04 FIX (2026-07-30, R36): The R35-P1-03 fix made
	// pendingBatchErr permanently sticky — Flush() returned the error
	// without ever attempting to Write the retained batch, so the
	// "retained for retry" path was unreachable. A single transient
	// append error (or ErrBatchFull before the recordPendingWrite split
	// fix) would permanently disable Verkle tree persistence for the
	// process lifetime. Now: attempt to Write the retained batch. On
	// success, clear the sticky error and reset so normal operation
	// resumes (the in-memory cache t.db remains authoritative for reads;
	// any ops lost to a prior reset are recovered by RecoverConsistency
	// on next startup via the commit-pending marker). On failure, keep
	// the error sticky — genuine I/O failure, caller must investigate.
	if t.pendingBatchErr != nil {
		if writeErr := t.pendingBatch.Write(); writeErr != nil {
			return fmt.Errorf("verkle Flush: pending batch append error (write retry failed, batch retained): %w", t.pendingBatchErr)
		}
		// Write succeeded (or batch was empty no-op) — accumulated ops
		// are now durable. Clear the sticky error and reset for future
		// appends. The tree resumes normal persistence operation.
		t.pendingBatchErr = nil
		t.pendingBatch.Reset()
		return nil
	}

	// Atomic write of all accumulated node mutations.
	if err := t.pendingBatch.Write(); err != nil {
		// R33 TRIE-06 FIX: Do NOT reset pendingBatch on Write failure.
		// Preserving the queued mutations lets the next Flush() retry.
		// Resetting would lose them while t.db still holds the new
		// versions, causing permanent memory/disk divergence.
		return fmt.Errorf("verkle Flush: batch write failed (pending batch retained for retry): %w", err)
	}

	// Reset for the next operation.
	t.pendingBatch.Reset()
	return nil
}

// PruneOrphans removes orphaned nodes from the in-memory cache and
// persistent database. An orphaned node is one whose hash is no longer
// reachable from the current root via parent-child links. This includes:
//   - Old versions of a node that was overwritten (the old hash is still
//     in t.db but no parent points to it anymore)
//   - Subtrees removed by Delete (their hashes are still in t.db but
//     no InternalNode.Children[i] points to them)
//
// TRIE- (2026-07-20): Previously, Delete only nullified the child
// pointer (`n.Children[idx] = types.Hash{}`) but left the orphaned node's
// encoded bytes in t.db forever, causing unbounded memory growth on long-
// running chains. This is not a consensus issue (the orphaned bytes are
// simply ignored during traversal) but it is a resource leak.
//
// Algorithm: breadth-first traversal from rootNode, collecting all reachable
// node hashes into a set. Then iterate t.db and t.persistentDB and delete
// any entry whose key is not in the reachable set.
//
// This method is safe to call concurrently with reads (it acquires the
// tree write lock). It is NOT called automatically on every Delete because
// the full traversal is O(N) in tree size — callers should invoke it
// periodically (e.g., once per N blocks, or when t.db size exceeds a
// threshold) rather than on every operation.
//
// Returns the number of orphaned entries removed.
func (t *VerkleTree) PruneOrphans() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.rootNode == nil {
		// Tree is empty — all cached entries are orphans.
		t.dbMu.Lock()
		removed := len(t.db)
		t.db = make(map[string][]byte)
		t.dbMu.Unlock()
		if t.persistentDB != nil {
			iter := t.persistentDB.NewIterator([]byte(vnodePrefix), nil)
			var keysToDelete [][]byte
			for iter.Next() {
				keysToDelete = append(keysToDelete, append([]byte(nil), iter.Key()...))
			}
			iter.Release()
			for _, key := range keysToDelete {
				_ = t.persistentDB.Delete(key)
			}
		}
		return removed
	}

	// Collect reachable hashes via BFS from rootNode.
	reachable := make(map[string]struct{})
	t.collectReachableHashes(t.rootNode, reachable)

	// Prune in-memory cache.
	t.dbMu.Lock()
	removed := 0
	for k := range t.db {
		if _, ok := reachable[k]; !ok {
			delete(t.db, k)
			removed++
		}
	}
	t.dbMu.Unlock()

	// Prune persistent DB (best-effort; failures are logged but do not
	// abort the operation since the in-memory cache is the source of
	// truth for active state).
	if t.persistentDB != nil {
		iter := t.persistentDB.NewIterator([]byte(vnodePrefix), nil)
		var keysToDelete [][]byte
		for iter.Next() {
			key := iter.Key()
			// Persistent DB keys are prefixed with vnodePrefix.
			// Strip the prefix to get the hash bytes.
			if len(key) <= len(vnodePrefix) {
				continue
			}
			hashBytes := key[len(vnodePrefix):]
			if _, ok := reachable[string(hashBytes)]; !ok {
				keysToDelete = append(keysToDelete, append([]byte(nil), key...))
			}
		}
		iter.Release()
		for _, key := range keysToDelete {
			if err := t.persistentDB.Delete(key); err != nil {
				verkleLog.Warnf("PruneOrphans: failed to delete orphaned node %x: %v", key, err)
			} else {
				removed++
			}
		}
	}

	return removed
}

// collectReachableHashes performs a BFS from the given node, collecting
// the hash of every reachable node into the `reachable` set. The set is
// keyed by the string form of the node hash bytes, matching the key format
// used in t.db.
//
// TRIE- This traversal is bounded by the tree size and does not
// recurse into extension nodes' children beyond what is necessary to mark
// them reachable. Cycles are impossible in a well-formed Verkle tree
// (each level descends deeper), but we defensively track visited hashes
// to prevent infinite loops on corrupted data.
func (t *VerkleTree) collectReachableHashes(root TreeNode, reachable map[string]struct{}) {
	if root == nil {
		return
	}
	queue := []TreeNode{root}
	visited := make(map[string]struct{})
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if node == nil {
			continue
		}
		hash := node.Hash()
		hashKey := string(hash[:])
		if _, seen := visited[hashKey]; seen {
			continue
		}
		visited[hashKey] = struct{}{}
		reachable[hashKey] = struct{}{}

		switch n := node.(type) {
		case *InternalNode:
			for _, childHash := range n.Children {
				if childHash == (types.Hash{}) {
					continue
				}
				child := t.getNode(childHash)
				if child != nil {
					queue = append(queue, child)
				}
			}
		case *ExtensionNode:
			// R33 P2-08 FIX (2026-07-28): Check childHash before enqueuing.
			// Previously, collectReachableHashes only enqueued n.Child when
			// non-nil. But ExtensionNodes loaded from DB may have n.Child == nil
			// with only n.childHash populated (lazy-load reference). Skipping
			// such nodes caused their entire subtree to be marked unreachable
			// during PruneOrphans, leading to orphan-collection of live nodes
			// and subsequent tree corruption (Get/walk failures).
			//
			// Now we prioritize n.childHash: if n.Child is nil but childHash is
			// non-zero, we load the child from DB via getNode before enqueuing.
			// This mirrors the lazy-load pattern already used in delete() and
			// insert() for ExtensionNode traversal.
			if n.Child != nil {
				queue = append(queue, n.Child)
			} else if n.childHash != (types.Hash{}) {
				child := t.getNode(n.childHash)
				if child != nil {
					queue = append(queue, child)
				}
			}
		case *LeafNode:
			// Leaf nodes have no children — nothing to enqueue.
		}
	}
}

// NodeCount returns the number of nodes currently cached in memory.
// Useful for monitoring memory usage and deciding when to call PruneOrphans.
//
// TRIE- (2026-07-20): Added to support operational monitoring of
// the orphan-collection mechanism.
func (t *VerkleTree) NodeCount() int {
	t.dbMu.RLock()
	defer t.dbMu.RUnlock()
	return len(t.db)
}

// getNode retrieves a node from the in-memory cache, falling back to the
// persistent database on miss.
// AUDIT (2026) DATA-02: Previously, getNode only checked the in-memory
// t.db map and returned nil on cache miss. This meant that if the in-memory
// cache was evicted or incomplete (e.g., after a Copy() or when the tree
// was too large to load entirely), nodes that exist on disk would be
// treated as non-existent — causing Get/Put/Delete to silently fail,
// tree corruption, and state root divergence across nodes.
// TRIE- decodeNode now returns (node, err); on decode failure of
// cached bytes, fall through to persistent DB instead of returning nil.
func (t *VerkleTree) getNode(hash types.Hash) TreeNode {
	// R33 P2-07 FIX (2026-07-28): Zero hash is the canonical "empty slot"
	// marker in InternalNode.Children and ExtensionNode.childHash. Returning
	// nil for a zero hash is correct and silent — no log needed.
	if hash == (types.Hash{}) {
		return nil
	}
	t.dbMu.RLock()
	data, ok := t.db[string(hash[:])]
	t.dbMu.RUnlock()
	if ok {
		if node, err := decodeNode(data); err == nil {
			return node
		}
		// Corrupted cache entry — fall through to persistent DB.
	}

	// AUDIT (2026) DATA-02: Fall back to persistent database.
	if t.persistentDB != nil {
		key := append([]byte(vnodePrefix), hash[:]...)
		persistedData, err := t.persistentDB.Get(key)
		if err == nil && len(persistedData) > 0 {
			// Populate the in-memory cache for future lookups.
			nodeData := make([]byte, len(persistedData))
			copy(nodeData, persistedData)
			if node, derr := decodeNode(nodeData); derr == nil {
				t.dbMu.Lock()
				t.db[string(hash[:])] = nodeData
				t.dbMu.Unlock()
				return node
			}
		}
	}

	// R33 P2-07 FIX (2026-07-28): A non-zero hash that resolves to no node
	// in cache or DB indicates tree corruption — a child reference points to
	// a non-existent node. Previously getNode silently returned nil, and
	// callers treated nil as "empty slot", potentially overwriting live
	// subtrees on subsequent inserts or losing data on deletes. Now we log
	// a warning so operators can detect corruption before it cascades.
	// Callers must still handle nil defensively (and most do), but the log
	// makes the corruption visible instead of silent.
	verkleLog.Warn("getNode: non-zero hash not found in cache or DB (tree corruption)",
		map[string]any{"hash": hash.String()})
	return nil
}

// decodeNode decodes a node from bytes.
// TRIE- Accepts both the new format (VerkleEncodingMagic prefix)
// and the legacy format (raw NodeType byte) for backward compatibility
// with already-persisted data. Returns (nil, ErrInvalidNode) for unknown
// node types instead of silently returning nil.
func decodeNode(data []byte) (TreeNode, error) {
	if len(data) == 0 {
		return nil, ErrInvalidNode
	}
	var payload []byte
	if data[0] == VerkleEncodingMagic {
		// New format: [magic][NodeType][...rest].
		if len(data) < 2 {
			return nil, ErrInvalidNode
		}
		// Strip the magic byte so Decode*Node sees its expected layout
		// (NodeType at offset 0).
		payload = data[1:]
	} else {
		// Legacy format: [NodeType][...rest].
		payload = data
	}
	switch payload[0] {
	case NodeTypeLeaf:
		return DecodeLeafNode(payload)
	case NodeTypeInternal:
		return DecodeInternalNode(payload)
	case NodeTypeExtension:
		return DecodeExtensionNode(payload)
	}
	return nil, ErrInvalidNode
}

// encodeNodeWithMagic prepends VerkleEncodingMagic to the node's Encode()
// output. Used by the persistence layer (storeNode, recomputeRoot) so that
// all on-disk and in-cache bytes carry a version marker.
// TRIE-
func encodeNodeWithMagic(node TreeNode) []byte {
	if node == nil {
		return nil
	}
	raw := node.Encode()
	if len(raw) == 0 {
		return nil
	}
	out := make([]byte, 1+len(raw))
	out[0] = VerkleEncodingMagic
	copy(out[1:], raw)
	return out
}

// recomputeRoot recalculates the root hash
// R6-DB-1 FIX: persists root node to database for restart recovery
// TRIE- persist with VerkleEncodingMagic prefix.
//
// STORAGE-P0-01/03 FIX (R31, 2026-07-27): appends root write to
// pendingBatch instead of issuing a direct Put. Combined with storeNode
// batching, this ensures the root and all its descendants are committed
// atomically by Flush() — eliminating the prior window where a crash
// could leave the on-disk root pointing at non-existent children.
func (t *VerkleTree) recomputeRoot() {
	if t.rootNode == nil {
		t.root = types.Hash{}
		return
	}
	t.root = t.rootNode.Hash()

	if t.persistentDB != nil {
		rootKey := append([]byte(vnodePrefix), []byte("_root_")...)
		rootData := encodeNodeWithMagic(t.rootNode)
		if len(rootData) == 0 {
			return
		}
		// STORAGE-P0-01/03 FIX: route through pendingBatch so the root
		// write is atomic with all child node writes from this operation.
		t.recordPendingWrite(rootKey, rootData, []byte("_root_"))
	}
}

// Copy creates a deep copy of the Verkle tree
func (t *VerkleTree) Copy() *VerkleTree {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	t.dbMu.RLock()
	newDB := make(map[string][]byte)
	for k, v := range t.db {
		newDB[k] = append([]byte(nil), v...)
	}
	t.dbMu.RUnlock()

	newTree := &VerkleTree{
		root:         t.root,
		rootNode:     t.copyNode(t.rootNode),
		dbMu:         &sync.RWMutex{},
		db:           newDB,
		maxDepth:     t.maxDepth,
		persistentDB: t.persistentDB,
		// R39-P1-05 (2026-08-02) FIX: propagate the original's
		// persistentFlushMu POINTER so the copy and the original share the
		// SAME serializing mutex. This is the audit's "share the persistentDB but
		// serialize Flush with a mutex" recommendation — every tree derived from a
		// single persistentDB forms a serialization group via this shared
		// naked pointer, and Flush() formations on different trees cannot
		// race the underlying bbolt instance. The pointer is non-nil here
		// because Copy() only reaches this branch when
		// t.persistentDB != nil (the `if t.persistentDB != nil` block below),
		// and NewVerkleTree guarantees persistentFlushMu is set whenever
		// persistentDB is set — so for a Copy() of a tree constructed via
		// NewVerkleTree the assertion always holds. Tests that build a
		// VerkleTree struct manually (assigning persistentDB without going
		// through NewVerkleTree) MUST set persistentFlushMu themselves; if
		// they don't, Flush() will synthesize a per-call mutex via nil-guard
		// (see Flush) so production hardening is preserved against that
		// defensive default.
		persistentFlushMu: t.persistentFlushMu,
	}
	// STORAGE-P0-01 FIX (R31, 2026-07-27): the copy gets its own fresh
	// pendingBatch so writes on the copy don't bleed into the original's
	// batch (and vice-versa). Each tree must be Flush()'d independently.
	if t.persistentDB != nil {
		newTree.pendingBatch = t.persistentDB.NewBatch()
	}
	return newTree
}

// copyNode recursively copies a node.
// FIX: ExtensionNode may have Child==nil but childHash!=empty (e.g. after
// DecodeExtensionNode deserialization). In that case we must resolve the child
// from the in-memory DB before copying, otherwise NewExtensionNode would use
// an empty childHash and produce a wrong hash, corrupting the copied trie's root.
func (t *VerkleTree) copyNode(node TreeNode) TreeNode {
	if node == nil {
		return nil
	}

	switch n := node.(type) {
	case *LeafNode:
		leaf := NewLeafNode(n.Key, n.Value)
		// AUDIT (2026) R3-DATA-01: Copy suffix values so same-stem
		// entries are preserved during tree Copy().
		if len(n.SuffixValues) > 0 {
			leaf.SuffixValues = make(map[byte][]byte, len(n.SuffixValues))
			for k, v := range n.SuffixValues {
				leaf.SuffixValues[k] = append([]byte(nil), v...)
			}
			leaf.recomputeHash()
		}
		return leaf
	case *InternalNode:
		newInternal := NewInternalNode()
		for i := 0; i < BranchingFactor; i++ {
			newInternal.Children[i] = n.Children[i]
		}
		newInternal.hash = n.hash
		return newInternal
	case *ExtensionNode:
		child := n.Child
		if child == nil && n.childHash != (types.Hash{}) {
			child = t.getNode(n.childHash)
		}
		var childCopy TreeNode
		if child != nil {
			childCopy = t.copyNode(child)
		}
		ext := NewExtensionNode(n.Stem, n.StemLen, childCopy)
		return ext
	}
	return nil
}

// Prove generates a proof for a key.
//
// TRIE-/002 (2026-07-20): Rewritten to populate the new
// ExtensionStems and ExclusionEvidence fields, and to fix a duplicate
// root hash bug in the previous implementation (Path was initialized
// with rootNode.Hash() and proveWalk appended the root hash again on
// first visit, producing Path = [root.Hash(), root.Hash(), ...]).
// The new implementation initializes Path as empty and lets
// proveWalk append each visited node's hash, producing
// Path = [root.Hash(), ..., leaf.Hash()] with exactly len(Siblings)+1
// entries.
func (t *VerkleTree) Prove(key []byte) (*VerkleProof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	proof := &VerkleProof{
		Key:            key,
		Path:           []types.Hash{},
		Siblings:       [][]SiblingWithIdx{},
		ExtensionStems: []ExtensionLevelData{},
	}

	if t.rootNode == nil {
		// Empty-tree exclusion: every key is trivially absent.
		proof.IsExclusion = true
		return proof, nil
	}

	stem := keyToStem(key)
	path := []types.Hash{}
	siblings := [][]SiblingWithIdx{}
	extStems := []ExtensionLevelData{}
	var evidence *ExclusionEvidence

	// Walk the tree collecting path, siblings, extension stems, and
	// (for exclusion) fork-point evidence.
	found := t.proveWalk(t.rootNode, stem, key, 0, &path, &siblings, &extStems, &evidence)
	if found != nil {
		if leaf, ok := found.(*LeafNode); ok {
			// AUDIT (2026) R3-DATA-01: Return the correct value for
			// suffix-indexed entries, not just the primary Value.
			if bytes.Equal(leaf.Key, key) {
				proof.Value = leaf.Value
			} else if leaf.SuffixValues != nil {
				suffix := keyToSuffix(key)
				proof.Value = leaf.SuffixValues[suffix]
			} else {
				proof.Value = leaf.Value
			}
			proof.IsExclusion = false
			proof.StemHash = leaf.hash
			// TRIE- append leaf hash as the final Path entry.
			path = append(path, leaf.Hash())
			// TRIE- carry the full encoded leaf so the verifier
			// can recompute leaf.Hash() (which incorporates SuffixValues)
			// and verify the queried suffix is genuinely present. Without
			// this, an attacker could forge a proof for a suffix that
			// doesn't exist in the leaf — HashLeaf(Key, Value) would
			// match Path[last] even though the leaf has no such suffix.
			proof.InclusionLeaf = append([]byte(nil), leaf.Encode()...)
		}
	} else {
		proof.IsExclusion = true
		// TRIE- carry fork-point evidence for verifier.
		proof.ExclusionEvidence = evidence
	}

	proof.Path = path
	proof.Siblings = siblings
	proof.ExtensionStems = extStems

	return proof, nil
}

// proveWalk traverses the tree collecting proof data.
//
// TRIE-/002 (2026-07-20): Rewritten to:
//   - Fix the duplicate root hash bug (Path is no longer pre-populated
//     in Prove; this function appends each visited node's hash exactly
//     once).
//   - Populate ExtensionStems parallel to Siblings (one entry per level,
//     with StemLen > 0 for Extension levels).
//   - Set ExclusionEvidence when the key is absent, indicating WHY it
//     is absent (empty slot, extension stem mismatch, or leaf key
//     mismatch). The previous implementation returned nil with no
//     evidence, leaving the verifier unable to distinguish "absent
//     because empty" from "absent because occupied by a different key".
//   - Check Extension stem prefix match BEFORE recursing into the
//     child (the previous implementation always recursed, which could
//     traverse the wrong path and produce incorrect proofs).
func (t *VerkleTree) proveWalk(node TreeNode, stem [StemSize]byte, key []byte, depth int, path *[]types.Hash, siblings *[][]SiblingWithIdx, extStems *[]ExtensionLevelData, evidence **ExclusionEvidence) TreeNode {
	if node == nil || depth >= StemSize {
		return node
	}
	// R32-P2-06: Hard backstop — see walk() docs for rationale.
	if depth >= maxVerkleRecursionDepth {
		verkleLog.Warn("verkle proveWalk: hit hard recursion depth limit (tree may be corrupted)",
			map[string]any{"depth": depth, "limit": maxVerkleRecursionDepth})
		return nil
	}

	switch n := node.(type) {
	case *LeafNode:
		if bytes.Equal(n.Key, key) {
			return n
		}
		// AUDIT (2026) R3-DATA-01: Check suffix-indexed values.
		if n.SuffixValues != nil {
			suffix := keyToSuffix(key)
			if _, exists := n.SuffixValues[suffix]; exists {
				return n
			}
		}
		// TRIE- Leaf key mismatch — fork point is this leaf.
		// Append leaf hash to Path and set ExclusionEvidence with the
		// full encoded leaf (so the verifier can recompute leaf.Hash()
		// and verify LeafKey != query key cryptographically).
		*path = append(*path, n.Hash())
		*evidence = &ExclusionEvidence{
			Type:        ExclusionTypeLeafMismatch,
			EncodedLeaf: append([]byte(nil), n.Encode()...),
		}
		return nil

	case *InternalNode:
		if depth >= StemSize {
			return nil
		}
		idx := int(stem[depth]) // #nosec G602 -- slice bounds verified by surrounding logic

		// Collect siblings with their indices for proper verification.
		levelSiblings := []SiblingWithIdx{}
		for i := 0; i < BranchingFactor; i++ {
			if i != idx && n.Children[i] != (types.Hash{}) {
				levelSiblings = append(levelSiblings, SiblingWithIdx{
					Idx:  i,
					Hash: n.Children[i],
				})
			}
		}
		*siblings = append(*siblings, levelSiblings)
		*path = append(*path, n.Hash())
		// TRIE- mark this as an Internal level (StemLen == 0).
		*extStems = append(*extStems, ExtensionLevelData{})

		childHash := n.Children[idx]
		if childHash == (types.Hash{}) {
			// TRIE- Empty slot — fork point is the missing child.
			// Append zero hash to Path so the verifier can recompute the
			// parent (with child = zero) and verify it matches Path[len-2].
			*path = append(*path, types.Hash{})
			*evidence = &ExclusionEvidence{Type: ExclusionTypeEmptySlot}
			return nil
		}
		childNode := t.getNode(childHash)
		if childNode == nil {
			// Hash is non-zero but node can't be retrieved (corrupted
			// DB or partial load). Without the fork-point node we
			// cannot construct valid ExclusionEvidence — return nil
			// and let the verifier fail-closed (ExclusionEvidence == nil).
			return nil
		}
		return t.proveWalk(childNode, stem, key, depth+1, path, siblings, extStems, evidence)

	case *ExtensionNode:
		// R32-P2-06: Reject invalid StemLen before recursing. Same
		// rationale as walk()/insert()/delete(). Without this guard,
		// n.Stem[:n.StemLen] with StemLen == 0 is an empty slice, and
		// HasPrefix(stem[depth:], emptySlice) is ALWAYS true — the
		// prover would recurse into the child without advancing depth,
		// looping until the hard backstop fires.
		if n.StemLen <= 0 || n.StemLen > StemSize {
			verkleLog.Warn("verkle proveWalk: ExtensionNode has invalid StemLen (tree corrupted)",
				map[string]any{"stemLen": n.StemLen})
			return nil
		}
		// TRIE- Always append the extension's hash to Path
		// (it's on the path whether we recurse into it or stop here
		// for stem mismatch).
		*path = append(*path, n.Hash())

		// TRIE-/002: Check stem prefix match BEFORE recursing.
		// The previous implementation always recursed, which produced
		// incorrect proofs when the stem didn't match (the prover
		// traversed the wrong path).
		if !bytes.HasPrefix(stem[depth:], n.Stem[:n.StemLen]) {
			// Stem doesn't match — fork point is this extension.
			// Set ExclusionEvidence with the extension's Stem and child
			// hash so the verifier can recompute HashExtension(Stem, Child)
			// and verify Stem does NOT prefix-match the query key's stem.
			// Do NOT append to Siblings or ExtensionStems — this is the
			// fork point, not a traversed level.
			childHash := n.childHash
			if n.Child != nil {
				childHash = n.Child.Hash()
			}
			*evidence = &ExclusionEvidence{
				Type:             ExclusionTypeExtensionMismatch,
				ExtensionStem:    n.Stem,
				ExtensionStemLen: n.StemLen,
				ExtensionChild:   childHash,
			}
			return nil
		}

		// Stem matches — append empty sibs and stem data, then recurse.
		*siblings = append(*siblings, []SiblingWithIdx{}) // Extension has no direct siblings at this level
		*extStems = append(*extStems, ExtensionLevelData{Stem: n.Stem, StemLen: n.StemLen})

		child := n.Child
		if child == nil && n.childHash != (types.Hash{}) {
			child = t.getNode(n.childHash)
		}
		if child != nil {
			return t.proveWalk(child, stem, key, depth+n.StemLen, path, siblings, extStems, evidence)
		}
		return nil
	}

	return nil
}

// VerifyProof verifies a Verkle proof against a root
func VerifyProof(root types.Hash, proof *VerkleProof) bool {
	if proof == nil {
		return false
	}
	return proof.Verify(root)
}

// GetDB returns the underlying database (for testing/debugging)
func (t *VerkleTree) GetDB() map[string][]byte {
	t.dbMu.RLock()
	defer t.dbMu.RUnlock()
	result := make(map[string][]byte, len(t.db))
	for k, v := range t.db {
		copied := make([]byte, len(v))
		copy(copied, v)
		result[k] = copied
	}
	return result
}

// SetHasher sets the node hasher (for future Pedersen commitment migration)
func SetHasher(hasher NodeHasher) {
	defaultHasher = hasher
}

// GetHasher returns the current node hasher
func GetHasher() NodeHasher {
	return defaultHasher
}
