// Quantaureum Node source, version 1.0.0.
package trie

import (
	"encoding/binary"
	"math"
	"testing"
)

// R5-08 (2026-10-21 fifth-round audit): DecodeExtensionNode accepted StemLen == 0
// even though NewExtensionNode refuses it (R32-P2-06: a zero-length stem makes
// the traversal descend without consuming any stem). The decoder now enforces
// the constructor's invariant, so a node read back from disk can never be one
// the tree itself would have refused to build.

func r5EncodeExtension(stemLen uint32) []byte {
	buf := make([]byte, 1+4+StemSize+32)
	buf[0] = NodeTypeExtension
	binary.BigEndian.PutUint32(buf[1:5], stemLen)
	for i := range StemSize {
		buf[5+i] = byte(i + 1)
	}
	return buf
}

func TestR5_08_DecodeExtensionNodeRejectsZeroStemLen(t *testing.T) {
	for _, stemLen := range []uint32{0, 1 << 31, math.MaxUint32} {
		node, err := DecodeExtensionNode(r5EncodeExtension(stemLen))
		if err != ErrInvalidNode || node != nil {
			t.Fatalf("StemLen %d: got (node=%v, err=%v), want (nil, ErrInvalidNode)", stemLen, node, err)
		}
	}
}

func TestR5_08_DecodeExtensionNodeRoundTripsValidStemLen(t *testing.T) {
	// Positive control for every StemLen the constructor accepts, including the
	// two boundaries: the wire format must not start rejecting honest data.
	for stemLen := 1; stemLen <= StemSize; stemLen++ {
		var stem [StemSize]byte
		for i := range StemSize {
			stem[i] = byte(i + 1)
		}
		child := NewLeafNode([]byte{byte(stemLen)}, []byte("v"))
		original := NewExtensionNode(stem, stemLen, child)
		if original == nil {
			t.Fatalf("NewExtensionNode rejected the legitimate StemLen %d", stemLen)
		}

		decoded, err := DecodeExtensionNode(original.Encode())
		if err != nil {
			t.Fatalf("StemLen %d: DecodeExtensionNode: %v", stemLen, err)
		}
		if decoded == nil {
			t.Fatalf("StemLen %d: decoded nil without an error", stemLen)
		}
		if decoded.StemLen != stemLen {
			t.Fatalf("StemLen round-trip = %d, want %d", decoded.StemLen, stemLen)
		}
		if decoded.Hash() != original.Hash() {
			t.Fatalf("StemLen %d: decoded hash %s != original %s", stemLen, decoded.Hash(), original.Hash())
		}
	}
}
