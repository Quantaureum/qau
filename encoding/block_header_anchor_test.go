// Quantaureum Node source, version 1.0.0.
package encoding

// Round-trip coverage for the optional QTD group-key anchor field (v1
// observer channel): present bytes must survive marshal/unmarshal and the
// field must stay absent (and skipped by older readers) when unset.

import (
	"testing"
)

func TestBlockHeaderQTDGroupKeyRoundTrip(t *testing.T) {
	header := &BlockHeader{
		Version:   1,
		Height:    42,
		Slot:      640,
		Epoch:     20,
		ChainID:   1333,
		Timestamp: 1759999999,
	}
	key := make([]byte, 1952)
	for i := range key {
		key[i] = byte(i)
	}
	header.QTDGroupKey = key
	proof := make([]byte, 3293)
	for i := range proof {
		proof[i] = byte(255 - i%256)
	}
	header.QTDGroupKeyProof = proof

	encoded, err := MarshalBlockHeader(header)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded, err := UnmarshalBlockHeader(encoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded.QTDGroupKey) != len(key) {
		t.Fatalf("group key length mismatch: %d != %d", len(decoded.QTDGroupKey), len(key))
	}
	for i := range key {
		if decoded.QTDGroupKey[i] != key[i] {
			t.Fatalf("group key byte %d mismatch", i)
		}
	}
	if len(decoded.QTDGroupKeyProof) != len(proof) {
		t.Fatalf("proof length mismatch: %d != %d", len(decoded.QTDGroupKeyProof), len(proof))
	}
	for i := range proof {
		if decoded.QTDGroupKeyProof[i] != proof[i] {
			t.Fatalf("proof byte %d mismatch", i)
		}
	}

	// Unset: the field must not appear at all.
	header.QTDGroupKey = nil
	header.QTDGroupKeyProof = nil
	encoded, err = MarshalBlockHeader(header)
	if err != nil {
		t.Fatalf("marshal without key: %v", err)
	}
	decoded, err = UnmarshalBlockHeader(encoded)
	if err != nil {
		t.Fatalf("unmarshal without key: %v", err)
	}
	if len(decoded.QTDGroupKey) != 0 {
		t.Fatalf("unset key decoded with %d bytes", len(decoded.QTDGroupKey))
	}
	if len(decoded.QTDGroupKeyProof) != 0 {
		t.Fatalf("unset proof decoded with %d bytes", len(decoded.QTDGroupKeyProof))
	}
}
