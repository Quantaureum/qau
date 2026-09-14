// Quantaureum Node source, version 1.0.0.
package enode

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestNewRecord(t *testing.T) {
	r := NewRecord()
	if r == nil {
		t.Fatal("NewRecord returned nil")
	}
	if r.Seq() != 0 {
		t.Errorf("initial Seq = %d, want 0", r.Seq())
	}
}

func TestRecordSetGet(t *testing.T) {
	r := NewRecord()

	r.Set("ip", []byte{1, 2, 3, 4})

	val, ok := r.Get("ip")
	if !ok {
		t.Error("Get(ip) should return ok=true")
	}
	if !bytes.Equal(val, []byte{1, 2, 3, 4}) {
		t.Errorf("Get(ip) = %v, want [1 2 3 4]", val)
	}
}

func TestRecordGetMissing(t *testing.T) {
	r := NewRecord()

	_, ok := r.Get("missing")
	if ok {
		t.Error("Get(missing) should return ok=false")
	}
}

func TestRecordSetOverwrite(t *testing.T) {
	r := NewRecord()

	r.Set("ip", []byte{1, 2, 3, 4})
	r.Set("ip", []byte{5, 6, 7, 8})

	val, ok := r.Get("ip")
	if !ok {
		t.Error("Get(ip) should return ok=true")
	}
	if !bytes.Equal(val, []byte{5, 6, 7, 8}) {
		t.Errorf("Get(ip) = %v, want [5 6 7 8]", val)
	}
}

func TestRecordSeq(t *testing.T) {
	r := NewRecord()

	r.SetSeq(42)
	if r.Seq() != 42 {
		t.Errorf("Seq = %d, want 42", r.Seq())
	}
}

func TestRecordSignature(t *testing.T) {
	r := NewRecord()

	if r.Signature() != nil {
		t.Error("initial Signature should be nil")
	}

	r.SetSignature([]byte("test-sig"))
	if !bytes.Equal(r.Signature(), []byte("test-sig")) {
		t.Error("Signature mismatch")
	}
}

func TestRecordSetIP(t *testing.T) {
	r := NewRecord()

	ip := net.ParseIP("198.51.100.10")
	r.SetIP(ip)

	retrieved := r.IP()
	if retrieved == nil {
		t.Fatal("IP should not be nil")
	}
	if !retrieved.Equal(ip.To4()) {
		t.Errorf("IP = %v, want %v", retrieved, ip)
	}
}

func TestRecordSetIP6(t *testing.T) {
	r := NewRecord()

	ip := net.ParseIP("::1")
	r.SetIP(ip)

	retrieved := r.IP6()
	if retrieved == nil {
		t.Error("IP6 should not be nil")
	}
}

func TestRecordSetTCP(t *testing.T) {
	r := NewRecord()

	r.SetTCP(9000)
	if r.TCP() != 9000 {
		t.Errorf("TCP = %d, want 9000", r.TCP())
	}
}

func TestRecordSetUDP(t *testing.T) {
	r := NewRecord()

	r.SetUDP(9001)
	if r.UDP() != 9001 {
		t.Errorf("UDP = %d, want 9001", r.UDP())
	}
}

func TestRecordSetID(t *testing.T) {
	r := NewRecord()

	r.SetID("v4")
	if r.ID() != "v4" {
		t.Errorf("ID = %q, want %q", r.ID(), "v4")
	}
}

func TestRecordSetPublicKey(t *testing.T) {
	r := NewRecord()

	pubkey := make([]byte, 1952) // Dilithium3 public key size
	for i := range pubkey {
		pubkey[i] = byte(i % 256)
	}
	r.SetPublicKey(pubkey)

	retrieved := r.PublicKey()
	if !bytes.Equal(retrieved, pubkey) {
		t.Error("PublicKey mismatch")
	}
}

func TestRecordSetGetPoWNonce(t *testing.T) {
	r := NewRecord()

	r.SetPoWNonce(12345)
	nonce, ok := r.GetPoWNonce()
	if !ok {
		t.Error("GetPoWNonce should return ok=true")
	}
	if nonce != 12345 {
		t.Errorf("PoWNonce = %d, want 12345", nonce)
	}
}

func TestRecordGetPoWNonceMissing(t *testing.T) {
	r := NewRecord()

	_, ok := r.GetPoWNonce()
	if ok {
		t.Error("GetPoWNonce should return ok=false when not set")
	}
}

func TestRecordPairs(t *testing.T) {
	r := NewRecord()
	r.Set("key1", []byte("val1"))
	r.Set("key2", []byte("val2"))

	pairs := r.Pairs()
	if len(pairs) != 2 {
		t.Errorf("len(Pairs) = %d, want 2", len(pairs))
	}
}

func TestRecordSortedPairs(t *testing.T) {
	r := NewRecord()
	r.Set("zzz", []byte("last"))
	r.Set("aaa", []byte("first"))
	r.Set("mmm", []byte("middle"))

	pairs := r.Pairs()
	if pairs[0].key != "aaa" {
		t.Errorf("first pair key = %q, want %q", pairs[0].key, "aaa")
	}
	if pairs[1].key != "mmm" {
		t.Errorf("second pair key = %q, want %q", pairs[1].key, "mmm")
	}
	if pairs[2].key != "zzz" {
		t.Errorf("third pair key = %q, want %q", pairs[2].key, "zzz")
	}
}

func TestRecordEncodeDecode(t *testing.T) {
	r := NewRecord()
	r.SetSeq(1)
	r.SetSignature([]byte("test-signature-data"))
	r.Set("ip", []byte{1, 2, 3, 4})
	r.SetTCP(9000)

	encoded, err := r.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded := NewRecord()
	err = decoded.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Seq() != r.Seq() {
		t.Errorf("Seq = %d, want %d", decoded.Seq(), r.Seq())
	}
	if !bytes.Equal(decoded.Signature(), r.Signature()) {
		t.Error("Signature mismatch")
	}
	if decoded.TCP() != 9000 {
		t.Errorf("TCP = %d, want 9000", decoded.TCP())
	}
}

func TestDecodeRecord(t *testing.T) {
	r := NewRecord()
	r.SetSignature([]byte("sig"))
	r.Set("key", []byte("value"))

	encoded, _ := r.Encode()
	decoded, err := DecodeRecord(encoded)
	if err != nil {
		t.Fatalf("DecodeRecord failed: %v", err)
	}
	if decoded.Seq() != r.Seq() {
		t.Error("Seq mismatch")
	}
}

func TestRecordClone(t *testing.T) {
	r := NewRecord()
	r.SetSeq(42)
	r.SetSignature([]byte("sig"))
	r.Set("ip", []byte{1, 2, 3, 4})

	clone := r.Clone()
	if !r.Equal(clone) {
		t.Error("clone should be equal to original")
	}

	// Modify clone should not affect original
	clone.SetSeq(99)
	if r.Seq() == 99 {
		t.Error("modifying clone should not affect original")
	}
}

func TestRecordEqual(t *testing.T) {
	r1 := NewRecord()
	r1.SetSeq(1)
	r1.SetSignature([]byte("sig"))
	r1.Set("ip", []byte{1, 2, 3, 4})

	r2 := NewRecord()
	r2.SetSeq(1)
	r2.SetSignature([]byte("sig"))
	r2.Set("ip", []byte{1, 2, 3, 4})

	if !r1.Equal(r2) {
		t.Error("identical records should be equal")
	}

	r3 := NewRecord()
	r3.SetSeq(2)
	if r1.Equal(r3) {
		t.Error("records with different seq should not be equal")
	}
}

func TestRecordEqualNil(t *testing.T) {
	r := NewRecord()
	if r.Equal(nil) {
		t.Error("non-nil record should not equal nil")
	}

	var nilRecord *Record
	if nilRecord.Equal(r) {
		t.Error("nil record should not equal non-nil")
	}
}

func TestRecordEncodeTooLarge(t *testing.T) {
	r := NewRecord()
	// Set a signature that's too large
	r.SetSignature(make([]byte, MaxRecordSize))

	_, err := r.Encode()
	if err != ErrRecordTooLarge {
		t.Errorf("expected ErrRecordTooLarge, got %v", err)
	}
}

func TestRecordDecodeInvalid(t *testing.T) {
	r := NewRecord()
	err := r.Decode([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for invalid data")
	}
}

func TestRecordDecodeTooLarge(t *testing.T) {
	r := NewRecord()
	err := r.Decode(make([]byte, MaxRecordSize+1))
	if err != ErrRecordTooLarge {
		t.Errorf("expected ErrRecordTooLarge, got %v", err)
	}
}

func TestEncodeSignedData(t *testing.T) {
	r := NewRecord()
	r.SetSeq(1)
	r.Set("ip", []byte{1, 2, 3, 4})

	data := r.EncodeSignedData()
	if len(data) == 0 {
		t.Error("EncodeSignedData should not return empty data")
	}

	// Verify it starts with the sequence number
	seq := binary.BigEndian.Uint64(data[:8])
	if seq != 1 {
		t.Errorf("seq in signed data = %d, want 1", seq)
	}
}

func TestFromNode(t *testing.T) {
	id, _ := GenerateID()
	node := NewNode(id, net.ParseIP("198.51.100.10"), 9000, 9001)
	node.SetSeq(5)

	r := FromNode(node)
	if r == nil {
		t.Fatal("FromNode returned nil")
	}
	if r.Seq() != 5 {
		t.Errorf("Seq = %d, want 5", r.Seq())
	}
	if r.TCP() != 9000 {
		t.Errorf("TCP = %d, want 9000", r.TCP())
	}
	if r.UDP() != 9001 {
		t.Errorf("UDP = %d, want 9001", r.UDP())
	}
	if r.ID() != "v4" {
		t.Errorf("ID = %q, want %q", r.ID(), "v4")
	}
}

func TestRecordVerifySignatureEmpty(t *testing.T) {
	r := NewRecord()
	err := r.VerifySignature()
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature for empty signature, got %v", err)
	}
}

func TestRecordVerifySignatureNoPubkey(t *testing.T) {
	r := NewRecord()
	r.SetSignature([]byte("fake-sig"))
	err := r.VerifySignature()
	if err != ErrMissingKey {
		t.Errorf("expected ErrMissingKey for missing pubkey, got %v", err)
	}
}
