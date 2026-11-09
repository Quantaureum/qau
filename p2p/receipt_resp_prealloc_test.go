// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"encoding/binary"
	"runtime"
	"testing"
)

// AUDIT run-3 qau.p2p/receipt-resp-prealloc-amplification regression tests.
//
// DecodeReceiptResponse must not size slice preallocations from wire-declared
// counts alone. A 48-byte frame that declares 100000 receipts previously
// allocated a 100000-slot [][]byte header (~2.4MB) before the first per-item
// length check rejected the frame.

func measureAlloc(t *testing.T, fn func()) uint64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestDecodeReceiptResponse_RejectsInflatedSetCount(t *testing.T) {
	// Header only: RequestID(8) + SetCount(4). Every declared set would need
	// at least BlockHash(32) + RCount(4) bytes, none are present.
	data := make([]byte, 12)
	binary.BigEndian.PutUint64(data[0:8], 1)
	binary.BigEndian.PutUint32(data[8:12], MaxReceiptRequestCount)

	var err error
	alloc := measureAlloc(t, func() {
		_, err = DecodeReceiptResponse(data)
	})
	if err == nil {
		t.Fatal("expected rejection of set count exceeding remaining payload")
	}
	if alloc > 256*1024 {
		t.Fatalf("inflated set count allocated %d bytes before validation", alloc)
	}
}

func TestDecodeReceiptResponse_RejectsInflatedReceiptCount(t *testing.T) {
	// 48-byte frame declaring 100000 receipts in one set. Each receipt needs
	// at least RLen(4) + 1 payload byte, so the frame is ~49MB short.
	data := make([]byte, 48)
	binary.BigEndian.PutUint64(data[0:8], 1)
	binary.BigEndian.PutUint32(data[8:12], 1) // setCount = 1
	// data[12:44] = BlockHash (zero)
	binary.BigEndian.PutUint32(data[44:48], 100000) // rCount

	var err error
	alloc := measureAlloc(t, func() {
		_, err = DecodeReceiptResponse(data)
	})
	if err == nil {
		t.Fatal("expected rejection of receipt count exceeding remaining payload")
	}
	if alloc > 256*1024 {
		t.Fatalf("inflated receipt count allocated %d bytes before validation", alloc)
	}
}

func TestDecodeReceiptResponse_ValidRoundTrip(t *testing.T) {
	resp := &ReceiptResponse{
		RequestID: 7,
		Sets: []ReceiptSet{
			{BlockHash: [32]byte{1}, Receipts: [][]byte{{0xaa, 0xbb}, {0xcc}}},
			{BlockHash: [32]byte{2}, Receipts: [][]byte{}},
		},
	}
	decoded, err := DecodeReceiptResponse(EncodeReceiptResponse(resp))
	if err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	if decoded.RequestID != resp.RequestID || len(decoded.Sets) != len(resp.Sets) {
		t.Fatalf("round trip mismatch: %+v", decoded)
	}
	if len(decoded.Sets[0].Receipts) != 2 || len(decoded.Sets[1].Receipts) != 0 {
		t.Fatalf("receipt set shape mismatch: %+v", decoded.Sets)
	}
}
