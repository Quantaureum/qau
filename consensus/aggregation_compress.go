// Quantaureum Node source, version 1.0.0.
// Package consensus — Phase 3.2: AggregationBits Snappy Compression
//
// AggregationBits is a bitfield where each bit represents whether a validator
// participated in an attestation. For 200K validators, this is 25KB raw.
// Snappy compression reduces this by 50-80% for sparse bitfields (most validators
// don't participate in a given slot's attestation).
//
// This file provides transparent compression/decompression of AggregationBits
// to reduce network bandwidth and storage overhead.
package consensus

import (
	"fmt"

	"github.com/golang/snappy"
)

// CompressAggregationBits compresses a raw AggregationBits bitfield using Snappy.
// Returns the compressed bytes or an error.
func CompressAggregationBits(bits []byte) ([]byte, error) {
	if len(bits) == 0 {
		return nil, nil
	}

	compressed := snappy.Encode(nil, bits)
	if len(compressed) == 0 && len(bits) > 0 {
		return nil, fmt.Errorf("snappy compression produced empty output for %d input bytes", len(bits))
	}

	return compressed, nil
}

// DecompressAggregationBits decompresses a Snappy-compressed AggregationBits bitfield.
// maxLen is the expected maximum decompressed length (for bounds checking).
//
// AUDIT (2026) CORE-07 FIX: Previously this function called snappy.Decode(nil,
// compressed) BEFORE checking maxLen, allowing a small crafted compressed payload to
// force a multi-gigabyte allocation before the bound check rejected it. Now we read
// the declared decoded length from the Snappy header via snappy.DecodedLen (no
// allocation) and validate it against maxLen before any large allocation.
func DecompressAggregationBits(compressed []byte, maxLen int) ([]byte, error) {
	if len(compressed) == 0 {
		return nil, nil
	}

	// Validate the declared decompressed length BEFORE allocating.
	if maxLen > 0 {
		declaredLen, err := snappy.DecodedLen(compressed)
		if err != nil {
			return nil, fmt.Errorf("snappy decoded-length check failed: %w", err)
		}
		if declaredLen > maxLen {
			return nil, fmt.Errorf("decompressed AggregationBits exceeds max length: %d > %d", declaredLen, maxLen)
		}
	}

	decompressed, err := snappy.Decode(nil, compressed)
	if err != nil {
		return nil, fmt.Errorf("snappy decompression failed: %w", err)
	}

	// Defense-in-depth: re-check the actual decompressed length in case the header
	// lied (a malformed stream where DecodedLen returns a smaller value than actual).
	if maxLen > 0 && len(decompressed) > maxLen {
		return nil, fmt.Errorf("decompressed AggregationBits exceeds max length: %d > %d", len(decompressed), maxLen)
	}

	return decompressed, nil
}

// CompressedAggregationBitsSize estimates the compressed size of AggregationBits.
// For sparse bitfields (most validators not participating), Snappy achieves
// 50-80% compression. For dense bitfields, compression is minimal.
func CompressedAggregationBitsSize(rawBits []byte) int {
	if len(rawBits) == 0 {
		return 0
	}
	compressed, _ := CompressAggregationBits(rawBits)
	return len(compressed)
}

// IsCompressed checks if AggregationBits appears to be Snappy-compressed.
// Snappy frames start with specific magic bytes.
//
// AUDIT (2026) R4-CORE-07 FIX: Previously this function called
// snappy.Decode(nil, data) to check if the data is valid Snappy. That
// actually decompressed the ENTIRE payload, allowing a small crafted
// compressed input (e.g., a few bytes expanding to gigabytes) to trigger
// unbounded memory allocation and CPU — a DoS amplification vector.
//
// Fix: use snappy.DecodedLen(data) first, which only reads the Snappy
// block header (varint length prefix) WITHOUT allocating or decompressing.
// If the header is invalid, the data is definitely not Snappy. If the
// declared decompressed length exceeds a reasonable cap (10MB, matching
// MaxWSMessageSize), reject it to prevent unbounded allocation. Only then
// do we call snappy.Decode to verify the data is truly Snappy — but now
// the allocation is bounded by the cap. The actual decompression with
// caller-specified bounds checking happens in DecompressAggregationBits.
func IsCompressed(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// Step 1: Read the declared length from the Snappy header varint.
	// This is O(1) — no allocation, no decompression.
	declaredLen, err := snappy.DecodedLen(data)
	if err != nil {
		return false
	}
	// Step 2: Cap the declared length to prevent unbounded allocation.
	// 10MB matches MaxWSMessageSize — any AggregationBits larger than this
	// is either malicious or a bug.
	const maxIsCompressedDecodeLen = 10 * 1024 * 1024
	if declaredLen > maxIsCompressedDecodeLen {
		return false
	}
	// Step 3: Now safe to decode — the declared length is bounded.
	// This verifies the data is truly valid Snappy (not just a valid header).
	_, err = snappy.Decode(nil, data)
	return err == nil
}
