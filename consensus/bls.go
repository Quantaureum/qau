// Quantaureum Node source, version 1.0.0.
// Package consensus implements the QPOS consensus mechanism for Quantaureum.
// This file implements quantum-safe signature aggregation using Dilithium.
//
// R33 P3-04 FIX (2026-07-28): AUDIT NOTE — ROGUE-KEY ATTACK DOES NOT APPLY.
//
// The audit flagged this file as "not a real BLS aggregation — missing PoP for rogue-key defense" (not real BLS
// aggregation, lacks PoP to prevent rogue-key attacks). This is technically
// accurate but the risk is misclassified: the rogue-key attack is specific
// to BLS aggregate signatures that use pairing-based aggregation, where an
// attacker can synthesize a public key `pk_rogue = pk1 - pk2` and forge a
// valid aggregate signature without owning any private key.
//
// This file does NOT perform BLS pairing aggregation. Despite the legacy
// name (BLSAggregator), it is a Dilithium signature aggregator that works
// by concatenating individual Dilithium3 signatures and verifying EACH ONE
// INDIVIDUALLY via crypto.Verify in VerifyAggregate (see line ~232). There
// is no algebraic aggregation step that could be exploited by a rogue key.
//
// Furthermore, the CRND-08 fix (2026-07-12) already:
//  1. Rejects duplicate public keys (line ~201-211) — prevents the simplest
//     weight-inflation attack where the same key is passed N times.
//  2. Binds the aggregate commitment to the specific public keys and message
//     (via computeSignatureCommitment) — prevents replay of the same
//     aggregate blob against a different signer set or message.
//
// A Proof-of-Possession (PoP) requirement would add defense-in-depth by
// forcing each validator to prove ownership of its private key at
// registration time, but:
//   - Dilithium3 signatures are already unforgeable under chosen-message
//     attack (EU-CMA), so a validator that registers a public key it does
//     not own cannot subsequently produce valid signatures for it.
//   - Adding PoP would require changes to the Validator struct, genesis
//     format, and validator registration RPC — a disproportionate change
//     for a P3 LOW/INFO severity item.
//
// Decision: Document the non-applicability of rogue-key attacks here and
// rely on the existing CRND-08 dup-key check + commitment binding as
// sufficient defense-in-depth. If real BLS aggregation is ever introduced
// (e.g., for cross-chain bridge signatures), PoP MUST be added at that time.
package consensus

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/quantaureum/qau/crypto"
	"golang.org/x/crypto/sha3"
)

var (
	// ErrEmptySignatures is returned when no signatures to aggregate
	ErrEmptySignatures = errors.New("no signatures to aggregate")

	// ErrSignatureMismatch is returned when signature count doesn't match public key count
	ErrSignatureMismatch = errors.New("signature count doesn't match public key count")

	// ErrInvalidSignature is returned when a signature is invalid
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidAggregateFormat is returned when aggregate format is invalid
	ErrInvalidAggregateFormat = errors.New("invalid aggregate signature format")
)

// SerializedAggregate represents a serialized collection of quantum-safe signatures
// Format: [count(4)] + [sig1_len(4) + sig1] + [sig2_len(4) + sig2] + ... + [commitment(32)]
type SerializedAggregate struct {
	Signatures [][]byte
	Commitment [32]byte // Binding commitment for all signatures
}

// SignatureAggregator handles quantum-safe Dilithium signature aggregation
type SignatureAggregator struct {
	mu sync.RWMutex
}

// NewSignatureAggregator creates a new quantum-safe signature aggregator
func NewSignatureAggregator() *SignatureAggregator {
	return &SignatureAggregator{}
}

// Aggregate aggregates multiple Dilithium signatures.
// Returns a serialized aggregate that can be verified efficiently.
//
// AUDIT (2026) CRND-08 FIX: The commitment now binds the aggregate to the
// specific public keys and message, preventing replay of the same aggregate
// blob against a different signer set or message. Callers MUST pass the same
// publicKeys and message that will be used in VerifyAggregate; pass nil/empty
// for legacy callers (the commitment will degrade to signature-only binding).
func (a *SignatureAggregator) Aggregate(signatures [][]byte, publicKeys []*crypto.PublicKey, message []byte) ([]byte, error) {
	if len(signatures) == 0 {
		return nil, ErrEmptySignatures
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Compute binding commitment over signatures, public keys, and message
	commitment := computeSignatureCommitment(signatures, publicKeys, message)

	// Calculate total size: 4 (count) + sum(4 + len(sig)) + 32 (commitment)
	totalSize := 4 + 32
	for _, sig := range signatures {
		totalSize += 4 + len(sig)
	}

	// Serialize aggregate
	buf := make([]byte, totalSize)
	offset := 0

	// Write signature count
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(signatures))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4

	// Write each signature with length prefix
	for _, sig := range signatures {
		binary.BigEndian.PutUint32(buf[offset:], uint32(len(sig))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		offset += 4
		copy(buf[offset:], sig)
		offset += len(sig)
	}

	// Write commitment
	copy(buf[offset:], commitment[:])

	return buf, nil
}

// MaxAggregateSignatures is the maximum number of signatures in an aggregate.
// audit-fix  prevents DoS via massive memory allocation from untrusted data.
const MaxAggregateSignatures = 10000

// MaxSingleSignatureSize is the maximum allowed size for a single signature (16 KB).
// Dilithium3 signatures are ~3293 bytes; this provides generous headroom.
// audit-fix  prevents DoS via huge individual signature allocation.
const MaxSingleSignatureSize = 16384

// MaxTotalAggregateSize is the maximum total byte size of all signatures
// in a deserialized aggregate. Caps memory usage to prevent DoS via
// count * sigLen multiplication.
// QUANTUM-FIX (2026-07-17): Previously, an attacker could craft a
// payload with count=10000 and sigLen=16384 each, forcing 160MB allocation
// (10000 * 16384 = 163,840,000 bytes). 32MB accommodates ~9700 Dilithium3
// signatures (3293 bytes each), far exceeding realistic aggregate sizes
// while preventing the memory amplification attack.
const MaxTotalAggregateSize = 32 * 1024 * 1024 // 32MB

// ErrTooManySignatures is returned when aggregate contains too many signatures
var ErrTooManySignatures = errors.New("aggregate contains too many signatures")

// ErrSignatureTooLarge is returned when an individual signature exceeds the size limit
var ErrSignatureTooLarge = errors.New("individual signature exceeds maximum size")

// ErrAggregateTooLarge is returned when the total byte size of all signatures
// in an aggregate exceeds MaxTotalAggregateSize.
// QUANTUM-FIX (2026-07-17).
var ErrAggregateTooLarge = errors.New("aggregate total signature size exceeds maximum")

// Disaggregate deserializes an aggregated signature
func (a *SignatureAggregator) Disaggregate(data []byte) (*SerializedAggregate, error) {
	if len(data) < 36 { // minimum: 4 (count) + 32 (commitment)
		return nil, ErrInvalidAggregateFormat
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	offset := 0
	count := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// audit-fix  cap count to prevent DoS via massive memory allocation
	if count > MaxAggregateSignatures {
		return nil, ErrTooManySignatures
	}

	signatures := make([][]byte, count)
	// QUANTUM-FIX (2026-07-17): Track total allocated bytes to prevent
	// memory amplification DoS. Previously, an attacker could craft a payload
	// with count=10000 and sigLen=16384 each, forcing 160MB allocation
	// (10000 * 16384 = 163,840,000 bytes). The per-signature size cap
	// (MaxSingleSignatureSize=16384) and count cap (MaxAggregateSignatures=10000)
	// alone do not prevent the multiplication attack. We accumulate the
	// declared signature sizes and reject the payload early if the total
	// exceeds MaxTotalAggregateSize (32MB), BEFORE allocating the buffers.
	var totalAllocated uint64
	for i := uint32(0); i < count; i++ {
		if len(data) < offset+4 {
			return nil, ErrInvalidAggregateFormat
		}
		sigLen := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		// audit-fix  reject oversized individual signatures
		if sigLen > MaxSingleSignatureSize {
			return nil, ErrSignatureTooLarge
		}

		if len(data) < offset+int(sigLen) {
			return nil, ErrInvalidAggregateFormat
		}

		// QUANTUM-FIX: check total allocation BEFORE allocating.
		// This prevents the 160MB allocation from count=10000 * sigLen=16384.
		totalAllocated += uint64(sigLen)
		if totalAllocated > MaxTotalAggregateSize {
			return nil, ErrAggregateTooLarge
		}

		signatures[i] = make([]byte, sigLen)
		copy(signatures[i], data[offset:offset+int(sigLen)])
		offset += int(sigLen)
	}

	if len(data) < offset+32 {
		return nil, ErrInvalidAggregateFormat
	}

	agg := &SerializedAggregate{
		Signatures: signatures,
	}
	copy(agg.Commitment[:], data[offset:offset+32])

	return agg, nil
}

// VerifyAggregate verifies an aggregated Dilithium signature
//
// R33 P3-11 FIX (2026-07-28): Added structured security logging at each
// aggregate-level failure path using the centralized crypto.Reason* constants.
// Previously these failures returned false silently (only the inner
// crypto.Verify calls logged their own failures), making it hard for SIEM
// tools to distinguish between "no signatures", "duplicate public key",
// "count mismatch", "commitment mismatch", and "individual verify failed".
func (a *SignatureAggregator) VerifyAggregate(publicKeys []*crypto.PublicKey, message []byte, aggregatedSig []byte) bool {
	if len(publicKeys) == 0 || len(aggregatedSig) == 0 {
		qposAdvLogger.Warn("VerifyAggregate rejected: empty inputs", map[string]any{
			"category":     "SECURITY",
			"reason":       "empty_inputs",
			"pubkey_count": len(publicKeys),
			"sig_data_len": len(aggregatedSig),
		})
		return false
	}

	// AUDIT (2026) CRND-08 FIX: Reject duplicate public keys to prevent
	// rogue-key/weight-inflation attacks where the same key is passed N times
	// to inflate the apparent signer count.
	seenKeys := make(map[string]struct{}, len(publicKeys))
	for _, pk := range publicKeys {
		if pk == nil {
			qposAdvLogger.Warn("VerifyAggregate rejected: nil public key in set", map[string]any{
				"category": "SECURITY",
				"reason":   crypto.ReasonNilPublicKey,
			})
			return false
		}
		keyHex := string(pk.Bytes())
		if _, exists := seenKeys[keyHex]; exists {
			qposAdvLogger.Warn("VerifyAggregate rejected: duplicate public key", map[string]any{
				"category": "SECURITY",
				"reason":   crypto.ReasonDuplicatePublicKey,
			})
			return false
		}
		seenKeys[keyHex] = struct{}{}
	}

	// Deserialize aggregate
	agg, err := a.Disaggregate(aggregatedSig)
	if err != nil {
		qposAdvLogger.Warn("VerifyAggregate rejected: disaggregate failed", map[string]any{
			"category": "SECURITY",
			"reason":   "disaggregate_failed",
			"error":    err.Error(),
		})
		return false
	}

	// Check signature count matches public key count
	if len(agg.Signatures) != len(publicKeys) {
		qposAdvLogger.Warn("VerifyAggregate rejected: signature count mismatch", map[string]any{
			"category": "SECURITY",
			"reason":   crypto.ReasonSignatureCountMismatch,
			"expected": len(publicKeys),
			"got":      len(agg.Signatures),
		})
		return false
	}

	// Verify commitment (now bound to public keys and message)
	expectedCommitment := computeSignatureCommitment(agg.Signatures, publicKeys, message)
	if subtle.ConstantTimeCompare(agg.Commitment[:], expectedCommitment[:]) != 1 {
		qposAdvLogger.Warn("VerifyAggregate rejected: commitment mismatch", map[string]any{
			"category": "SECURITY",
			"reason":   crypto.ReasonCommitmentMismatch,
		})
		return false
	}

	// Verify each signature individually using Dilithium.
	// crypto.Verify already emits structured logs with ReasonVerificationFailed
	// for each individual failure, so we don't duplicate that here.
	for i, pk := range publicKeys {
		if !crypto.Verify(pk, message, agg.Signatures[i]) {
			return false
		}
	}

	return true
}

// VerifyAggregateParallel verifies signatures in parallel for better performance.
// audit-fix NEW-1: bounded concurrency via semaphore to prevent goroutine exhaustion.
func (a *SignatureAggregator) VerifyAggregateParallel(publicKeys []*crypto.PublicKey, message []byte, aggregatedSig []byte) bool {
	if len(publicKeys) == 0 || len(aggregatedSig) == 0 {
		return false
	}

	// AUDIT (2026) CRND-08 FIX: Reject duplicate public keys.
	seenKeys := make(map[string]struct{}, len(publicKeys))
	for _, pk := range publicKeys {
		if pk == nil {
			return false
		}
		keyHex := string(pk.Bytes())
		if _, exists := seenKeys[keyHex]; exists {
			return false
		}
		seenKeys[keyHex] = struct{}{}
	}

	// Deserialize aggregate
	agg, err := a.Disaggregate(aggregatedSig)
	if err != nil {
		return false
	}

	if len(agg.Signatures) != len(publicKeys) {
		return false
	}

	// Verify commitment first (now bound to public keys and message)
	expectedCommitment := computeSignatureCommitment(agg.Signatures, publicKeys, message)
	if subtle.ConstantTimeCompare(agg.Commitment[:], expectedCommitment[:]) != 1 {
		return false
	}

	// audit-fix H-FUND-4: short-circuit evaluation to prevent DoS via large batches.
	// Use atomic bool to signal failure across goroutines without mutex contention.
	// An attacker can no longer force thousands of Dilithium verifications by placing
	// one bad signature at the end of a large batch.
	var batchFailed int32
	var wg sync.WaitGroup
	wg.Add(len(publicKeys))
	sem := make(chan struct{}, MaxVRFVerifyConcurrency)

	for i := range publicKeys {
		// H-FUND-4 FIX: skip spawning goroutines once a failure is detected
		if atomic.LoadInt32(&batchFailed) != 0 {
			wg.Done()
			continue
		}
		sem <- struct{}{}
		go func(idx int) {
			defer func() { <-sem }()
			defer wg.Done()
			// R7-P3 FIX: recover prevents a panic in crypto.Verify from
			// crashing the node. Mark the batch as failed so a panicking
			// signature is never silently treated as valid.
			defer func() {
				if r := recover(); r != nil {
					atomic.StoreInt32(&batchFailed, 1)
					qposAdvLogger.Errorf("panic in aggregated signature verification worker: %v", r)
				}
			}()
			if atomic.LoadInt32(&batchFailed) != 0 {
				return
			}
			if publicKeys[idx] == nil {
				return
			}
			if !crypto.Verify(publicKeys[idx], message, agg.Signatures[idx]) {
				atomic.StoreInt32(&batchFailed, 1)
				return
			}
		}(i)
	}

	wg.Wait()

	return atomic.LoadInt32(&batchFailed) == 0
}

// computeSignatureCommitment creates a binding commitment over all signatures,
// public keys, and the message.
// AUDIT (2026) CRND-08 FIX: Previously this function hashed only the
// signatures, allowing the same aggregate blob to be replayed against a
// different signer set or message. Now it also hashes the public keys and
// the message, cryptographically binding the aggregate to its authentication
// context.
func computeSignatureCommitment(signatures [][]byte, publicKeys []*crypto.PublicKey, message []byte) [32]byte {
	h := sha3.New256()

	// Write number of signatures
	countBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(countBuf, uint32(len(signatures))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	h.Write(countBuf)

	// Write each signature
	for _, sig := range signatures {
		// Write signature length
		binary.BigEndian.PutUint32(countBuf, uint32(len(sig))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		h.Write(countBuf)
		// Write signature data
		h.Write(sig)
	}

	// AUDIT (2026) CRND-08: Bind public keys into the commitment
	h.Write([]byte("PUBKEYS:"))
	binary.BigEndian.PutUint32(countBuf, uint32(len(publicKeys))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	h.Write(countBuf)
	for _, pk := range publicKeys {
		if pk != nil {
			pkBytes := pk.Bytes()
			binary.BigEndian.PutUint32(countBuf, uint32(len(pkBytes))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
			h.Write(countBuf)
			h.Write(pkBytes)
		} else {
			h.Write([]byte{0, 0, 0, 0})
		}
	}

	// AUDIT (2026) CRND-08: Bind message into the commitment
	h.Write([]byte("MESSAGE:"))
	binary.BigEndian.PutUint32(countBuf, uint32(len(message))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	h.Write(countBuf)
	h.Write(message)

	var commitment [32]byte
	copy(commitment[:], h.Sum(nil))
	return commitment
}

// VerifyBatch verifies multiple message-signature pairs in batch.
// audit-fix H-FUND-4: short-circuit evaluation to prevent DoS via large batches.
// audit-fix M-FUND-3: removed unnecessary RLock — this function does not access
// any shared mutable state; all data is passed as parameters.
func (a *SignatureAggregator) VerifyBatch(publicKeys []*crypto.PublicKey, messages [][]byte, signatures [][]byte) bool {
	if len(publicKeys) != len(messages) || len(messages) != len(signatures) {
		return false
	}
	var batchFailed int32
	var wg sync.WaitGroup
	wg.Add(len(publicKeys))
	sem := make(chan struct{}, MaxVRFVerifyConcurrency)

	for i := range publicKeys {
		// H-FUND-4 FIX: skip spawning goroutines once a failure is detected
		if atomic.LoadInt32(&batchFailed) != 0 {
			wg.Done()
			continue
		}
		sem <- struct{}{}
		go func(idx int) {
			defer func() { <-sem }()
			defer wg.Done()
			// R7-P3 FIX: recover prevents a panic in crypto.Verify from
			// crashing the node. Mark the batch as failed so a panicking
			// signature is never silently treated as valid.
			defer func() {
				if r := recover(); r != nil {
					atomic.StoreInt32(&batchFailed, 1)
					qposAdvLogger.Errorf("panic in batch signature verification worker: %v", r)
				}
			}()
			if atomic.LoadInt32(&batchFailed) != 0 {
				return
			}
			if publicKeys[idx] == nil {
				return
			}
			if !crypto.Verify(publicKeys[idx], messages[idx], signatures[idx]) {
				atomic.StoreInt32(&batchFailed, 1)
				return
			}
		}(i)
	}

	wg.Wait()

	return atomic.LoadInt32(&batchFailed) == 0
}

// Legacy aliases for backward compatibility
type BLSAggregator = SignatureAggregator

func NewBLSAggregator() *SignatureAggregator {
	return NewSignatureAggregator()
}
