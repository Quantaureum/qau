// Quantaureum Node source, version 1.0.0.
// Package consensus — Phase 4.2: Parallel Attestation Verification
//
// With 10K+ validators per epoch, sequential attestation verification becomes
// a bottleneck. Each Dilithium3 signature verification takes ~1ms, so verifying
// 128 attestations takes ~128ms — too slow for a 12-second slot.
//
// ParallelVerifier uses multiple goroutines to verify attestations concurrently,
// leveraging multi-core CPUs. With 8 workers, verification time drops from
// ~128ms to ~16ms (8x speedup).
//
// Thread-safe and worker-pool based for controlled resource usage.
package consensus

import (
	"encoding/binary"
	"sync"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// ParallelVerifier provides concurrent attestation signature verification.
type ParallelVerifier struct {
	workers  int
	sigCache *crypto.SignatureCache
}

// NewParallelVerifier creates a new parallel attestation verifier.
// workers is the number of parallel verification goroutines.
// If workers <= 0, defaults to 8.
func NewParallelVerifier(workers int, sigCache *crypto.SignatureCache) *ParallelVerifier {
	if workers <= 0 {
		workers = 8
	}
	if sigCache == nil {
		sigCache = crypto.NewSignatureCache(10000)
	}
	return &ParallelVerifier{
		workers:  workers,
		sigCache: sigCache,
	}
}

// VerifyAttestations verifies multiple attestations in parallel.
// Returns the number of valid attestations and a slice of invalid validator indices.
func (pv *ParallelVerifier) VerifyAttestations(atts []*Attestation, pubKeys map[int]*crypto.PublicKey) (validCount int, invalidIndices []int) {
	if len(atts) == 0 {
		return 0, nil
	}

	numWorkers := pv.workers
	if len(atts) < numWorkers {
		numWorkers = len(atts)
	}

	// Create work channels
	type verifyJob struct {
		index int
		att   *Attestation
	}

	jobs := make(chan verifyJob, len(atts))
	results := make(chan struct {
		index int
		valid bool
	}, len(atts))

	// Start workers
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// R7-P3 FIX: recover prevents a single bad signature from
			// crashing the entire node. The job is skipped on panic.
			defer func() {
				if r := recover(); r != nil {
					qposAdvLogger.Errorf("panic in parallel attestation verification worker: %v", r)
				}
			}()
			for job := range jobs {
				valid := pv.verifyOne(job.att, pubKeys)
				results <- struct {
					index int
					valid bool
				}{job.index, valid}
			}
		}()
	}

	// Submit jobs
	for i, att := range atts {
		jobs <- verifyJob{index: i, att: att}
	}
	close(jobs)

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for result := range results {
		if result.valid {
			validCount++
		} else {
			invalidIndices = append(invalidIndices, result.index)
		}
	}

	return validCount, invalidIndices
}

// verifyOne verifies a single attestation, checking the signature cache first.
func (pv *ParallelVerifier) verifyOne(att *Attestation, pubKeys map[int]*crypto.PublicKey) bool {
	if att == nil {
		return false
	}

	pubKey, ok := pubKeys[att.ValidatorIndex]
	if !ok {
		return false
	}

	// Build the signed message (same as what the validator signed)
	msg := buildAttestationMessage(att)

	// Check cache first, then full verification
	return pv.sigCache.VerifyWithCache(pubKey, msg, att.Signature)
}

// buildAttestationMessage builds the message that was signed by the validator.
// This must match exactly what the validator signed during attestation creation.
//
// AUDIT (2026) CORE-06 FIX: Previously this function used a 120-byte format
// that was missing the domain separator, network ID, KeyVersion, and validator
// index. The active signing path (QPOS.attestationSigningData in validator.go)
// uses a 162-byte format with all those fields, so the latent ParallelVerifier
// would have rejected every valid attestation. This function now mirrors
// attestationSigningData exactly so the two paths cannot drift again.
func buildAttestationMessage(att *Attestation) []byte {
	// Format: domainSep(18) + networkID(8) + slot(8) + keyVersion(8) +
	//         beaconBlockRoot(32) + sourceEpoch(8) + sourceRoot(32) +
	//         targetEpoch(8) + targetRoot(32) + validatorIndex(8) = 162 bytes
	domainLen := len(AttestationDomainSeparator)
	msg := make([]byte, domainLen+8+8+8+types.HashLength+8+types.HashLength+8+types.HashLength+8)
	offset := 0

	// Domain separator
	copy(msg[offset:], AttestationDomainSeparator)
	offset += domainLen

	// Network ID (prevents cross-chain replay)
	binary.BigEndian.PutUint64(msg[offset:], GetAttestationNetworkID())
	offset += 8

	// Slot
	binary.BigEndian.PutUint64(msg[offset:], att.Slot)
	offset += 8

	// KeyVersion (prevents forged attestations after key rotation)
	binary.BigEndian.PutUint64(msg[offset:], att.KeyVersion)
	offset += 8

	// BeaconBlockRoot
	copy(msg[offset:], att.BeaconBlockRoot[:])
	offset += types.HashLength

	// Source epoch and root
	binary.BigEndian.PutUint64(msg[offset:], att.Source.Epoch)
	offset += 8
	copy(msg[offset:], att.Source.Root[:])
	offset += types.HashLength

	// Target epoch and root
	binary.BigEndian.PutUint64(msg[offset:], att.Target.Epoch)
	offset += 8
	copy(msg[offset:], att.Target.Root[:])
	offset += types.HashLength

	// Validator index (treat negative as 0 to match attestationSigningData)
	valIdx := uint64(0)
	if att.ValidatorIndex > 0 {
		valIdx = uint64(att.ValidatorIndex) // #nosec G115 -- bounded by validator set size
	}
	binary.BigEndian.PutUint64(msg[offset:], valIdx)

	return msg
}

// VerifyAggregatedAttestationParallel verifies an aggregated attestation in parallel.
// This checks the AggregatedSignature (single QTD signature) against the group public key.
func (pv *ParallelVerifier) VerifyAggregatedAttestationParallel(agg *AggregatedAttestation, groupPubKey *crypto.PublicKey) bool {
	if agg == nil || groupPubKey == nil {
		return false
	}

	// If we have a single aggregated signature (QTD mode), verify it once
	if len(agg.AggregatedSignature) > 0 {
		msg := buildAggregatedAttestationMessage(agg)
		return pv.sigCache.VerifyWithCache(groupPubKey, msg, agg.AggregatedSignature)
	}

	// Fallback: non-QTD mode with individual signatures.
	// AUDIT (2026) CORE B-4 FIX: Previously returned len(agg.Signatures) > 0
	// without any cryptographic verification — any non-empty signature list was
	// accepted as valid. This function only receives the group public key, not
	// individual validator public keys, so it cannot verify individual signatures.
	// Fail-closed: reject aggregated attestations that lack a QTD aggregated
	// signature. Callers needing per-signature verification in non-QTD mode
	// should use VerifyAttestations (which has access to the validator set).
	return false
}

// buildAggregatedAttestationMessage builds the message for aggregated attestation verification.
func buildAggregatedAttestationMessage(agg *AggregatedAttestation) []byte {
	// Same format as individual attestation but without validator index
	msg := make([]byte, 8+32+8+32+8+32)
	offset := 0

	msg[offset] = byte(agg.Slot >> 56)
	msg[offset+1] = byte(agg.Slot >> 48) // #nosec G115
	msg[offset+2] = byte(agg.Slot >> 40) // #nosec G115
	msg[offset+3] = byte(agg.Slot >> 32) // #nosec G115
	msg[offset+4] = byte(agg.Slot >> 24) // #nosec G115
	msg[offset+5] = byte(agg.Slot >> 16) // #nosec G115
	msg[offset+6] = byte(agg.Slot >> 8)  // #nosec G115
	msg[offset+7] = byte(agg.Slot)       // #nosec G115
	offset += 8

	copy(msg[offset:], agg.BeaconBlockRoot[:])
	offset += 32

	msg[offset] = byte(agg.Source.Epoch >> 56)
	msg[offset+1] = byte(agg.Source.Epoch >> 48) // #nosec G115
	msg[offset+2] = byte(agg.Source.Epoch >> 40) // #nosec G115
	msg[offset+3] = byte(agg.Source.Epoch >> 32) // #nosec G115
	msg[offset+4] = byte(agg.Source.Epoch >> 24) // #nosec G115
	msg[offset+5] = byte(agg.Source.Epoch >> 16) // #nosec G115
	msg[offset+6] = byte(agg.Source.Epoch >> 8)  // #nosec G115
	msg[offset+7] = byte(agg.Source.Epoch)       // #nosec G115
	offset += 8

	copy(msg[offset:], agg.Source.Root[:])
	offset += 32

	msg[offset] = byte(agg.Target.Epoch >> 56)
	msg[offset+1] = byte(agg.Target.Epoch >> 48) // #nosec G115
	msg[offset+2] = byte(agg.Target.Epoch >> 40) // #nosec G115
	msg[offset+3] = byte(agg.Target.Epoch >> 32) // #nosec G115
	msg[offset+4] = byte(agg.Target.Epoch >> 24) // #nosec G115
	msg[offset+5] = byte(agg.Target.Epoch >> 16) // #nosec G115
	msg[offset+6] = byte(agg.Target.Epoch >> 8)  // #nosec G115
	msg[offset+7] = byte(agg.Target.Epoch)       // #nosec G115
	offset += 8

	copy(msg[offset:], agg.Target.Root[:])

	return msg
}

// BatchVerifyAttestations verifies a batch of attestations in parallel and returns stats.
// This is the main entry point for epoch-level attestation verification.
func (pv *ParallelVerifier) BatchVerifyAttestations(atts []*Attestation, pubKeys map[int]*crypto.PublicKey) BatchVerifyResult {
	valid, invalid := pv.VerifyAttestations(atts, pubKeys)
	return BatchVerifyResult{
		Total:          len(atts),
		Valid:          valid,
		Invalid:        len(invalid),
		InvalidIndices: invalid,
		ValidityRate:   float64(valid) / float64(len(atts)),
	}
}

// BatchVerifyResult holds the results of a batch attestation verification.
type BatchVerifyResult struct {
	Total          int
	Valid          int
	Invalid        int
	InvalidIndices []int
	ValidityRate   float64
}

// IsFullyValid returns true if all attestations in the batch are valid.
func (r *BatchVerifyResult) IsFullyValid() bool {
	return r.Invalid == 0 && r.Total > 0
}

// WorkerCount returns the number of parallel workers.
func (pv *ParallelVerifier) WorkerCount() int {
	return pv.workers
}

// CacheStats returns stats from the underlying signature cache.
func (pv *ParallelVerifier) CacheStats() (hits, misses uint64, hitRate float64) {
	return pv.sigCache.Stats()
}
