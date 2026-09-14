// Quantaureum Node source, version 1.0.0.
// Package crypto provides batch signature verification for improved performance.
// Batch verification allows verifying multiple signatures more efficiently
// by amortizing the cost of certain operations.
package crypto

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
)

// Batch verification errors
var (
	ErrBatchEmpty          = errors.New("batch is empty")
	ErrBatchVerifyFailed   = errors.New("batch verification failed")
	ErrBatchSizeMismatch   = errors.New("batch size mismatch")
	ErrBatchPartialFailure = errors.New("some signatures in batch failed verification")
	// audit-fix M-2: reject oversized batches to prevent DoS
	ErrBatchTooLarge = errors.New("batch size exceeds maximum")
)

// audit-fix M-2: maximum allowed batch size to prevent resource exhaustion
const MaxBatchSize = 10000

// BatchVerifyResult contains the result of batch verification
type BatchVerifyResult struct {
	// AllValid is true if all signatures are valid
	AllValid bool
	// ValidCount is the number of valid signatures
	ValidCount int
	// InvalidCount is the number of invalid signatures
	InvalidCount int
	// Results contains individual verification results (true = valid)
	Results []bool
	// Errors contains errors for invalid signatures (nil = valid)
	Errors []error
}

// SignatureItem represents a single signature to verify
type SignatureItem struct {
	PublicKey *PublicKey
	Message   []byte
	Signature []byte
}

// BatchVerifier provides batch signature verification
type BatchVerifier struct {
	// Number of worker goroutines
	numWorkers int
	// Batch size threshold for parallel processing
	parallelThreshold int
}

// NewBatchVerifier creates a new batch verifier
func NewBatchVerifier() *BatchVerifier {
	numCPU := runtime.NumCPU()
	return &BatchVerifier{
		numWorkers:        numCPU,
		parallelThreshold: 4, // Use parallel for 4+ signatures
	}
}

// NewBatchVerifierWithConfig creates a batch verifier with custom configuration
func NewBatchVerifierWithConfig(numWorkers, parallelThreshold int) *BatchVerifier {
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	if parallelThreshold <= 0 {
		parallelThreshold = 4
	}
	return &BatchVerifier{
		numWorkers:        numWorkers,
		parallelThreshold: parallelThreshold,
	}
}

// VerifyBatch verifies a batch of signatures
// Returns BatchVerifyResult with detailed results for each signature.
// audit-fix M-2: rejects batches exceeding MaxBatchSize to prevent DoS.
// R24-C4 FIX: Returns aggregate errors only when verification fails to prevent
// information leakage about which specific signatures are invalid.
func (bv *BatchVerifier) VerifyBatch(items []SignatureItem) *BatchVerifyResult {
	n := len(items)
	if n == 0 {
		return &BatchVerifyResult{
			AllValid: true,
			Results:  []bool{},
			Errors:   []error{},
		}
	}

	if n > MaxBatchSize {
		// Return all-invalid result for oversized batches
		// R47-CR-07 FIX: Set Errors[0] as aggregate error (consistent with
		// the sequential and parallel paths), not per-item errors.
		errs := make([]error, n)
		results := make([]bool, n)
		errs[0] = ErrBatchTooLarge
		return &BatchVerifyResult{
			AllValid:     false,
			InvalidCount: n,
			Results:      results,
			Errors:       errs,
		}
	}

	result := &BatchVerifyResult{
		Results: make([]bool, n),
		Errors:  make([]error, n),
	}

	// R24-C4 FIX: Use flag to track if ANY verification failed
	// This allows us to return aggregate error instead of per-item errors
	anyFailed := false

	// Use sequential verification for small batches
	if n < bv.parallelThreshold {
		for i, item := range items {
			valid := Verify(item.PublicKey, item.Message, item.Signature)
			result.Results[i] = valid
			if valid {
				result.ValidCount++
			} else {
				result.InvalidCount++
				anyFailed = true
				// R24-C4: Don't set per-item error to prevent info leak
				// result.Errors[i] = ErrInvalidSignature
			}
		}
		result.AllValid = !anyFailed
		// R24-C4: Only set aggregate error if any failed
		if anyFailed {
			result.Errors[0] = ErrBatchPartialFailure
		}
		return result
	}

	// Use parallel verification for larger batches
	return bv.verifyParallelSecure(items, result)
}

// verifyParallelSecure verifies signatures in parallel without leaking per-item errors.
// R24-C4 FIX: Does not set per-item errors to prevent information leakage about
// which specific signatures are invalid. Uses aggregate error only.
//
// R9-C01 / R9-C07 (2026-07-19) FIX — R8 H-03 partial closure completed:
// R8 added per-item recover (inner defer) AND an outer recover, but the
// outer recover used `_ = r` to silently swallow panics — no logging, no
// InvalidCount update. Worse, when a panic occurred OUTSIDE the per-item
// recover (e.g. channel range, atomic op on misaligned address), the
// worker exited without updating any counter, leaving InvalidCount=0 and
// causing result.AllValid to be computed as TRUE even though a panic had
// occurred and at least one signature was never verified. This is the most
// severe R9 finding: an attacker-crafted signature that triggers a panic
// outside the inner recover would be silently accepted as valid.
//
// FIX: outer recover now (1) logs the panic, (2) atomically increments a
// dedicated panicCount counter, and (3) AllValid is computed as
// (InvalidCount == 0 && panicCount == 0) so any worker panic forces
// AllValid=false. The panic also surfaces as ErrBatchPartialFailure.
func (bv *BatchVerifier) verifyParallelSecure(items []SignatureItem, result *BatchVerifyResult) *BatchVerifyResult {
	n := len(items)

	// Create work channel
	workCh := make(chan int, n)
	for i := 0; i < n; i++ {
		workCh <- i
	}
	close(workCh)

	// Atomic counters for results
	var validCount int64
	var invalidCount int64
	// R9-C07 (2026-07-19) FIX: dedicated panic counter so any worker-level
	// panic forces AllValid=false even when InvalidCount==0.
	var panicCount int64

	// Start workers
	var wg sync.WaitGroup
	numWorkers := bv.numWorkers
	if numWorkers > n {
		numWorkers = n
	}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// H-03 (R8 2026-07-19 FIX): A panic inside Verify (e.g. a
			// malformed Dilithium3 public key that triggers a bounds
			// panic in the circl library, or a corrupted signature slice)
			// would otherwise kill the worker goroutine and leave the
			// remaining signatures unverified. VerifyBatch is called from
			// consensus-critical paths (block/attestation validation); an
			// unhandled panic here can stall the chain. Convert panics into
			// per-item failures so the batch can still complete and the
			// caller sees the bad signature as invalid rather than as a
			// node crash.
			//
			// R9-C01/C07 (2026-07-19) FIX: outer recover previously used
			// `_ = r` to silently discard panics — no logging, no
			// InvalidCount update. A panic here (outside the per-item
			// recover) would leave InvalidCount=0, causing the caller to
			// wrongly conclude AllValid=true. Now we log AND bump a
			// dedicated panicCount so AllValid is forced to false.
			defer func() {
				if r := recover(); r != nil {
					atomic.AddInt64(&panicCount, 1)
					// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger
					// (module=crypto, category=SECURITY) for SIEM collection.
					securityLogger.Error("BatchVerifier worker panic (outer recover)",
						map[string]any{
							"panic": fmt.Sprintf("%v", r),
						})
				}
			}()
			for i := range workCh {
				item := items[i]
				func() {
					defer func() {
						if r := recover(); r != nil {
							// CRYPTO-R10-N05 (2026-07-19) FIX: Reorder so
							// the atomic increment is the LAST operation.
							// Previously the order was: set Results[i]=false,
							// bump invalidCount, then log. If logging.Warn
							// panicked (e.g. logger misconfigured), the
							// outer recover would catch the panic and bump
							// panicCount — but invalidCount had ALREADY
							// been bumped, leading to a double-count where
							// a single bad item inflated both InvalidCount
							// and panicCount. While the failure mode was a
							// safe false-negative (AllValid still false),
							// it misled operators looking at metrics.
							//
							// Now: log FIRST (if it panics, neither
							// invalidCount nor Results[i] has been touched,
							// so the outer recover's panicCount bump is the
							// sole counter for this item). Then set Results[i]
							// = false. Then bump invalidCount LAST — atomic
							// AddInt64 on a properly-aligned local cannot
							// panic, so the increment is guaranteed to
							// complete if reached.
							// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger
							// (module=crypto, category=SECURITY) for SIEM collection.
							securityLogger.Warn("BatchVerifier per-item panic",
								map[string]any{
									"item_index": i,
									"panic":      fmt.Sprintf("%v", r),
								})
							result.Results[i] = false
							atomic.AddInt64(&invalidCount, 1)
						}
					}()
					valid := Verify(item.PublicKey, item.Message, item.Signature)
					result.Results[i] = valid
					if valid {
						atomic.AddInt64(&validCount, 1)
					} else {
						atomic.AddInt64(&invalidCount, 1)
						// R24-C4: Don't set per-item error to prevent info leak
						// result.Errors[i] = ErrInvalidSignature
					}
				}()
			}
		}()
	}

	wg.Wait()

	result.ValidCount = int(validCount)
	result.InvalidCount = int(invalidCount)
	// R9-C07 (2026-07-19) FIX: AllValid is false if ANY of:
	//   - InvalidCount > 0 (an explicit invalid signature)
	//   - panicCount > 0 (a worker-level panic left ≥1 item unverified)
	// Either condition forces the caller to treat the batch as untrusted.
	result.AllValid = result.InvalidCount == 0 && atomic.LoadInt64(&panicCount) == 0

	// R24-C4: Only set aggregate error if any failed
	// R9-C07: also set if panicCount > 0 so callers see an error.
	if !result.AllValid {
		result.Errors[0] = ErrBatchPartialFailure
	}

	return result
}

// VerifyBatchStrict verifies a batch and returns error if any signature is invalid
func (bv *BatchVerifier) VerifyBatchStrict(items []SignatureItem) error {
	if len(items) == 0 {
		return ErrBatchEmpty
	}

	result := bv.VerifyBatch(items)
	if !result.AllValid {
		return ErrBatchPartialFailure
	}
	return nil
}

// VerifyBatchAll verifies all signatures and returns true only if all are valid
func (bv *BatchVerifier) VerifyBatchAll(items []SignatureItem) bool {
	if len(items) == 0 {
		return true
	}
	result := bv.VerifyBatch(items)
	return result.AllValid
}

// VerifyBatchAny verifies signatures and returns true if at least one is valid
func (bv *BatchVerifier) VerifyBatchAny(items []SignatureItem) bool {
	if len(items) == 0 {
		return false
	}
	result := bv.VerifyBatch(items)
	return result.ValidCount > 0
}

// VerifyBatchThreshold verifies signatures and returns true if at least threshold are valid
func (bv *BatchVerifier) VerifyBatchThreshold(items []SignatureItem, threshold int) bool {
	if len(items) == 0 {
		return threshold <= 0
	}
	result := bv.VerifyBatch(items)
	return result.ValidCount >= threshold
}

// BatchSignResult contains the result of batch signing
type BatchSignResult struct {
	// Signatures contains the generated signatures
	Signatures [][]byte
	// Errors contains errors for failed signatures (nil = success)
	Errors []error
	// SuccessCount is the number of successful signatures
	SuccessCount int
	// FailureCount is the number of failed signatures
	FailureCount int
}

// SignBatch signs multiple messages with the same private key
func SignBatch(privateKey *PrivateKey, messages [][]byte) *BatchSignResult {
	n := len(messages)
	result := &BatchSignResult{
		Signatures: make([][]byte, n),
		Errors:     make([]error, n),
	}

	if n == 0 {
		return result
	}

	// Sign each message
	for i, msg := range messages {
		sig, err := Sign(privateKey, msg)
		if err != nil {
			result.Errors[i] = err
			result.FailureCount++
		} else {
			result.Signatures[i] = sig
			result.SuccessCount++
		}
	}

	return result
}

// SignBatchParallel signs multiple messages in parallel
// Each message can use a different private key
type SignItem struct {
	PrivateKey *PrivateKey
	Message    []byte
}

// SignBatchParallel signs multiple items in parallel
// R48-CR-04 FIX: Added MaxBatchSize check to prevent goroutine exhaustion.
func SignBatchParallel(items []SignItem, numWorkers int) *BatchSignResult {
	n := len(items)
	result := &BatchSignResult{
		Signatures: make([][]byte, n),
		Errors:     make([]error, n),
	}

	if n == 0 {
		return result
	}

	// R48-CR-04 FIX: Reject oversized batches to prevent goroutine/resource exhaustion.
	if n > MaxBatchSize {
		for i := range result.Errors {
			result.Errors[i] = ErrBatchTooLarge
		}
		// CR-03 FIX: Set FailureCount so callers can inspect how many items failed.
		result.FailureCount = n
		return result
	}

	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	if numWorkers > n {
		numWorkers = n
	}

	// Create work channel
	workCh := make(chan int, n)
	for i := 0; i < n; i++ {
		workCh <- i
	}
	close(workCh)

	// Atomic counters
	var successCount int64
	var failureCount int64

	// Start workers
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// M-07 FIX (R8 2026-07-19): outer recover guards against any
			// panic outside the per-item recover (e.g., channel send/recv,
			// atomic ops on misaligned addresses). Without this, a single
			// panic in the worker goroutine propagates and crashes the entire
			// node — same DoS class as R8 H-03 (verifyParallelSecure) and
			// C-02 (GMQTD_Sign). Sign() itself has an internal recover, but
			// that does NOT cover the surrounding worker code.
			//
			// CRYPTO-R9-M-REDO-01 (2026-07-19) FIX: Previously, when the
			// outer recover fired while a worker was still holding an
			// index popped from workCh (i.e., panic occurred between
			// `i := range workCh` and entry into the per-item closure,
			// or inside the closure but before per-item recover could
			// account for the failure), that index was neither counted
			// in SuccessCount nor FailureCount. The counters would
			// under-report by 1 per such panic, masking the real error
			// rate. Track the in-flight index via currentIdx and clear
			// it (set to -1) once the per-item closure has accounted
			// for the outcome — so the outer recover only marks the
			// item failed when the per-item path did NOT already do so,
			// avoiding double-counting.
			currentIdx := -1
			defer func() {
				if r := recover(); r != nil {
					// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger
					// (module=crypto, category=SECURITY) for SIEM collection.
					securityLogger.Warn("SignBatchParallel worker panic (best-effort recovery)",
						map[string]any{"panic": fmt.Sprintf("%v", r)})
					if currentIdx >= 0 {
						result.Errors[currentIdx] = fmt.Errorf("worker panic: %v", r)
						atomic.AddInt64(&failureCount, 1)
					}
				}
			}()
			for i := range workCh {
				// Capture i for the inner closure.
				idx := i
				currentIdx = idx
				func() {
					// FIX: per-item recover ensures a single malformed
					// SignItem (e.g., nil PrivateKey causing Sign() internal
					// panic, or items[idx] out-of-bounds if items was
					// mutated) doesn't kill the worker goroutine — without
					// this, the worker exits and remaining items in workCh
					// are silently dropped.
					defer func() {
						if r := recover(); r != nil {
							result.Errors[idx] = fmt.Errorf("sign panic: %v", r)
							atomic.AddInt64(&failureCount, 1)
						}
						// CRYPTO-R9-M-REDO-01: clear currentIdx so the outer
						// recover does not double-count this index. This runs
						// on both happy and panic paths of the closure.
						currentIdx = -1
					}()
					item := items[idx]
					sig, err := Sign(item.PrivateKey, item.Message)
					if err != nil {
						result.Errors[idx] = err
						atomic.AddInt64(&failureCount, 1)
					} else {
						result.Signatures[idx] = sig
						atomic.AddInt64(&successCount, 1)
					}
				}()
			}
		}()
	}

	wg.Wait()

	result.SuccessCount = int(successCount)
	result.FailureCount = int(failureCount)

	return result
}

// Global batch verifier instance
var defaultBatchVerifier = NewBatchVerifier()

// VerifyBatch verifies a batch of signatures using the default verifier
func VerifyBatch(items []SignatureItem) *BatchVerifyResult {
	return defaultBatchVerifier.VerifyBatch(items)
}

// VerifyBatchStrict verifies a batch using the default verifier (strict mode)
func VerifyBatchStrict(items []SignatureItem) error {
	return defaultBatchVerifier.VerifyBatchStrict(items)
}

// VerifyBatchAll verifies all signatures using the default verifier
func VerifyBatchAll(items []SignatureItem) bool {
	return defaultBatchVerifier.VerifyBatchAll(items)
}
