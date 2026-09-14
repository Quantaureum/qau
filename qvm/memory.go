// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"errors"
	"math"
)

// Memory limits
const (
	MaxMemorySize  = 1024 * 1024 * 32 // 32 MB max memory
	MemoryPageSize = 32               // Memory expansion granularity
)

// Memory errors
var (
	ErrMemoryOverflow = errors.New("memory overflow")
	ErrInvalidOffset  = errors.New("invalid memory offset")
)

// Memory represents the QVM linear memory.
type Memory struct {
	data []byte
}

// NewMemory creates a new empty memory.
func NewMemory() *Memory {
	return &Memory{
		data: make([]byte, 0, 4096), // Pre-allocate 4KB
	}
}

// expand expands memory to accommodate the given offset and size.
func (m *Memory) expand(offset, size uint64) error {
	if size == 0 {
		return nil
	}

	// HIGH FIX: Comprehensive overflow checks before any arithmetic
	// Check if offset itself exceeds max memory
	if offset > MaxMemorySize {
		return ErrMemoryOverflow
	}

	// Check if size exceeds max memory
	if size > MaxMemorySize {
		return ErrMemoryOverflow
	}

	// Check for overflow in offset + size calculation
	end := offset + size
	if end < offset || end < size { // Overflow check: sum must be >= both operands
		return ErrMemoryOverflow
	}

	if end > MaxMemorySize {
		return ErrMemoryOverflow
	}

	// HIGH FIX: Validate end value is reasonable before proceeding with page calculation
	if end < offset || end < size {
		return ErrMemoryOverflow
	}

	if end > uint64(len(m.data)) {
		// Round up to page size with overflow protection
		// HIGH FIX: Check for overflow in page size calculation
		pagesNeeded := (end + MemoryPageSize - 1) / MemoryPageSize
		// Check if pagesNeeded * MemoryPageSize would overflow
		if pagesNeeded > MaxMemorySize/MemoryPageSize {
			return ErrMemoryOverflow
		}
		newSize := pagesNeeded * MemoryPageSize
		if newSize > MaxMemorySize {
			newSize = MaxMemorySize
		}
		// Final sanity check
		if newSize < end {
			return ErrMemoryOverflow
		}

		newData := make([]byte, newSize)
		copy(newData, m.data)
		m.data = newData
	}

	return nil
}

// Set stores data at the given offset.
func (m *Memory) Set(offset uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	if err := m.expand(offset, uint64(len(data))); err != nil {
		return err
	}

	copy(m.data[offset:], data)
	return nil
}

// SetByte stores a single byte at the given offset.
func (m *Memory) SetByte(offset uint64, value byte) error {
	if err := m.expand(offset, 1); err != nil {
		return err
	}
	m.data[offset] = value
	return nil
}

// Set32 stores a 32-byte word at the given offset.
func (m *Memory) Set32(offset uint64, value Word) error {
	return m.Set(offset, value[:])
}

// Get retrieves data from the given offset.
func (m *Memory) Get(offset, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}

	if err := m.expand(offset, size); err != nil {
		return nil, err
	}

	result := make([]byte, size)
	copy(result, m.data[offset:offset+size])
	return result, nil
}

// GetPtr returns a copy of the memory region at the given offset.
//
// QVM-R10-H1 (2026-07-19) FIX: Previously this method returned a DIRECT
// REFERENCE to the VM's internal buffer (a sub-slice of m.data), allowing
// any caller to silently mutate VM memory and corrupt execution state.
// Even though the only in-tree caller (opMLOAD in operations.go) wraps
// the result in NewWord() (which copies into a [32]byte value type),
// future callers could forget to do so — and parallel-execution and
// JIT paths are particularly prone to aliasing bugs.
//
// Fix: return a defensive copy. The cost is one allocation per call
// (32 bytes for MLOAD, which is the only current caller). The GetPtr
// API is retained for backward compatibility with downstream code,
// but the safety guarantee now matches GetPtrCopy.
//
// If a future hot path genuinely needs zero-copy read access, it must be
// added as a new, carefully audited method — do NOT reintroduce a general
// unsafe accessor (QV-05: the former unexported getPtrUnsafe was removed
// because it exposed the internal buffer and had zero callers).
func (m *Memory) GetPtr(offset, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}

	if err := m.expand(offset, size); err != nil {
		return nil, err
	}

	// QVM-R10-H1: defensive copy — never expose the internal buffer.
	result := make([]byte, size)
	copy(result, m.data[offset:offset+size])
	return result, nil
}

// GetPtrCopy returns a COPY of the memory region at the given offset.
// Unlike GetPtr, the returned slice is independent of the VM's internal
// buffer and can be safely mutated by the caller without corrupting VM state.
//
// R26-047: This method is the safe alternative to GetPtr for any code path
// where the caller might modify the returned slice. Use GetPtr only for
// hot-path read-only access that has been carefully audited.
func (m *Memory) GetPtrCopy(offset, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	if err := m.expand(offset, size); err != nil {
		return nil, err
	}
	result := make([]byte, size)
	copy(result, m.data[offset:offset+size])
	return result, nil
}

// GetByte retrieves a single byte from the given offset.
func (m *Memory) GetByte(offset uint64) (byte, error) {
	if err := m.expand(offset, 1); err != nil {
		return 0, err
	}
	return m.data[offset], nil
}

// Get32 retrieves a 32-byte word from the given offset.
func (m *Memory) Get32(offset uint64) (Word, error) {
	data, err := m.Get(offset, 32)
	if err != nil {
		return Word{}, err
	}
	return NewWord(data), nil
}

// Copy copies data within memory.
func (m *Memory) Copy(destOffset, srcOffset, size uint64) error {
	if size == 0 {
		return nil
	}

	// audit-fix L-3: check for uint64 overflow on both dest and src additions
	if destOffset+size < destOffset {
		return ErrMemoryOverflow
	}
	if srcOffset+size < srcOffset {
		return ErrMemoryOverflow
	}

	// Expand to accommodate both source and destination
	maxOffset := destOffset + size
	if srcOffset+size > maxOffset {
		maxOffset = srcOffset + size
	}

	if err := m.expand(0, maxOffset); err != nil {
		return err
	}

	// Use copy which handles overlapping regions correctly
	copy(m.data[destOffset:destOffset+size], m.data[srcOffset:srcOffset+size])
	return nil
}

// Size returns the current memory size.
func (m *Memory) Size() uint64 {
	return uint64(len(m.data))
}

// Clear clears the memory by zeroing all bytes and resetting the length.
//
// QVM-R10-M3 (2026-07-19) FIX: Previously Clear only set `m.data = m.data[:0]`
// (via the loop+truncate), but the loop wrote to m.data[i] which still left
// the backing array's CONTENT intact after the length was truncated to 0.
// Go's slice truncation `s[:0]` keeps the underlying array, so any subsequent
// append/extension (including by a future Memory.expand on the same Memory
// instance, or by any code holding a stale reference to the old backing
// array — see QVM-R10-H1 GetPtr defense) could re-expose PQC private keys,
// signatures, or other sensitive data that was previously stored in memory.
//
// The fix: zeroize the backing array CONTENT in place before truncating,
// using the same per-index pattern as ZeroRange (which the compiler cannot
// fold away as a dead store — see ZeroRange's comment for rationale). After
// Clear returns, both the visible length and the backing-array content are
// empty/zero, so no residual sensitive data can be re-exposed.
//
// Note: we deliberately do NOT replace m.data with a new zero-length slice
// (e.g., `m.data = make([]byte, 0)`) because the existing backing array
// may be shared by external code that previously called GetPtr (pre-R10-H1
// behavior). Reusing the same backing array after zeroizing is safer than
// orphaning it (which would leave the original content intact in the GC
// until collected).
func (m *Memory) Clear() {
	// QVM-R10-M3: zero the backing array content in place. The per-index
	// pattern matches ZeroRange — see that func's comment for why we don't
	// use a bulk memclr helper (compiler dead-store elimination concern).
	for i := range m.data {
		m.data[i] = 0
	}
	m.data = m.data[:0]
}

// ZeroRange zeros [offset, offset+size) in memory.
// Used for secure cleanup of sensitive data like PQC private keys.
// SECURITY FIX: HIGH-008 - Prevent sensitive data from lingering in memory after use.
//
// P3-V2 AUDIT NOTE (byte-by-byte zeroing is intentional): The per-index loop
// `for i := offset; i < end; i++ { m.data[i] = 0 }` is deliberately used
// instead of a bulk `copy`/`memclr` helper. A direct indexed write through a
// pointer to m.data[i] is harder for the compiler to eliminate as a dead
// store than a single memset-style call, which matters because this routine
// scrubs CRYPTOGRAPHIC key material that must not be optimized away. For the
// sizes involved (key-sized ranges, not multi-MB buffers) the per-byte cost
// is negligible relative to the security guarantee. Do not "optimize" this to
// a helper that the compiler might fold away.
func (m *Memory) ZeroRange(offset, size uint64) error {
	if size == 0 {
		return nil
	}

	// Check for uint64 overflow on end calculation
	end := offset + size
	if end < offset || end < size {
		return ErrMemoryOverflow
	}

	// Ensure memory is expanded to cover the range
	if err := m.expand(offset, size); err != nil {
		return err
	}

	// Zero the bytes in-place
	for i := offset; i < end; i++ {
		m.data[i] = 0
	}

	return nil
}

// Clone creates a copy of the memory.
func (m *Memory) Clone() *Memory {
	clone := &Memory{
		data: make([]byte, len(m.data)),
	}
	copy(clone.data, m.data)
	return clone
}

// Data returns a copy of the memory contents.
// audit-fix R2-L1: returns a copy to prevent callers from bypassing
// gas accounting or size limits by mutating the internal slice.
func (m *Memory) Data() []byte {
	cpy := make([]byte, len(m.data))
	copy(cpy, m.data)
	return cpy
}

// MemoryCost calculates the gas cost for memory expansion.
// Cost = 3 * words + words^2 / 512
// audit-fix R11-4: clamp size to MaxMemorySize to prevent uint64 overflow
// in (words * words). Without this, sizes close to MaxUint64 cause the
// quadratic term to wrap around, producing a near-zero gas cost for what
// should be an impossibly expensive expansion.
func MemoryCost(size uint64) uint64 {
	if size == 0 {
		return 0
	}

	// Any size beyond MaxMemorySize will be rejected by expand(), but we
	// must still return a correct (enormous) gas cost so the caller hits
	// OOG rather than paying negligible gas for a doomed operation.
	if size > MaxMemorySize {
		return ^uint64(0) // MaxUint64 — guarantees OOG
	}

	// Check for overflow before adding 31
	if size > math.MaxUint64-31 {
		return ^uint64(0) // MaxUint64 — guarantees OOG
	}

	// Round up to word size
	words := (size + 31) / 32

	// Linear cost
	linear := words * 3

	// SECURITY (audit P2-05): Check for overflow in quadratic cost.
	// words*words overflows uint64 when words > 2^32. Since MaxMemorySize
	// limits words to ~2^25, this check is defense-in-depth.
	if words > 1<<32 {
		return ^uint64(0) // overflow — guarantees OOG
	}
	quadratic := (words * words) / 512

	// Check for overflow in linear + quadratic
	if linear > ^uint64(0)-quadratic {
		return ^uint64(0) // overflow — guarantees OOG
	}
	return linear + quadratic
}

// MemoryExpansionCost calculates the additional gas cost for expanding memory.
// H-NEW-7 FIX: Check for overflow/underflow when subtracting costs.
// If newCost or currentCost is MaxUint64 (overflow sentinel), handle carefully.
func MemoryExpansionCost(currentSize, newSize uint64) uint64 {
	if newSize <= currentSize {
		return 0
	}
	newCost := MemoryCost(newSize)
	currentCost := MemoryCost(currentSize)
	// If either is MaxUint64, the expansion is impossibly expensive
	if newCost == ^uint64(0) || currentCost == ^uint64(0) {
		return ^uint64(0) // Return max to guarantee OOG
	}
	// Underflow check: if newCost < currentCost (shouldn't happen with proper math)
	if newCost < currentCost {
		return ^uint64(0) // Return max to guarantee OOG
	}
	return newCost - currentCost
}
