// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"errors"
	"math/big"
)

// Stack size limits
const (
	MaxStackSize = 1024 // Maximum stack depth
	WordSize     = 32   // Size of a stack word in bytes
)

// Stack errors
var (
	ErrStackOverflow  = errors.New("stack overflow")
	ErrStackUnderflow = errors.New("stack underflow")
	ErrInvalidIndex   = errors.New("invalid stack index")
)

// Word represents a 256-bit stack word.
type Word [WordSize]byte

// NewWord creates a new Word from bytes.
func NewWord(data []byte) Word {
	var w Word
	if len(data) > WordSize {
		data = data[len(data)-WordSize:]
	}
	copy(w[WordSize-len(data):], data)
	return w
}

// NewWordFromUint64 creates a Word from uint64.
func NewWordFromUint64(v uint64) Word {
	var w Word
	for i := 0; i < 8; i++ {
		w[WordSize-1-i] = byte(v >> (8 * i)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	}
	return w
}

// NewWordFromBigInt creates a Word from big.Int.
func NewWordFromBigInt(v *big.Int) Word {
	var w Word
	if v == nil {
		return w
	}
	bytes := v.Bytes()
	if len(bytes) > WordSize {
		bytes = bytes[len(bytes)-WordSize:]
	}
	copy(w[WordSize-len(bytes):], bytes)
	return w
}

// ToUint64 converts Word to uint64 (truncates if larger).
func (w Word) ToUint64() uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(w[WordSize-1-i]) << (8 * i)
	}
	return v
}

// ToBigInt converts Word to big.Int.
func (w Word) ToBigInt() *big.Int {
	return new(big.Int).SetBytes(w[:])
}

// IsZero returns true if the word is zero.
func (w Word) IsZero() bool {
	for _, b := range w {
		if b != 0 {
			return false
		}
	}
	return true
}

// Bytes returns the word as a byte slice.
func (w Word) Bytes() []byte {
	return w[:]
}

// Stack represents the QVM execution stack.
type Stack struct {
	data []Word
}

// NewStack creates a new empty stack.
func NewStack() *Stack {
	return &Stack{
		data: make([]Word, 0, 64), // Pre-allocate some capacity
	}
}

// Push pushes a word onto the stack.
//
// P3-V4 AUDIT NOTE (capacity growth strategy): The stack starts with capacity
// 64 (see NewStack) and grows by 25% (newCap = cap*5/4) each time it fills,
// clamped to [64, MaxStackSize]. 25% amortized growth balances allocation
// overhead against memory waste: it is larger than Go's default 2x doubling to
// keep peak memory low for the deep-but-narrow QVM stack, yet still amortizes
// append cost to O(1). When len==cap the data is reallocated and copied once;
// MaxStackSize is enforced as a hard ceiling before append, preventing
// unbounded growth. This is the documented growth contract — do not change
// without re-checking MaxStackSize interaction.
func (s *Stack) Push(w Word) error {
	if len(s.data) >= MaxStackSize {
		return ErrStackOverflow
	}
	// MEDIUM FIX: Pre-allocate capacity in batches to reduce allocations
	// Grow capacity by 25% when approaching limit to amortize allocation cost
	if len(s.data) == cap(s.data) {
		newCap := cap(s.data) * 5 / 4 // 25% growth
		if newCap < 64 {
			newCap = 64 // Minimum initial capacity
		}
		if newCap > MaxStackSize {
			newCap = MaxStackSize
		}
		newData := make([]Word, len(s.data), newCap)
		copy(newData, s.data)
		s.data = newData
	}
	s.data = append(s.data, w)
	return nil
}

// PushUint64 pushes a uint64 value onto the stack.
func (s *Stack) PushUint64(v uint64) error {
	return s.Push(NewWordFromUint64(v))
}

// PushBigInt pushes a big.Int value onto the stack.
func (s *Stack) PushBigInt(v *big.Int) error {
	return s.Push(NewWordFromBigInt(v))
}

// Pop pops a word from the stack.
func (s *Stack) Pop() (Word, error) {
	if len(s.data) == 0 {
		return Word{}, ErrStackUnderflow
	}
	w := s.data[len(s.data)-1]
	// L17-005 FIX: Clear the old slot to prevent residual data lingering in the
	// backing array. This prevents sensitive values (e.g., intermediate big.Int
	// results) from being retained in memory after they are popped.
	s.data[len(s.data)-1] = Word{}
	s.data = s.data[:len(s.data)-1]
	return w, nil
}

// PopUint64 pops a uint64 value from the stack.
func (s *Stack) PopUint64() (uint64, error) {
	w, err := s.Pop()
	if err != nil {
		return 0, err
	}
	return w.ToUint64(), nil
}

// PopBigInt pops a big.Int value from the stack.
func (s *Stack) PopBigInt() (*big.Int, error) {
	w, err := s.Pop()
	if err != nil {
		return nil, err
	}
	return w.ToBigInt(), nil
}

// Peek returns the top word without removing it.
func (s *Stack) Peek() (Word, error) {
	if len(s.data) == 0 {
		return Word{}, ErrStackUnderflow
	}
	return s.data[len(s.data)-1], nil
}

// PeekN returns the nth word from the top (0 = top).
func (s *Stack) PeekN(n int) (Word, error) {
	if n < 0 || n >= len(s.data) {
		return Word{}, ErrInvalidIndex
	}
	return s.data[len(s.data)-1-n], nil
}

// Dup duplicates the nth item from the top.
func (s *Stack) Dup(n int) error {
	if n < 1 || n > len(s.data) {
		return ErrInvalidIndex
	}
	w := s.data[len(s.data)-n]
	return s.Push(w)
}

// Swap swaps the top item with the nth item.
func (s *Stack) Swap(n int) error {
	if n < 1 || n >= len(s.data) {
		return ErrInvalidIndex
	}
	top := len(s.data) - 1
	s.data[top], s.data[top-n] = s.data[top-n], s.data[top]
	return nil
}

// Len returns the current stack size.
func (s *Stack) Len() int {
	return len(s.data)
}

// Data returns a defensive copy of the stack contents.
// HIGH-1 (R8 2026-07-19 FIX): Previously returned the internal slice
// directly, allowing callers (e.g. tracer) to mutate the stack or to
// observe stale slice headers after subsequent Push/Pop operations.
// Returning a copy guarantees that the snapshot is consistent and that
// the caller cannot corrupt the executor's working stack.
func (s *Stack) Data() []Word {
	out := make([]Word, len(s.data))
	copy(out, s.data)
	return out
}

// Clear clears the stack.
func (s *Stack) Clear() {
	s.data = s.data[:0]
}

// Clone creates a copy of the stack.
func (s *Stack) Clone() *Stack {
	clone := &Stack{
		data: make([]Word, len(s.data)),
	}
	copy(clone.data, s.data)
	return clone
}
