// Quantaureum Node source, version 1.0.0.
// Package safeconv provides safe integer conversion functions that check for overflow
package safeconv

import (
	"errors"
	"math"
)

var (
	// ErrOverflow is returned when an integer conversion would overflow
	ErrOverflow = errors.New("integer overflow")
)

// Uint64ToInt64 safely converts uint64 to int64, returning error on overflow
func Uint64ToInt64(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, ErrOverflow
	}
	return int64(v), nil
}

// Uint64ToInt64Safe safely converts uint64 to int64, clamping to MaxInt64 on overflow
func Uint64ToInt64Safe(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// Uint64ToUint32 safely converts uint64 to uint32, returning error on overflow
func Uint64ToUint32(v uint64) (uint32, error) {
	if v > math.MaxUint32 {
		return 0, ErrOverflow
	}
	return uint32(v), nil
}

// Uint64ToUint32Safe safely converts uint64 to uint32, clamping to MaxUint32 on overflow
func Uint64ToUint32Safe(v uint64) uint32 {
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// Uint64ToUint8 safely converts uint64 to uint8, returning error on overflow
func Uint64ToUint8(v uint64) (uint8, error) {
	if v > math.MaxUint8 {
		return 0, ErrOverflow
	}
	return uint8(v), nil
}

// Uint64ToInt safely converts uint64 to int, returning error on overflow
func Uint64ToInt(v uint64) (int, error) {
	if v > math.MaxInt {
		return 0, ErrOverflow
	}
	return int(v), nil
}

// Uint64ToIntSafe safely converts uint64 to int, clamping to MaxInt on overflow
func Uint64ToIntSafe(v uint64) int {
	if v > math.MaxInt {
		return math.MaxInt
	}
	return int(v)
}

// Int64ToUint64 safely converts int64 to uint64, returning error on negative
func Int64ToUint64(v int64) (uint64, error) {
	if v < 0 {
		return 0, ErrOverflow
	}
	return uint64(v), nil
}
