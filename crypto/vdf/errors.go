// Quantaureum Node source, version 1.0.0.
package vdf

import "errors"

var (
	// ErrShortBytes is returned when a serialized element has the wrong length.
	ErrShortBytes = errors.New("vdf: serialized element must be 64 bytes")
	// ErrCoeffOutOfRange is returned when a serialized coefficient exceeds the modulus.
	ErrCoeffOutOfRange = errors.New("vdf: coefficient exceeds modulus")
)
