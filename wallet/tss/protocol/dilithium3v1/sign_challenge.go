// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"crypto/sha3"
	"encoding/binary"
	"io"
)

func DeriveMode3Challenge(seed [CTildeSize]byte) (Poly, error) {
	shake := sha3.NewSHAKE256()
	if _, err := shake.Write(seed[:]); err != nil {
		return Poly{}, err
	}
	var buffer [136]byte
	if _, err := io.ReadFull(shake, buffer[:]); err != nil {
		return Poly{}, err
	}
	signs := binary.LittleEndian.Uint64(buffer[:8])
	bufferOffset := 8
	var challenge Poly
	for index := N - Tau; index < N; index++ {
		var selected uint8
		for {
			if bufferOffset == len(buffer) {
				if _, err := io.ReadFull(shake, buffer[:]); err != nil {
					return Poly{}, err
				}
				bufferOffset = 0
			}
			selected = buffer[bufferOffset]
			bufferOffset++
			if int(selected) <= index {
				break
			}
		}
		challenge[index] = challenge[selected]
		if signs&1 == 0 {
			challenge[selected] = 1
		} else {
			challenge[selected] = Q - 1
		}
		signs >>= 1
	}
	return challenge, nil
}
