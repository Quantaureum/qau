// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestShake128Equivalence(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i + 1)
	}

	var iv [34]byte
	copy(iv[:32], seed[:])
	iv[32] = 0
	iv[33] = 0
	h1 := sha3.NewShake128()
	h1.Write(iv[:])
	buf1 := make([]byte, 840)
	h1.Read(buf1)

	h2 := sha3.NewShake128()
	h2.Write(seed[:])
	var nb [2]byte
	nb[0] = 0
	nb[1] = 0
	h2.Write(nb[:])
	buf2 := make([]byte, 840)
	h2.Read(buf2)

	for i := 0; i < 840; i++ {
		if buf1[i] != buf2[i] {
			t.Fatalf("SHAKE128 mismatch at byte %d: %d vs %d", i, buf1[i], buf2[i])
		}
	}
	t.Log("SHAKE128 outputs match!")
}
