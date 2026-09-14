// Quantaureum Node source, version 1.0.0.
package multisig

import (
	"crypto/sha256"

	"github.com/quantaureum/qau/types"
)

func generateMultiSigAddressFromSorted(sortedPubkeys [][]byte, required int, total int) types.Address {
	h := sha256.New()
	for _, pk := range sortedPubkeys {
		h.Write(pk)
	}
	h.Write([]byte{byte(required), byte(total)})

	digest := h.Sum(nil)

	var addr types.Address
	copy(addr[:], digest[:20])
	return addr
}
