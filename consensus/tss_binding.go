// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/quantaureum/qau/types"
)

const tssCanonicalBindingDomain = "QAU-TSS-v1"

func ComputeTSSCanonicalBinding(chainID, epoch, slot uint64, proposer types.Address, domainTag string, originalMessage []byte) [32]byte {
	h := sha256.New()
	writeUint64 := func(v uint64) {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], v)
		h.Write(buf[:])
	}

	writeUint64(uint64(len(tssCanonicalBindingDomain)))
	h.Write([]byte(tssCanonicalBindingDomain))
	writeUint64(8)
	writeUint64(chainID)
	writeUint64(8)
	writeUint64(epoch)
	writeUint64(8)
	writeUint64(slot)
	writeUint64(uint64(len(proposer)))
	h.Write(proposer[:])
	writeUint64(uint64(len(domainTag)))
	h.Write([]byte(domainTag))
	writeUint64(uint64(len(originalMessage)))
	h.Write(originalMessage)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
