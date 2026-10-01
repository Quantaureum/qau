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
	binary.Write(h, binary.BigEndian, uint64(len(tssCanonicalBindingDomain)))
	h.Write([]byte(tssCanonicalBindingDomain))
	binary.Write(h, binary.BigEndian, uint64(8))
	binary.Write(h, binary.BigEndian, chainID)
	binary.Write(h, binary.BigEndian, uint64(8))
	binary.Write(h, binary.BigEndian, epoch)
	binary.Write(h, binary.BigEndian, uint64(8))
	binary.Write(h, binary.BigEndian, slot)
	binary.Write(h, binary.BigEndian, uint64(len(proposer)))
	h.Write(proposer[:])
	binary.Write(h, binary.BigEndian, uint64(len(domainTag)))
	h.Write([]byte(domainTag))
	binary.Write(h, binary.BigEndian, uint64(len(originalMessage)))
	h.Write(originalMessage)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
