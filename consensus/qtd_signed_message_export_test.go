// Quantaureum Node source, version 1.0.0.
package consensus

// Test of the exported seal message helper the node-side signing executor
// builds its signing request from: the layout must be exactly the canonical
// QTDDomainSep || chainID || epoch || slot || blockHash tuple the verifier
// reconstructs, and the legacy chainID == 0 form must stay the raw block hash.

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestQTDSignedMessageLayout(t *testing.T) {
	blockHash := types.Hash{0xAB}
	message := QTDSignedMessage(1668, 9, 42, blockHash)
	if len(message) != qtdSignedMessageLen {
		t.Fatalf("message length = %d, want %d", len(message), qtdSignedMessageLen)
	}
	if !bytes.Equal(message[0:qtdDomainSepLen], []byte(QTDDomainSep)) {
		t.Fatal("message does not start with the domain separator")
	}
	if got := binary.BigEndian.Uint64(message[qtdDomainSepLen : qtdDomainSepLen+8]); got != 1668 {
		t.Fatalf("chain ID = %d, want 1668", got)
	}
	if got := binary.BigEndian.Uint64(message[qtdDomainSepLen+8 : qtdDomainSepLen+16]); got != 9 {
		t.Fatalf("epoch = %d, want 9", got)
	}
	if got := binary.BigEndian.Uint64(message[qtdDomainSepLen+16 : qtdDomainSepLen+24]); got != 42 {
		t.Fatalf("slot = %d, want 42", got)
	}
	if !bytes.Equal(message[qtdDomainSepLen+24:], blockHash[:]) {
		t.Fatal("message does not end with the block hash")
	}
	legacy := QTDSignedMessage(0, 9, 42, blockHash)
	if len(legacy) != len(blockHash) || !bytes.Equal(legacy, blockHash[:]) {
		t.Fatal("chainID zero must keep the legacy raw-blockHash message")
	}
}
