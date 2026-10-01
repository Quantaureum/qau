// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"testing"
)

func TestTMLDSAReshareNoncePersistsBeforeReuse(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	sessionID := [32]byte{0xd1}
	nonce, err := node.loadOrCreateTMLDSAReshareNonce(
		sessionID,
		1,
		7,
		bytes.NewReader(bytes.Repeat([]byte{0xd2}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if nonce == ([32]byte{}) {
		t.Fatal("zero nonce returned")
	}

	restarted := &Node{config: node.config}
	reloaded, err := restarted.loadOrCreateTMLDSAReshareNonce(
		sessionID,
		1,
		7,
		bytes.NewReader(bytes.Repeat([]byte{0xd3}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded != nonce {
		t.Fatal("restart generated a different committed nonce")
	}
}
