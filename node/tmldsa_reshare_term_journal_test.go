// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"testing"

	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAReshareTermPersistsBeforeCommitment(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	sessionID := [32]byte{0xf1}
	reveal, err := node.loadOrPersistTMLDSAReshareTerm(
		sessionID,
		1,
		3,
		2,
		protocolmldsa65.ReshareDealerWitnessID(1),
		1234,
		bytes.NewReader(bytes.Repeat([]byte{0xf2}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if reveal.Term != 1234 || reveal.Salt == ([32]byte{}) {
		t.Fatalf("unexpected reveal: %+v", reveal)
	}

	restarted := &Node{config: node.config}
	reloaded, err := restarted.loadOrPersistTMLDSAReshareTerm(
		sessionID,
		1,
		3,
		2,
		protocolmldsa65.ReshareDealerWitnessID(1),
		1234,
		bytes.NewReader(bytes.Repeat([]byte{0xf3}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded != reveal {
		t.Fatal("restart changed durable term reveal")
	}
	if _, err := restarted.loadOrPersistTMLDSAReshareTerm(
		sessionID,
		1,
		3,
		2,
		protocolmldsa65.ReshareDealerWitnessID(1),
		1235,
		bytes.NewReader(bytes.Repeat([]byte{0xf4}, 64)),
	); err == nil {
		t.Fatal("changed term reused durable salt")
	}
}
