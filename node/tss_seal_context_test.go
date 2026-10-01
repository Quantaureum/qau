// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
)

func sealContextTestMessage(chainID, epoch, slot uint64, hash types.Hash) []byte {
	message := append([]byte(nil), []byte(consensus.QTDDomainSep)...)
	for _, number := range []uint64{chainID, epoch, slot} {
		message = binary.BigEndian.AppendUint64(message, number)
	}
	return append(message, hash[:]...)
}

func TestQTDSealSigningAuthorization(t *testing.T) {
	root := types.Hash{0x42}
	message := sealContextTestMessage(1333, 1, 35, root)
	view := qtdSealSigningView{
		chainID: 1333, epoch: 1, currentSlot: 36, canonicalRoot: root,
		rootKnown: true, approved: true, active: true,
		members: map[int]types.Address{4: {0x44}, 7: {0x77}},
	}
	context, err := validateQTDSealSigning(message, []int{7, 4}, types.Address{0x44}, view)
	if err != nil {
		t.Fatal(err)
	}
	if context.slot != 35 || context.proposer != (types.Address{0x44}) || !bytes.Equal(context.originalMessage, message) {
		t.Fatal("seal context changed the canonical signed message or selected the wrong aggregator")
	}
	for _, test := range []struct {
		name   string
		change func(*qtdSealSigningView)
	}{
		{"wrong chain", func(state *qtdSealSigningView) { state.chainID++ }},
		{"wrong epoch", func(state *qtdSealSigningView) { state.epoch++ }},
		{"future slot", func(state *qtdSealSigningView) { state.currentSlot = 34 }},
		{"unknown root", func(state *qtdSealSigningView) { state.rootKnown = false }},
		{"fork root", func(state *qtdSealSigningView) { state.canonicalRoot[0]++ }},
		{"unapproved", func(state *qtdSealSigningView) { state.approved = false }},
		{"inactive", func(state *qtdSealSigningView) { state.active = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			altered := view
			test.change(&altered)
			if _, err := validateQTDSealSigning(message, []int{4, 7}, types.Address{0x44}, altered); err == nil {
				t.Fatal("unauthorized seal context accepted")
			}
		})
	}
	for _, participants := range [][]int{{4}, {4, 4}, {4, 7, 8}, {4, 8}} {
		if _, err := validateQTDSealSigning(message, participants, types.Address{0x44}, view); err == nil {
			t.Fatalf("wrong committee accepted: %v", participants)
		}
	}
	if _, err := validateQTDSealSigning(message, []int{4, 7}, types.Address{0x77}, view); err == nil {
		t.Fatal("non-designated executive aggregator accepted")
	}
	for _, invalid := range [][]byte{message[:32], append(append([]byte(nil), message...), 0), sealContextTestMessage(1333, 2, 35, root)} {
		if _, err := validateQTDSealSigning(invalid, []int{4, 7}, types.Address{0x44}, view); err == nil {
			t.Fatal("malformed or inconsistent seal message accepted")
		}
	}
}

func TestTSSRoutesAreSessionScoped(t *testing.T) {
	node := &Node{blockProducer: &BlockProducer{validatorAddr: types.Address{1}}}
	first, second := [32]byte{1}, [32]byte{2}
	if err := node.registerTSSRoute(first, types.Address{1}, []byte("first"), time.Now().UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := node.registerTSSRoute(second, types.Address{2}, []byte("second"), time.Now().UnixNano()); err != nil {
		t.Fatal(err)
	}
	if !node.isTSSAggregator(first) || node.isTSSAggregator(second) || node.isTSSAggregator([32]byte{3}) {
		t.Fatal("aggregator authorization leaked across sessions")
	}
	node.removeTSSRoute(second)
	if !node.isTSSAggregator(first) {
		t.Fatal("cleaning another session removed the active aggregator")
	}
	if err := node.registerTSSRoute(first, types.Address{2}, []byte("replacement"), time.Now().UnixNano()); err == nil {
		t.Fatal("active session route was overwritten")
	}
}
