// Quantaureum Node source, version 1.0.0.
package node

import (
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
	"testing"
)

func TestImportedCanonicalBlockRegistersReviewLifecycle(t *testing.T) {
	producer, engine, coordinator, runner := newEpochTransitionTestBlockProducer(t)
	defer close(runner.release)
	producer.threeChambersFlow = consensus.NewThreeChambersFlow(engine, coordinator)
	header := &encoding.BlockHeader{Slot: 33, Epoch: 1, ProposerAddr: types.Address{1}}
	hash := block.ComputeBlockHash(header)
	engine.SetSlotBlockRoot(header.Slot, hash)
	producer.onCanonicalBlockImported(header)
	lifecycle := producer.threeChambersFlow.GetLifecycle(header.Slot)
	if lifecycle == nil || lifecycle.BlockHash != hash || lifecycle.Phase != consensus.PhaseProposed {
		t.Fatalf("imported block not registered for review: %+v", lifecycle)
	}
	producer.onCanonicalBlockImported(header)
	if got := producer.threeChambersFlow.GetLifecycle(header.Slot); got.BlockHash != hash {
		t.Fatal("duplicate import changed lifecycle")
	}
}

func TestImportedForkDoesNotRegisterReviewLifecycle(t *testing.T) {
	producer, engine, coordinator, runner := newEpochTransitionTestBlockProducer(t)
	defer close(runner.release)
	producer.threeChambersFlow = consensus.NewThreeChambersFlow(engine, coordinator)
	header := &encoding.BlockHeader{Slot: 33, Epoch: 1, ProposerAddr: types.Address{1}}
	engine.SetSlotBlockRoot(header.Slot, types.Hash{0xAB})
	producer.onCanonicalBlockImported(header)
	if producer.threeChambersFlow.GetLifecycle(header.Slot) != nil {
		t.Fatal("noncanonical import registered for review")
	}
}
