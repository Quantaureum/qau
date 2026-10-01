// Quantaureum Node source, version 1.0.0.
package node

import (
	"reflect"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/wallet/tss"
)

func TestWireTSSSignerRestoresCommittedHolderGeneration(t *testing.T) {
	managerConfig := tss.DefaultTSSConfig()
	managerConfig.Threshold = 2
	managerConfig.TotalShares = 3
	manager, err := tss.NewTSSManager(managerConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.GenerateKeyShares(); err != nil {
		t.Fatal(err)
	}
	defer manager.ZeroizeAllShares()
	if err := manager.RetireResharedShare([]int{4, 7}, 2); err != nil {
		t.Fatal(err)
	}

	producer, _, coordinator, _ := newEpochTransitionTestBlockProducer(t)
	node := &Node{config: &Config{}, tssManager: manager, blockProducer: producer}
	node.wireTSSSigner()
	if holders := coordinator.HolderParticipantIDs(); !reflect.DeepEqual(holders, []int{4, 7}) {
		t.Fatalf("restored holders = %v, want [4 7]", holders)
	}
}

func TestRefreshTSSFinalitySignerAfterShareActivation(t *testing.T) {
	managerConfig := tss.DefaultTSSConfig()
	managerConfig.Threshold = 2
	managerConfig.TotalShares = 3
	manager, err := tss.NewTSSManager(managerConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.GenerateKeyShares(); err != nil {
		t.Fatal(err)
	}
	defer manager.ZeroizeAllShares()
	manager.SetAllowPlaintextExport(true)
	activeState, err := manager.ExportKeyShares()
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RetireResharedShare([]int{4, 7}, 2); err != nil {
		t.Fatal(err)
	}

	producer, qpos, _, _ := newEpochTransitionTestBlockProducer(t)
	qpos.GetQTDFinality().SetQTDSigner(nil)
	node := &Node{config: &Config{}, tssManager: manager, blockProducer: producer}
	node.wireTSSSigner()
	if qpos.GetQTDFinality().GetFinalityType() == consensus.FinalityQTDInstant {
		t.Fatal("shareless signer activated instant finality")
	}
	if err := manager.ImportKeyShares(activeState); err != nil {
		t.Fatal(err)
	}
	node.refreshTSSFinalitySigner()
	if qpos.GetQTDFinality().GetFinalityType() != consensus.FinalityQTDInstant {
		t.Fatal("activated share did not rebind the QTD signer")
	}
}
