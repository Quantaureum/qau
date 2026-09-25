package node

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

func r107NewQPOS(t *testing.T) *consensus.QPOS {
	t.Helper()
	validators := make([]*consensus.Validator, 4)
	for i := range validators {
		validators[i] = &consensus.Validator{
			Address: types.Address{byte(i + 1)},
			Stake:   new(big.Int).Mul(big.NewInt(6000), big.NewInt(1e18)),
			Active:  true,
		}
	}
	validatorSet, err := consensus.NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	qpos, err := consensus.NewQPOS(validatorSet)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	t.Cleanup(qpos.Stop)
	return qpos
}

func TestR107_NewBlockProducerRestoresDurableFinalityCheckpoint(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false
	cfg.ValidatorKey = ""

	node, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	t.Cleanup(func() { closeNodeDB(node) })

	justifiedEpoch := uint64(1465)
	finalizedEpoch := uint64(1464)
	justifiedRoot := types.Hash{0xCD}
	finalizedRoot := types.Hash{0xEF}
	// NewNode initializes storage lazily during Start. Install the same
	// BlockStore dependency here so this test exercises the real
	// NewBlockProducer startup wiring without starting network services.
	node.blockStore = block.NewBlockStore(db.NewMemDB())
	if err := node.blockStore.PutFinalityState(
		justifiedEpoch,
		finalizedEpoch,
		justifiedRoot,
		finalizedRoot,
	); err != nil {
		t.Fatalf("PutFinalityState: %v", err)
	}

	producer := NewBlockProducer(node, 12*time.Second)
	if producer == nil || producer.QPOS() == nil {
		t.Fatal("NewBlockProducer did not initialize QPOS")
	}
	t.Cleanup(producer.QPOS().Stop)

	qpos := producer.QPOS()
	if got := qpos.GetJustifiedEpoch(); got != justifiedEpoch {
		t.Fatalf("justified epoch after NewBlockProducer = %d, want %d", got, justifiedEpoch)
	}
	if got := qpos.GetFinalizedEpoch(); got != finalizedEpoch {
		t.Fatalf("finalized epoch after NewBlockProducer = %d, want %d", got, finalizedEpoch)
	}
	if !qpos.HasEpochRoot(justifiedEpoch) || !qpos.HasEpochRoot(finalizedEpoch) {
		t.Fatalf(
			"NewBlockProducer did not restore checkpoint roots: justified=%t finalized=%t",
			qpos.HasEpochRoot(justifiedEpoch),
			qpos.HasEpochRoot(finalizedEpoch),
		)
	}
}

func TestR107_CorruptFinalityStateFailsClosedAndSelfHeals(t *testing.T) {
	store := block.NewBlockStore(db.NewMemDB())
	if err := store.GetDB().Put([]byte("qpos-finality-v1"), []byte("corrupt")); err != nil {
		t.Fatalf("seed corrupt finality state: %v", err)
	}

	qpos := r107NewQPOS(t)
	if err := configureQPOSFinalityPersistence(qpos, store); err != nil {
		t.Fatalf("configure with corrupt finality state: %v", err)
	}

	headerHash := types.Hash{0xAB}
	justifiedRoot := types.Hash{0xCD}
	finalizedRoot := types.Hash{0xEF}
	qpos.AdoptHeaderFinality(9, 8, headerHash)
	qpos.SetEpochBlockRoot(8, finalizedRoot)
	qpos.SetEpochBlockRoot(9, justifiedRoot)

	justified, finalized, gotJustifiedRoot, gotFinalizedRoot, err := store.LoadFinalityState()
	if err != nil {
		t.Fatalf("LoadFinalityState after canonical recovery: %v", err)
	}
	if justified != 9 || finalized != 8 || gotJustifiedRoot != justifiedRoot || gotFinalizedRoot != finalizedRoot {
		t.Fatalf(
			"recovered state = (%d, %d, %x, %x), want (9, 8, %x, %x)",
			justified,
			finalized,
			gotJustifiedRoot[:4],
			gotFinalizedRoot[:4],
			justifiedRoot[:4],
			finalizedRoot[:4],
		)
	}
}

func TestR107_FinalityPersistenceWiringSurvivesRestart(t *testing.T) {
	database := db.NewMemDB()
	store := block.NewBlockStore(database)
	qpos := r107NewQPOS(t)
	if err := configureQPOSFinalityPersistence(qpos, store); err != nil {
		t.Fatalf("configureQPOSFinalityPersistence: %v", err)
	}

	headerHash := types.Hash{0xAB}
	justifiedRoot := types.Hash{0xCD}
	finalizedRoot := types.Hash{0xEF}
	qpos.AdoptHeaderFinality(9, 8, headerHash)
	qpos.SetEpochBlockRoot(8, finalizedRoot)
	qpos.SetEpochBlockRoot(9, justifiedRoot)

	restarted := r107NewQPOS(t)
	if err := configureQPOSFinalityPersistence(restarted, store); err != nil {
		t.Fatalf("configureQPOSFinalityPersistence after restart: %v", err)
	}
	if got := restarted.GetJustifiedEpoch(); got != 9 {
		t.Fatalf("restored justified epoch = %d, want 9", got)
	}
	if got := restarted.GetFinalizedEpoch(); got != 8 {
		t.Fatalf("restored finalized epoch = %d, want 8", got)
	}
	if !restarted.HasEpochRoot(9) || !restarted.HasEpochRoot(8) {
		t.Fatalf(
			"restored checkpoint roots missing: justified=%t finalized=%t",
			restarted.HasEpochRoot(9),
			restarted.HasEpochRoot(8),
		)
	}
}
