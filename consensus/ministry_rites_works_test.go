// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

func setupMinistryRites(t *testing.T) (*QPOS, *MinistryRites) {
	t.Helper()
	vs, err := NewValidatorSet(generateValidators(10))
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	registry := NewMinistryRegistry(qpos, coordinator)
	return qpos, registry.Rites()
}

func TestMinistryRites_GetStatus(t *testing.T) {
	_, rites := setupMinistryRites(t)

	status := rites.GetStatus()
	if status["ministry"] != "Rites" {
		t.Fatalf("ministry = %v, want Rites", status["ministry"])
	}
	if status["displayName"] != "Rites" {
		t.Fatalf("displayName = %v, want Rites", status["displayName"])
	}
}

func setupMinistryWorks(t *testing.T) (*QPOS, *MinistryWorks) {
	t.Helper()
	vs, err := NewValidatorSet(generateValidators(10))
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	registry := NewMinistryRegistry(qpos, coordinator)
	// SECURITY (audit GOV-03): Register a system caller for tests so that
	// ministry methods with authorization checks can be called.
	RegisterSystemCaller(testSystemCaller)
	return qpos, registry.Works()
}

func TestMinistryWorks_RegisterShard(t *testing.T) {
	_, works := setupMinistryWorks(t)

	shard, err := works.RegisterShard(testSystemCaller, 100, "1000000")
	if err != nil {
		t.Fatalf("RegisterShard failed: %v", err)
	}

	if shard.ID != 1 {
		t.Fatalf("shard ID = %d, want 1", shard.ID)
	}
	if shard.State != ShardStateActive {
		t.Fatalf("shard state = %s, want Active", shard.State)
	}
	if shard.ValidatorCount != 100 {
		t.Fatalf("validator count = %d, want 100", shard.ValidatorCount)
	}
}

func TestMinistryWorks_DeactivateShard(t *testing.T) {
	_, works := setupMinistryWorks(t)

	shard, _ := works.RegisterShard(testSystemCaller, 100, "1000000")

	err := works.DeactivateShard(testSystemCaller, shard.ID)
	if err != nil {
		t.Fatalf("DeactivateShard failed: %v", err)
	}

	result, _ := works.GetShard(shard.ID)
	if result.State != ShardStateInactive {
		t.Fatalf("shard state = %s, want Inactive", result.State)
	}
}

func TestMinistryWorks_RegisterBridge(t *testing.T) {
	_, works := setupMinistryWorks(t)

	bridge, err := works.RegisterBridge(testSystemCaller, "Ethereum Bridge", 1, 5, "500000")
	if err != nil {
		t.Fatalf("RegisterBridge failed: %v", err)
	}

	if bridge.ID != 1 {
		t.Fatalf("bridge ID = %d, want 1", bridge.ID)
	}
	if bridge.State != BridgeStateActive {
		t.Fatalf("bridge state = %s, want Active", bridge.State)
	}
	if bridge.RemoteChainID != 1 {
		t.Fatalf("remote chain ID = %d, want 1", bridge.RemoteChainID)
	}
}

func TestMinistryWorks_SuspendAndReactivateBridge(t *testing.T) {
	_, works := setupMinistryWorks(t)

	bridge, _ := works.RegisterBridge(testSystemCaller, "Test Bridge", 1, 3, "100000")

	err := works.SuspendBridge(testSystemCaller, bridge.ID, "security concern")
	if err != nil {
		t.Fatalf("SuspendBridge failed: %v", err)
	}

	result, _ := works.GetBridge(bridge.ID)
	if result.State != BridgeStateSuspended {
		t.Fatalf("bridge state = %s, want Suspended", result.State)
	}

	err = works.ReactivateBridge(testSystemCaller, bridge.ID)
	if err != nil {
		t.Fatalf("ReactivateBridge failed: %v", err)
	}

	result, _ = works.GetBridge(bridge.ID)
	if result.State != BridgeStateActive {
		t.Fatalf("bridge state = %s, want Active", result.State)
	}
}

func TestMinistryWorks_CrossChainTx(t *testing.T) {
	_, works := setupMinistryWorks(t)

	bridge, _ := works.RegisterBridge(testSystemCaller, "Test Bridge", 1, 3, "100000")

	sourceHash := types.Hash{0x01, 0x02, 0x03}
	tx, err := works.RecordCrossChainTx(testSystemCaller, bridge.ID, sourceHash, "100")
	if err != nil {
		t.Fatalf("RecordCrossChainTx failed: %v", err)
	}

	if tx.Status != "pending" {
		t.Fatalf("tx status = %s, want pending", tx.Status)
	}

	destHash := types.Hash{0x04, 0x05, 0x06}
	err = works.CompleteCrossChainTx(testSystemCaller, tx.ID, destHash)
	if err != nil {
		t.Fatalf("CompleteCrossChainTx failed: %v", err)
	}
}

func TestMinistryWorks_CrossChainTxOnSuspendedBridge(t *testing.T) {
	_, works := setupMinistryWorks(t)

	bridge, _ := works.RegisterBridge(testSystemCaller, "Test Bridge", 1, 3, "100000")
	works.SuspendBridge(testSystemCaller, bridge.ID, "test")

	sourceHash := types.Hash{0x01}
	_, err := works.RecordCrossChainTx(testSystemCaller, bridge.ID, sourceHash, "100")
	if err == nil {
		t.Fatal("cross-chain tx on suspended bridge should fail")
	}
}

func TestMinistryWorks_ShardHealth(t *testing.T) {
	_, works := setupMinistryWorks(t)

	shard, _ := works.RegisterShard(testSystemCaller, 100, "1000000")

	healthy, err := works.GetShardHealth(shard.ID)
	if err != nil {
		t.Fatalf("GetShardHealth failed: %v", err)
	}
	if !healthy {
		t.Fatal("newly registered shard should be healthy")
	}

	works.DeactivateShard(testSystemCaller, shard.ID)
	healthy, _ = works.GetShardHealth(shard.ID)
	if healthy {
		t.Fatal("inactive shard should not be healthy")
	}
}

func TestMinistryWorks_GetStatus(t *testing.T) {
	_, works := setupMinistryWorks(t)

	status := works.GetStatus()
	if status["ministry"] != "Works" {
		t.Fatalf("ministry = %v, want Works", status["ministry"])
	}
	if status["displayName"] != "Works" {
		t.Fatalf("displayName = %v, want Works", status["displayName"])
	}
}

func TestMinistryRegistry_AllSixMinistries(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(10))
	qpos, _ := NewQPOS(vs)
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	registry := NewMinistryRegistry(qpos, coordinator)

	status := registry.GetStatus()

	ministries := []string{"personnel", "revenue", "justice", "defense", "rites", "works"}
	for _, m := range ministries {
		if _, ok := status[m]; !ok {
			t.Fatalf("missing ministry %s in status", m)
		}
	}

	for _, id := range []MinistryID{MinistryIDPersonnel, MinistryIDRevenue, MinistryIDJustice, MinistryIDDefense, MinistryIDRites, MinistryIDWorks} {
		ms := registry.GetMinistryStatus(id)
		if ms == nil {
			t.Fatalf("GetMinistryStatus(%d) returned nil", id)
		}
		if !ms.Active {
			t.Fatalf("ministry %s should be active", id.DisplayName())
		}
	}
}
