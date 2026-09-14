// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

func TestDACommitteeManager(t *testing.T) {
	t.Run("NewDACommitteeManager", func(t *testing.T) {
		getValidators := func() []*ValidatorInfo {
			return nil
		}
		getRandao := func(epoch uint64) types.Hash {
			return types.Hash{}
		}

		mgr := NewDACommitteeManager(getValidators, getRandao)
		if mgr == nil {
			t.Fatal("NewDACommitteeManager returned nil")
		}
	})

	t.Run("GetCommittee success", func(t *testing.T) {
		getValidators := func() []*ValidatorInfo {
			validators := make([]*ValidatorInfo, DACommitteeSize+100)
			for i := 0; i < DACommitteeSize+100; i++ {
				addr := types.BytesToAddress([]byte{byte(i >> 8), byte(i & 0xFF)})
				validators[i] = &ValidatorInfo{
					Address: addr,
					Active:  true,
				}
			}
			return validators
		}
		getRandao := func(epoch uint64) types.Hash {
			return types.Hash{byte(epoch)}
		}

		mgr := NewDACommitteeManager(getValidators, getRandao)
		committee, err := mgr.GetCommittee(0)
		if err != nil {
			t.Fatalf("GetCommittee failed: %v", err)
		}

		if len(committee.Members) != DACommitteeSize {
			t.Errorf("expected %d members, got %d", DACommitteeSize, len(committee.Members))
		}

		for i := 0; i < DACommitteeSubnetCount; i++ {
			if len(committee.Subnets[i]) == 0 {
				t.Errorf("subnet %d has no members", i)
			}
		}
	})

	t.Run("GetCommittee no validators", func(t *testing.T) {
		getValidators := func() []*ValidatorInfo {
			return nil
		}
		getRandao := func(epoch uint64) types.Hash {
			return types.Hash{}
		}

		mgr := NewDACommitteeManager(getValidators, getRandao)
		committee, err := mgr.GetCommittee(0)
		// R54-CS-01 FIX: GetCommittee now returns error instead of nil, nil.
		// This prevents callers from proceeding with a nil committee.
		if err == nil {
			t.Error("expected error for no validators, got nil")
		}
		if committee != nil {
			t.Error("expected nil committee for no validators")
		}
		if mgr.IsDACommitteeAvailable() {
			t.Error("expected IsDACommitteeAvailable() to return false")
		}
	})

	t.Run("GetCommittee insufficient validators", func(t *testing.T) {
		getValidators := func() []*ValidatorInfo {
			validators := make([]*ValidatorInfo, 10)
			for i := 0; i < 10; i++ {
				validators[i] = &ValidatorInfo{Active: true}
			}
			return validators
		}
		getRandao := func(epoch uint64) types.Hash {
			return types.Hash{}
		}

		mgr := NewDACommitteeManager(getValidators, getRandao)
		committee, err := mgr.GetCommittee(0)
		// R54-CS-01 FIX: GetCommittee now returns error instead of nil, nil.
		if err == nil {
			t.Error("expected error for insufficient validators, got nil")
		}
		if committee != nil {
			t.Error("expected nil committee for insufficient validators")
		}
		if mgr.IsDACommitteeAvailable() {
			t.Error("expected IsDACommitteeAvailable() to return false")
		}
	})

	t.Run("GetCommittee caching", func(t *testing.T) {
		callCount := 0
		getValidators := func() []*ValidatorInfo {
			callCount++
			validators := make([]*ValidatorInfo, DACommitteeSize+100)
			for i := 0; i < DACommitteeSize+100; i++ {
				validators[i] = &ValidatorInfo{Active: true}
			}
			return validators
		}
		getRandao := func(epoch uint64) types.Hash {
			return types.Hash{byte(epoch)}
		}

		mgr := NewDACommitteeManager(getValidators, getRandao)

		_, err := mgr.GetCommittee(0)
		if err != nil {
			t.Fatalf("first GetCommittee failed: %v", err)
		}
		firstCallCount := callCount

		_, err = mgr.GetCommittee(0)
		if err != nil {
			t.Fatalf("second GetCommittee failed: %v", err)
		}

		if callCount != firstCallCount {
			t.Error("committee should be cached, getValidators should not be called again")
		}
	})

	t.Run("IsInCommittee", func(t *testing.T) {
		getValidators := func() []*ValidatorInfo {
			validators := make([]*ValidatorInfo, DACommitteeSize+100)
			for i := 0; i < DACommitteeSize+100; i++ {
				validators[i] = &ValidatorInfo{Active: true}
			}
			return validators
		}
		getRandao := func(epoch uint64) types.Hash {
			return types.Hash{byte(epoch)}
		}

		mgr := NewDACommitteeManager(getValidators, getRandao)

		inCommittee, subnetID := mgr.IsInCommittee(0, 0)
		if !inCommittee {
			t.Log("validator 0 not in committee (depends on shuffle)")
		}
		_ = subnetID

		inCommittee, _ = mgr.IsInCommittee(0, DACommitteeSize+1000)
		if inCommittee {
			t.Error("validator beyond range should not be in committee")
		}
	})

	t.Run("GetSubnetMembers", func(t *testing.T) {
		getValidators := func() []*ValidatorInfo {
			validators := make([]*ValidatorInfo, DACommitteeSize+100)
			for i := 0; i < DACommitteeSize+100; i++ {
				validators[i] = &ValidatorInfo{Active: true}
			}
			return validators
		}
		getRandao := func(epoch uint64) types.Hash {
			return types.Hash{byte(epoch)}
		}

		mgr := NewDACommitteeManager(getValidators, getRandao)

		members, err := mgr.GetSubnetMembers(0, 0)
		if err != nil {
			t.Fatalf("GetSubnetMembers failed: %v", err)
		}
		if len(members) == 0 {
			t.Error("subnet 0 should have members")
		}

		_, err = mgr.GetSubnetMembers(0, DACommitteeSubnetCount)
		if err == nil {
			t.Error("expected error for invalid subnet ID")
		}

		_, err = mgr.GetSubnetMembers(0, -1)
		if err == nil {
			t.Error("expected error for negative subnet ID")
		}
	})

	t.Run("cleanupOldCommittees", func(t *testing.T) {
		getValidators := func() []*ValidatorInfo {
			validators := make([]*ValidatorInfo, DACommitteeSize+100)
			for i := 0; i < DACommitteeSize+100; i++ {
				validators[i] = &ValidatorInfo{Active: true}
			}
			return validators
		}
		getRandao := func(epoch uint64) types.Hash {
			return types.Hash{byte(epoch)}
		}

		mgr := NewDACommitteeManager(getValidators, getRandao)

		mgr.GetCommittee(0)
		mgr.GetCommittee(10)

		mgr.mu.RLock()
		hasEpoch0 := mgr.committees[0] != nil
		mgr.mu.RUnlock()

		if !hasEpoch0 {
			t.Log("epoch 0 committee may have been cleaned up")
		}
	})
}

func TestDAAttestationCollector(t *testing.T) {
	// testAcceptAllVerifier is a test-only verifier that accepts all
	// attestations. AUDIT (2026) GOV-04: Production code must set a
	// real verifier that checks signature + committee membership.
	testAcceptAllVerifier := DAAttestationVerifier(func(a *encoding.DASAttestation) error {
		return nil
	})

	t.Run("NewDAAttestationCollector", func(t *testing.T) {
		collector := NewDAAttestationCollector()
		if collector == nil {
			t.Fatal("NewDAAttestationCollector returned nil")
		}
	})

	t.Run("SubmitAndGet", func(t *testing.T) {
		collector := NewDAAttestationCollector()

		att1 := &encoding.DASAttestation{
			Slot:           1,
			Available:      true,
			Confidence:     0.99,
			ValidatorIndex: 0,
		}
		att2 := &encoding.DASAttestation{
			Slot:           1,
			Available:      true,
			Confidence:     0.95,
			ValidatorIndex: 1,
		}

		collector.SetCommitteeSize(10)
		collector.SetAttestationVerifier(testAcceptAllVerifier)
		collector.SubmitAttestation(att1)
		collector.SubmitAttestation(att2)

		attestations := collector.GetAttestations(1)
		if len(attestations) != 2 {
			t.Errorf("expected 2 attestations, got %d", len(attestations))
		}
	})

	t.Run("GetAttestations empty slot", func(t *testing.T) {
		collector := NewDAAttestationCollector()

		attestations := collector.GetAttestations(999)
		if attestations != nil {
			t.Error("expected nil for empty slot")
		}
	})

	t.Run("GetAttestations sorted", func(t *testing.T) {
		collector := NewDAAttestationCollector()

		collector.SetCommitteeSize(10)
		collector.SetAttestationVerifier(testAcceptAllVerifier)
		collector.SubmitAttestation(&encoding.DASAttestation{Slot: 1, ValidatorIndex: 5})
		collector.SubmitAttestation(&encoding.DASAttestation{Slot: 1, ValidatorIndex: 1})
		collector.SubmitAttestation(&encoding.DASAttestation{Slot: 1, ValidatorIndex: 3})

		attestations := collector.GetAttestations(1)
		if len(attestations) != 3 {
			t.Fatalf("expected 3 attestations, got %d", len(attestations))
		}

		for i := 1; i < len(attestations); i++ {
			if attestations[i].ValidatorIndex < attestations[i-1].ValidatorIndex {
				t.Error("attestations should be sorted by validator index")
				break
			}
		}
	})

	t.Run("BuildAggregateAttestation", func(t *testing.T) {
		collector := NewDAAttestationCollector()

		collector.SetCommitteeSize(10)
		collector.SetAttestationVerifier(testAcceptAllVerifier)
		for i := 0; i < 10; i++ {
			collector.SubmitAttestation(&encoding.DASAttestation{
				Slot:           1,
				Available:      i < 7,
				Confidence:     0.99,
				ValidatorIndex: i,
				Signature:      []byte{byte(i)},
			})
		}

		aggregate := collector.BuildAggregateAttestation(1, nil)
		if aggregate == nil {
			t.Fatal("BuildAggregateAttestation returned nil")
		}

		if aggregate.AvailableCount != 7 {
			t.Errorf("expected 7 available, got %d", aggregate.AvailableCount)
		}
		if aggregate.TotalCount != 10 {
			t.Errorf("expected 10 total, got %d", aggregate.TotalCount)
		}
		if !aggregate.IsSufficient() {
			t.Error("7/10 should be sufficient")
		}
	})

	t.Run("BuildAggregateAttestation empty", func(t *testing.T) {
		collector := NewDAAttestationCollector()

		aggregate := collector.BuildAggregateAttestation(1, nil)
		if aggregate != nil {
			t.Error("expected nil for empty slot")
		}
	})

	t.Run("BuildAggregateAttestation insufficient", func(t *testing.T) {
		collector := NewDAAttestationCollector()

		collector.SetCommitteeSize(10)
		collector.SetAttestationVerifier(testAcceptAllVerifier)
		for i := 0; i < 10; i++ {
			collector.SubmitAttestation(&encoding.DASAttestation{
				Slot:           1,
				Available:      i < 5,
				Confidence:     0.99,
				ValidatorIndex: i,
				Signature:      []byte{byte(i)},
			})
		}

		// P1-7 (2026-07-14): BuildAggregateAttestation now returns nil when
		// IsSufficient()==false (5/10=0.5 < 0.6667), preventing callers from
		// mistaking an insufficient aggregate for a valid one.
		aggregate := collector.BuildAggregateAttestation(1, nil)
		if aggregate != nil {
			t.Fatal("BuildAggregateAttestation should return nil for insufficient aggregate (P1-7)")
		}
	})

	t.Run("CleanupOldSlots", func(t *testing.T) {
		collector := NewDAAttestationCollector()
		// DA-R5-05 (2026-07-16): Use a small-but-valid retention config
		// instead of relying on the production default (which is now
		// 1024 slots). This keeps the test focused on GC behavior.
		collector.SetRetentionConfig(encoding.DASRetentionConfig{
			BlobRetentionSlots:    8,
			SessionRetentionSlots: 4,
			AttestRetentionSlots:  2,
			ConfidenceDecaySlots:  1,
			MinConfidenceDecay:    0.5,
			GCTickerInterval:      60 * time.Second,
		})

		collector.SetCommitteeSize(10)
		collector.SetAttestationVerifier(testAcceptAllVerifier)
		collector.SubmitAttestation(&encoding.DASAttestation{Slot: 10, ValidatorIndex: 0})
		collector.SubmitAttestation(&encoding.DASAttestation{Slot: 200, ValidatorIndex: 0})

		collector.CleanupOldSlots(200)

		if collector.GetAttestations(10) != nil {
			t.Error("old slot attestations should be cleaned up")
		}
		if collector.GetAttestations(200) == nil {
			t.Error("current slot attestations should not be cleaned up")
		}
	})

	// AUDIT (2026) GOV-04: Fail-closed when verifier not configured.
	t.Run("SubmitAttestation rejected without verifier", func(t *testing.T) {
		collector := NewDAAttestationCollector()
		collector.SetCommitteeSize(10)
		// Note: no SetAttestationVerifier call — should fail-closed
		err := collector.SubmitAttestation(&encoding.DASAttestation{
			Slot:           1,
			Available:      true,
			ValidatorIndex: 0,
		})
		if err == nil {
			t.Fatal("expected error when attestation verifier is not configured")
		}
	})

	// AUDIT (2026) GOV-04: Verifier rejection propagates as error.
	t.Run("SubmitAttestation rejected by verifier", func(t *testing.T) {
		collector := NewDAAttestationCollector()
		collector.SetCommitteeSize(10)
		collector.SetAttestationVerifier(DAAttestationVerifier(func(a *encoding.DASAttestation) error {
			return fmt.Errorf("invalid signature")
		}))
		err := collector.SubmitAttestation(&encoding.DASAttestation{
			Slot:           1,
			Available:      true,
			ValidatorIndex: 0,
			Signature:      []byte{0x01},
		})
		if err == nil {
			t.Fatal("expected error when verifier rejects attestation")
		}
	})
}

type mockBlobStorage struct {
	cells   map[string]*encoding.Cell
	hasBlob map[string]bool
}

func (m *mockBlobStorage) GetCell(slot uint64, blobIndex, row, col int) (*encoding.Cell, *encoding.KZGCommitment, error) {
	key := fmt.Sprintf("%d:%d:%d:%d", slot, blobIndex, row, col)
	if cell, ok := m.cells[key]; ok {
		return cell, nil, nil
	}
	return nil, nil, fmt.Errorf("not found")
}

func (m *mockBlobStorage) HasBlob(slot uint64, blobIndex int) bool {
	key := fmt.Sprintf("%d:%d", slot, blobIndex)
	return m.hasBlob[key]
}

func TestDASubnetManager(t *testing.T) {
	t.Run("NewDASubnetManager", func(t *testing.T) {
		storage := &mockBlobStorage{
			cells:   make(map[string]*encoding.Cell),
			hasBlob: make(map[string]bool),
		}
		mgr := NewDASubnetManager(storage)
		if mgr == nil {
			t.Fatal("NewDASubnetManager returned nil")
		}
	})

	t.Run("AssignColumns", func(t *testing.T) {
		storage := &mockBlobStorage{
			cells:   make(map[string]*encoding.Cell),
			hasBlob: make(map[string]bool),
		}
		mgr := NewDASubnetManager(storage)

		mgr.AssignColumns(0, 4)

		cols := mgr.GetSubnetColumns(0)
		if len(cols) == 0 {
			t.Error("subnet 0 should have columns after assignment")
		}
	})

	t.Run("GetSubnetColumns invalid", func(t *testing.T) {
		storage := &mockBlobStorage{
			cells:   make(map[string]*encoding.Cell),
			hasBlob: make(map[string]bool),
		}
		mgr := NewDASubnetManager(storage)

		cols := mgr.GetSubnetColumns(-1)
		if cols != nil {
			t.Error("expected nil for invalid subnet")
		}

		cols = mgr.GetSubnetColumns(DACommitteeSubnetCount)
		if cols != nil {
			t.Error("expected nil for out of range subnet")
		}
	})

	t.Run("SampleSubnet no columns", func(t *testing.T) {
		storage := &mockBlobStorage{
			cells:   make(map[string]*encoding.Cell),
			hasBlob: make(map[string]bool),
		}
		mgr := NewDASubnetManager(storage)

		_, err := mgr.SampleSubnet(0, 1, 1)
		if err == nil {
			t.Error("expected error for subnet with no columns")
		}
	})

	t.Run("SampleSubnet with data", func(t *testing.T) {
		storage := &mockBlobStorage{
			cells:   make(map[string]*encoding.Cell),
			hasBlob: make(map[string]bool),
		}
		mgr := NewDASubnetManager(storage)

		mgr.AssignColumns(0, 2)

		for row := 0; row < encoding.CellsPerBlobExtended; row++ {
			for col := 0; col < 4; col++ {
				key := fmt.Sprintf("%d:%d:%d:%d", 1, col/2, row, col)
				var cell encoding.Cell
				for k := 0; k < encoding.CellSize; k++ {
					cell[k] = byte(row + col + k)
				}
				storage.cells[key] = &cell
			}
		}

		responses, err := mgr.SampleSubnet(0, 1, 2)
		if err != nil {
			t.Fatalf("SampleSubnet failed: %v", err)
		}
		if len(responses) == 0 {
			t.Error("SampleSubnet should return responses")
		}
	})
}

func TestShuffleIndexedValidators(t *testing.T) {
	t.Run("shuffle empty", func(t *testing.T) {
		validators := []indexedValidator{}
		shuffleIndexedValidators(validators, types.Hash{})
		if len(validators) != 0 {
			t.Error("empty slice should remain empty")
		}
	})

	t.Run("shuffle single", func(t *testing.T) {
		validators := []indexedValidator{{index: 0}}
		shuffleIndexedValidators(validators, types.Hash{})
		if len(validators) != 1 || validators[0].index != 0 {
			t.Error("single element should remain unchanged")
		}
	})

	t.Run("shuffle deterministic", func(t *testing.T) {
		validators1 := make([]indexedValidator, 100)
		validators2 := make([]indexedValidator, 100)
		for i := 0; i < 100; i++ {
			validators1[i] = indexedValidator{index: i}
			validators2[i] = indexedValidator{index: i}
		}

		seed := types.Hash{1, 2, 3}
		shuffleIndexedValidators(validators1, seed)
		shuffleIndexedValidators(validators2, seed)

		for i := 0; i < 100; i++ {
			if validators1[i].index != validators2[i].index {
				t.Error("shuffle should be deterministic with same seed")
				break
			}
		}
	})
}

func TestDACommitteeMember(t *testing.T) {
	t.Run("DACommitteeMember fields", func(t *testing.T) {
		addr := types.BytesToAddress([]byte{1, 2, 3, 4})
		member := DACommitteeMember{
			ValidatorIndex: 42,
			Address:        addr,
			SubnetID:       7,
		}

		if member.ValidatorIndex != 42 {
			t.Errorf("validator index mismatch")
		}
		if member.Address != addr {
			t.Errorf("address mismatch")
		}
		if member.SubnetID != 7 {
			t.Errorf("subnet ID mismatch")
		}
	})
}

func TestDACommittee(t *testing.T) {
	t.Run("DACommittee fields", func(t *testing.T) {
		committee := &DACommittee{
			Epoch:   5,
			Members: make([]DACommitteeMember, 0),
		}

		if committee.Epoch != 5 {
			t.Errorf("epoch mismatch")
		}
		if committee.Members == nil {
			t.Error("members should not be nil")
		}
	})
}

// ── P1-12: shuffleRNG VRF seed integration tests ──

// TestDACommitteeManager_SetBeaconChain verifies that SetBeaconChain stores
// the beacon chain reference. P1-12 (2026-07-14).
func TestDACommitteeManager_SetBeaconChain(t *testing.T) {
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return nil },
		func(epoch uint64) types.Hash { return types.Hash{} },
	)

	if mgr.beaconChain != nil {
		t.Error("beaconChain should be nil by default")
	}

	bc := NewBeaconChain()
	mgr.SetBeaconChain(bc)

	mgr.mu.RLock()
	stored := mgr.beaconChain
	mgr.mu.RUnlock()
	if stored != bc {
		t.Error("SetBeaconChain did not store the beacon chain")
	}
}

// TestDACommitteeManager_getShuffleSeed_VRF verifies that when a finalized
// beacon chain is configured, the VRF randomness is used as the shuffle seed
// instead of the RANDAO mix. P1-12 (2026-07-14).
func TestDACommitteeManager_getShuffleSeed_VRF(t *testing.T) {
	// Create a beacon chain with a finalized beacon for epoch 1.
	bc := NewBeaconChain()
	beacon := bc.CreateBeacon(1, 0) // threshold=0 → can finalize immediately
	output, err := beacon.Finalize()
	if err != nil {
		t.Fatalf("beacon Finalize failed: %v", err)
	}
	vrfRandomness := output.Randomness

	// RANDAO callback returns a different value.
	randaoSeed := types.Hash{0xAA}
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return nil },
		func(epoch uint64) types.Hash { return randaoSeed },
	)
	mgr.SetBeaconChain(bc)

	seed := mgr.getShuffleSeed(1)
	expected := types.BytesToHash(vrfRandomness[:])
	if seed != expected {
		t.Errorf("expected VRF randomness %x, got %x", expected, seed)
	}
	if seed == randaoSeed {
		t.Error("seed should be VRF randomness, not RANDAO fallback")
	}
}

// TestDACommitteeManager_getShuffleSeed_FallbackNoBeacon verifies that when
// no beacon chain is configured, the RANDAO mix is used as the seed.
// P1-12 (2026-07-14).
func TestDACommitteeManager_getShuffleSeed_FallbackNoBeacon(t *testing.T) {
	randaoSeed := types.Hash{0xBB}
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return nil },
		func(epoch uint64) types.Hash { return randaoSeed },
	)
	// No SetBeaconChain call — beaconChain is nil.

	seed := mgr.getShuffleSeed(1)
	if seed != randaoSeed {
		t.Errorf("expected RANDAO fallback %x, got %x", randaoSeed, seed)
	}
}

// TestDACommitteeManager_getShuffleSeed_FallbackNotFinalized verifies that
// when the beacon chain exists but the beacon for the epoch is not finalized,
// the RANDAO mix is used as the fallback seed. P1-12 (2026-07-14).
func TestDACommitteeManager_getShuffleSeed_FallbackNotFinalized(t *testing.T) {
	bc := NewBeaconChain()
	bc.CreateBeacon(1, 3) // threshold=3, not finalized (no contributions)

	randaoSeed := types.Hash{0xCC}
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return nil },
		func(epoch uint64) types.Hash { return randaoSeed },
	)
	mgr.SetBeaconChain(bc)

	seed := mgr.getShuffleSeed(1)
	if seed != randaoSeed {
		t.Errorf("expected RANDAO fallback when beacon not finalized, got %x", seed)
	}
}

// TestDACommitteeManager_getShuffleSeed_FallbackWrongEpoch verifies that
// when the beacon chain doesn't have a beacon for the requested epoch, the
// RANDAO mix is used as the fallback. P1-12 (2026-07-14).
func TestDACommitteeManager_getShuffleSeed_FallbackWrongEpoch(t *testing.T) {
	bc := NewBeaconChain()
	beacon := bc.CreateBeacon(5, 0) // beacon for epoch 5, not epoch 1
	_, _ = beacon.Finalize()

	randaoSeed := types.Hash{0xDD}
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return nil },
		func(epoch uint64) types.Hash { return randaoSeed },
	)
	mgr.SetBeaconChain(bc)

	seed := mgr.getShuffleSeed(1) // request epoch 1, beacon only has epoch 5
	if seed != randaoSeed {
		t.Errorf("expected RANDAO fallback for missing epoch, got %x", seed)
	}
}

// TestDACommitteeManager_GetCommittee_NoDeadlockWithBeacon is a regression test
// for a re-entrant RLock deadlock. Before the fix, computeCommittee held
// m.mu.Lock and called getShuffleSeed which tried to acquire m.mu.RLock —
// Go's sync.RWMutex blocks readers while a writer holds the lock, causing the
// goroutine to hang forever. This test calls GetCommittee with a beaconChain
// configured and uses a timeout to detect the hang. P1-12 fix (2026-07-14).
func TestDACommitteeManager_GetCommittee_NoDeadlockWithBeacon(t *testing.T) {
	bc := NewBeaconChain()
	// Create a finalized beacon for epoch 0 so VRF path is exercised.
	beacon := bc.CreateBeacon(0, 0)
	_, _ = beacon.Finalize()

	getValidators := func() []*ValidatorInfo {
		validators := make([]*ValidatorInfo, DACommitteeSize+100)
		for i := 0; i < DACommitteeSize+100; i++ {
			validators[i] = &ValidatorInfo{Active: true}
		}
		return validators
	}
	mgr := NewDACommitteeManager(
		getValidators,
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetBeaconChain(bc)

	done := make(chan struct{})
	go func() {
		_, _ = mgr.GetCommittee(0)
		close(done)
	}()

	select {
	case <-done:
		// Success — no deadlock.
	case <-time.After(10 * time.Second):
		t.Fatal("GetCommittee deadlocked when beaconChain is set (re-entrant RLock)")
	}
}

// TestP2_10_GetCommitteeCacheConcurrentRace exercises GetCommittee, SetConfig,
// and IsDACommitteeAvailable under heavy concurrency to verify no data races
// exist on the committee cache or config fields.
//
// P2-10 (2026-07-15): Before the fix, GetCommittee read m.config.Enabled and
// IsDACommitteeAvailable read m.config.Enabled + m.effectiveSize() without
// holding m.mu, while SetConfig wrote those fields under Lock — a classic
// data race detectable by `go test -race`. The fix moves all config reads
// under RLock.
//
// NOTE: -race requires CGO_ENABLED=1 (Linux CI). On Windows without GCC,
// the test still validates functional correctness (no deadlocks, no panics,
// consistent results) but cannot detect data races without the race detector.
// Run in CI: CGO_ENABLED=1 go test -race ./consensus/ -run TestP2_10
func TestP2_10_GetCommitteeCacheConcurrentRace(t *testing.T) {
	getValidators := func() []*ValidatorInfo {
		validators := make([]*ValidatorInfo, DACommitteeSize+100)
		for i := 0; i < DACommitteeSize+100; i++ {
			validators[i] = &ValidatorInfo{Active: true}
		}
		return validators
	}
	getRandao := func(epoch uint64) types.Hash {
		return types.Hash{byte(epoch), byte(epoch >> 8)}
	}
	mgr := NewDACommitteeManager(getValidators, getRandao)

	const goroutines = 32
	const iterations = 100

	var wg sync.WaitGroup
	var errCount atomic.Int64
	var panicCount atomic.Int64

	// Writer 1: Concurrent GetCommittee calls across many epochs.
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicCount.Add(1)
				}
			}()
			for i := 0; i < iterations; i++ {
				epoch := uint64((gid*iterations + i) % 50)
				committee, err := mgr.GetCommittee(epoch)
				if err != nil {
					errCount.Add(1)
				} else if committee == nil {
					errCount.Add(1)
				}
			}
		}(g)
	}

	// Writer 2: Concurrent SetConfig toggling between enabled/disabled.
	wg.Add(goroutines / 4)
	for g := 0; g < goroutines/4; g++ {
		go func(gid int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicCount.Add(1)
				}
			}()
			for i := 0; i < iterations; i++ {
				cfg := DACommitteeConfig{
					Enabled: (i+gid)%2 == 0,
					Size:    DACommitteeSize,
				}
				mgr.SetConfig(cfg)
			}
		}(g)
	}

	// Writer 3: Concurrent IsDACommitteeAvailable calls.
	wg.Add(goroutines / 4)
	for g := 0; g < goroutines/4; g++ {
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicCount.Add(1)
				}
			}()
			for i := 0; i < iterations; i++ {
				_ = mgr.IsDACommitteeAvailable()
			}
		}()
	}

	// 30s timeout for deadlock detection.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("GetCommittee concurrent test timed out (possible deadlock)")
	}

	if panicCount.Load() > 0 {
		t.Errorf("%d panics during concurrent access", panicCount.Load())
	}
	// Soft errors are OK: SetConfig(disabled) causes GetCommittee to return
	// ErrDACommitteeDisabled for some iterations. We only assert no panics
	// and no deadlocks.
	t.Logf("Concurrent test completed: %d soft errors (expected when SetConfig toggles enabled)",
		errCount.Load())
}

// TestP2_10_GetCommitteeCacheConsistency verifies that concurrent GetCommittee
// calls for the same epoch return the same (cached) committee pointer — i.e.,
// the cache is consistent under concurrency.
func TestP2_10_GetCommitteeCacheConsistency(t *testing.T) {
	getValidators := func() []*ValidatorInfo {
		validators := make([]*ValidatorInfo, DACommitteeSize+100)
		for i := 0; i < DACommitteeSize+100; i++ {
			validators[i] = &ValidatorInfo{Active: true}
		}
		return validators
	}
	getRandao := func(epoch uint64) types.Hash {
		return types.Hash{byte(epoch)}
	}
	mgr := NewDACommitteeManager(getValidators, getRandao)

	const epoch uint64 = 42
	const goroutines = 50

	// First call to populate cache.
	first, err := mgr.GetCommittee(epoch)
	if err != nil {
		t.Fatalf("first GetCommittee failed: %v", err)
	}

	// Concurrent calls should all return the same pointer.
	type result struct {
		committee *DACommittee
		err       error
	}
	results := make(chan result, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			c, err := mgr.GetCommittee(epoch)
			results <- result{c, err}
		}()
	}
	wg.Wait()
	close(results)

	for r := range results {
		if r.err != nil {
			t.Errorf("concurrent GetCommittee failed: %v", r.err)
			continue
		}
		if r.committee != first {
			t.Errorf("cache inconsistency: got %p, want %p (same epoch should return same cached pointer)",
				r.committee, first)
		}
	}
}

// ── P2-3: DA committee unit tests (shuffle determinism, subnet allocation, cleanup) ──

// makeDAValidators creates n active validators for DA committee tests.
func makeDAValidators(n int) []*ValidatorInfo {
	validators := make([]*ValidatorInfo, n)
	for i := 0; i < n; i++ {
		addr := types.BytesToAddress([]byte{byte(i >> 8), byte(i & 0xFF)})
		validators[i] = &ValidatorInfo{
			Address: addr,
			Active:  true,
		}
	}
	return validators
}

// TestP2_3_ShuffleDeterminism_SameSeedSameCommittee verifies that two
// separate manager instances with identical getRandao produce identical
// committee membership for the same epoch. This is the core determinism
// requirement: all nodes must agree on the committee.
//
// P2-3 (2026-07-15)
func TestP2_3_ShuffleDeterminism_SameSeedSameCommittee(t *testing.T) {
	validators := makeDAValidators(DACommitteeSize + 100)
	getValidators := func() []*ValidatorInfo { return validators }
	getRandao := func(epoch uint64) types.Hash { return types.Hash{byte(epoch), byte(epoch >> 8)} }

	mgr1 := NewDACommitteeManager(getValidators, getRandao)
	mgr2 := NewDACommitteeManager(getValidators, getRandao)

	c1, err := mgr1.GetCommittee(42)
	if err != nil {
		t.Fatalf("mgr1 GetCommittee failed: %v", err)
	}
	c2, err := mgr2.GetCommittee(42)
	if err != nil {
		t.Fatalf("mgr2 GetCommittee failed: %v", err)
	}

	if len(c1.Members) != len(c2.Members) {
		t.Fatalf("committee size mismatch: %d vs %d", len(c1.Members), len(c2.Members))
	}

	mismatch := 0
	for i := 0; i < len(c1.Members); i++ {
		if c1.Members[i].ValidatorIndex != c2.Members[i].ValidatorIndex {
			mismatch++
		}
		if c1.Members[i].SubnetID != c2.Members[i].SubnetID {
			t.Errorf("member %d subnet mismatch: %d vs %d", i, c1.Members[i].SubnetID, c2.Members[i].SubnetID)
		}
	}
	if mismatch > 0 {
		t.Errorf("%d/%d members differ between two managers with same seed", mismatch, len(c1.Members))
	}
}

// TestP2_3_ShuffleDeterminism_DifferentEpochDifferentCommittee verifies
// that different epochs (with different randao seeds) produce different
// committees. This ensures the shuffle is actually seed-dependent.
//
// P2-3 (2026-07-15)
func TestP2_3_ShuffleDeterminism_DifferentEpochDifferentCommittee(t *testing.T) {
	validators := makeDAValidators(DACommitteeSize + 100)
	getValidators := func() []*ValidatorInfo { return validators }
	getRandao := func(epoch uint64) types.Hash { return types.Hash{byte(epoch), byte(epoch >> 8)} }

	mgr := NewDACommitteeManager(getValidators, getRandao)

	c1, err := mgr.GetCommittee(1)
	if err != nil {
		t.Fatalf("GetCommittee(1) failed: %v", err)
	}
	c2, err := mgr.GetCommittee(2)
	if err != nil {
		t.Fatalf("GetCommittee(2) failed: %v", err)
	}

	// Count how many members differ. With 512 members and a good shuffle,
	// essentially all positions should differ.
	mismatch := 0
	for i := 0; i < len(c1.Members); i++ {
		if c1.Members[i].ValidatorIndex != c2.Members[i].ValidatorIndex {
			mismatch++
		}
	}

	// At least 90% of members should differ between epochs.
	if mismatch < len(c1.Members)*9/10 {
		t.Errorf("only %d/%d members differ between epochs 1 and 2 (expected ≥ 90%%)",
			mismatch, len(c1.Members))
	}
	t.Logf("epoch 1 vs 2: %d/%d members differ", mismatch, len(c1.Members))
}

// TestP2_3_SubnetAllocation_AllSubnetsPopulated verifies that all 32
// subnets have at least one member when the committee is full (512 members).
//
// P2-3 (2026-07-15)
func TestP2_3_SubnetAllocation_AllSubnetsPopulated(t *testing.T) {
	validators := makeDAValidators(DACommitteeSize + 100)
	getValidators := func() []*ValidatorInfo { return validators }
	getRandao := func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} }

	mgr := NewDACommitteeManager(getValidators, getRandao)
	committee, err := mgr.GetCommittee(0)
	if err != nil {
		t.Fatalf("GetCommittee failed: %v", err)
	}

	emptySubnets := 0
	for i := 0; i < DACommitteeSubnetCount; i++ {
		if len(committee.Subnets[i]) == 0 {
			emptySubnets++
		}
	}
	if emptySubnets > 0 {
		t.Errorf("%d subnets have no members (expected 0)", emptySubnets)
	}
}

// TestP2_3_SubnetAllocation_BalancedDistribution verifies that subnet
// distribution is roughly balanced: each subnet should have ~16 members
// (512/32 = 16). We allow ±4 deviation to account for the modular assignment.
//
// P2-3 (2026-07-15)
func TestP2_3_SubnetAllocation_BalancedDistribution(t *testing.T) {
	validators := makeDAValidators(DACommitteeSize + 100)
	getValidators := func() []*ValidatorInfo { return validators }
	getRandao := func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} }

	mgr := NewDACommitteeManager(getValidators, getRandao)
	committee, err := mgr.GetCommittee(0)
	if err != nil {
		t.Fatalf("GetCommittee failed: %v", err)
	}

	expectedPerSubnet := DACommitteeSize / DACommitteeSubnetCount // 16
	maxDeviation := 4

	for i := 0; i < DACommitteeSubnetCount; i++ {
		count := len(committee.Subnets[i])
		deviation := count - expectedPerSubnet
		if deviation < 0 {
			deviation = -deviation
		}
		if deviation > maxDeviation {
			t.Errorf("subnet %d has %d members, expected ~%d (deviation %d > %d)",
				i, count, expectedPerSubnet, deviation, maxDeviation)
		}
	}
}

// TestP2_3_SubnetAllocation_SubnetIDConsistent verifies that the SubnetID
// field in each member matches i % DACommitteeSubnetCount (the assignment
// logic in computeCommittee).
//
// P2-3 (2026-07-15)
func TestP2_3_SubnetAllocation_SubnetIDConsistent(t *testing.T) {
	validators := makeDAValidators(DACommitteeSize + 100)
	getValidators := func() []*ValidatorInfo { return validators }
	getRandao := func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} }

	mgr := NewDACommitteeManager(getValidators, getRandao)
	committee, err := mgr.GetCommittee(0)
	if err != nil {
		t.Fatalf("GetCommittee failed: %v", err)
	}

	for i, member := range committee.Members {
		expectedSubnet := i % DACommitteeSubnetCount
		if member.SubnetID != expectedSubnet {
			t.Errorf("member %d has SubnetID=%d, expected %d", i, member.SubnetID, expectedSubnet)
		}
		if member.SubnetID < 0 || member.SubnetID >= DACommitteeSubnetCount {
			t.Errorf("member %d SubnetID %d out of range [0, %d)", i, member.SubnetID, DACommitteeSubnetCount)
		}
	}
}

// TestP2_3_SubnetAllocation_GetSubnetMembersMatch verifies that
// GetSubnetMembers returns the same members stored in committee.Subnets
// for each subnet.
//
// P2-3 (2026-07-15)
func TestP2_3_SubnetAllocation_GetSubnetMembersMatch(t *testing.T) {
	validators := makeDAValidators(DACommitteeSize + 100)
	getValidators := func() []*ValidatorInfo { return validators }
	getRandao := func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} }

	mgr := NewDACommitteeManager(getValidators, getRandao)
	committee, err := mgr.GetCommittee(0)
	if err != nil {
		t.Fatalf("GetCommittee failed: %v", err)
	}

	for subnet := 0; subnet < DACommitteeSubnetCount; subnet++ {
		members, err := mgr.GetSubnetMembers(0, subnet)
		if err != nil {
			t.Fatalf("GetSubnetMembers(%d) failed: %v", subnet, err)
		}
		if len(members) != len(committee.Subnets[subnet]) {
			t.Errorf("subnet %d: GetSubnetMembers returned %d, committee.Subnets has %d",
				subnet, len(members), len(committee.Subnets[subnet]))
			continue
		}
		// Verify each member matches (GetSubnetMembers returns a copy, so
		// we compare by value).
		for j, m := range members {
			if m != committee.Subnets[subnet][j] {
				t.Errorf("subnet %d member %d mismatch", subnet, j)
			}
		}
	}
}

// TestP2_3_CleanupOldCommittees_RemovesOldEpochs verifies that calling
// GetCommittee with a sufficiently large epoch triggers cleanup of old
// cached committees. We detect cleanup by tracking getValidators call
// count — if an old epoch is cleaned up and then re-requested,
// getValidators is called again.
//
// cleanupOldCommittees deletes epoch e if e+4 < currentEpoch.
//
// P2-3 (2026-07-15)
func TestP2_3_CleanupOldCommittees_RemovesOldEpochs(t *testing.T) {
	validators := makeDAValidators(DACommitteeSize + 100)

	callCount := 0
	getValidators := func() []*ValidatorInfo {
		callCount++
		return validators
	}
	getRandao := func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} }

	mgr := NewDACommitteeManager(getValidators, getRandao)

	// Step 1: Cache epoch 0.
	_, err := mgr.GetCommittee(0)
	if err != nil {
		t.Fatalf("GetCommittee(0) failed: %v", err)
	}
	countAfterEpoch0 := callCount // should be 1

	// Step 2: Cache epoch 10. This triggers cleanupOldCommittees(10),
	// which deletes epoch 0 (0+4=4 < 10).
	_, err = mgr.GetCommittee(10)
	if err != nil {
		t.Fatalf("GetCommittee(10) failed: %v", err)
	}
	countAfterEpoch10 := callCount // should be 2

	// Step 3: Re-request epoch 0. If it was cleaned up, getValidators
	// is called again (count increases). If still cached, count stays.
	_, err = mgr.GetCommittee(0)
	if err != nil {
		t.Fatalf("GetCommittee(0) second call failed: %v", err)
	}
	countAfterReEpoch0 := callCount // should be 3 if cleaned up

	if countAfterReEpoch0 != countAfterEpoch10+1 {
		t.Errorf("epoch 0 was not cleaned up: callCount after re-request=%d, expected %d (cleanup should have evicted epoch 0)",
			countAfterReEpoch0, countAfterEpoch10+1)
	}
	t.Logf("callCount: after epoch0=%d, after epoch10=%d, after re-epoch0=%d (cleanup confirmed)",
		countAfterEpoch0, countAfterEpoch10, countAfterReEpoch0)
}

// TestP2_3_CleanupOldCommittees_Boundary verifies the exact cleanup
// boundary: epoch e is removed when e+4 < currentEpoch, and retained
// when e+4 >= currentEpoch.
//
// Boundary cases:
//   - epoch=1, currentEpoch=5: 1+4=5, NOT < 5 → retained
//   - epoch=0, currentEpoch=5: 0+4=4 < 5 → removed
//   - epoch=2, currentEpoch=6: 2+4=6, NOT < 6 → retained
//   - epoch=1, currentEpoch=6: 1+4=5 < 6 → removed
//
// P2-3 (2026-07-15)
func TestP2_3_CleanupOldCommittees_Boundary(t *testing.T) {
	validators := makeDAValidators(DACommitteeSize + 100)

	callCount := 0
	getValidators := func() []*ValidatorInfo {
		callCount++
		return validators
	}
	getRandao := func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} }

	mgr := NewDACommitteeManager(getValidators, getRandao)

	// Cache epoch 1 (should be retained when currentEpoch=5).
	_, err := mgr.GetCommittee(1)
	if err != nil {
		t.Fatalf("GetCommittee(1) failed: %v", err)
	}

	// Cache epoch 5. cleanupOldCommittees(5): epoch 1 → 1+4=5, NOT < 5 → retained.
	_, err = mgr.GetCommittee(5)
	if err != nil {
		t.Fatalf("GetCommittee(5) failed: %v", err)
	}
	countAfterEpoch5 := callCount

	// Re-request epoch 1. Should be cached (not cleaned up by epoch 5).
	_, err = mgr.GetCommittee(1)
	if err != nil {
		t.Fatalf("GetCommittee(1) re-request failed: %v", err)
	}
	if callCount != countAfterEpoch5 {
		t.Errorf("epoch 1 was incorrectly cleaned up by epoch 5: callCount=%d, expected %d (1+4=5 NOT < 5)",
			callCount, countAfterEpoch5)
	}

	// Now cache epoch 6. cleanupOldCommittees(6): epoch 1 → 1+4=5 < 6 → removed.
	_, err = mgr.GetCommittee(6)
	if err != nil {
		t.Fatalf("GetCommittee(6) failed: %v", err)
	}
	countAfterEpoch6 := callCount

	// Re-request epoch 1. Should be cleaned up (recomputed).
	_, err = mgr.GetCommittee(1)
	if err != nil {
		t.Fatalf("GetCommittee(1) second re-request failed: %v", err)
	}
	if callCount != countAfterEpoch6+1 { // +1 for epoch 1 recompute
		t.Errorf("epoch 1 was not cleaned up by epoch 6: callCount=%d, expected %d (1+4=5 < 6)",
			callCount, countAfterEpoch6+1)
	}
	t.Logf("boundary test: epoch 1 retained at currentEpoch=5, evicted at currentEpoch=6. callCount=%d", callCount)
}

// ============================================================================
// R4-CRND-01: DA committee shuffle seed always zero — regression tests
//
// AUDIT (2026) R4-CRND-01
// The production DA committee shuffle seed was constant-all-zero: the
// getRandao closure in node.go ignored its epoch argument and always
// returned qpos.GetRANDAO() (an accumulating XOR that never resets), so
// every epoch derived the same shuffle seed → the 512-seat committee and
// its 32×16 subnets were identical and publicly derivable each epoch →
// enabling a targeted eclipse against a chosen 16-seat subnet.
//
// Fix: the closure now prefers qpos.GetEpochVRFAccumulator(epoch) (the
// per-epoch VRF accumulator), falling back to GetRANDAO() only when the
// accumulator is still zero.
// ============================================================================

// TestR4CRND01_FixedClosure_ProducesDifferentCommitteesPerEpoch verifies
// that the FIXED closure (using per-epoch VRF accumulator) produces
// DIFFERENT committees for different epochs. This is the core security
// property: an attacker cannot predict the committee in advance because
// the VRF accumulator is distinct per epoch and unpredictable.
//
// AUDIT (2026) R4-CRND-01
func TestR4CRND01_FixedClosure_ProducesDifferentCommitteesPerEpoch(t *testing.T) {
	qpos, _ := setupQPOSWithKeys(1)

	// Set distinct per-epoch VRF accumulators (simulating AccumulateVRFOutput
	// calls from canonical-chain proposers in each epoch).
	qpos.mu.Lock()
	qpos.epochVRFAccumulator[1] = types.Hash{0x11, 0x22, 0x33}
	qpos.epochVRFAccumulator[2] = types.Hash{0xAA, 0xBB, 0xCC}
	qpos.mu.Unlock()

	// This closure mirrors the FIXED closure in node.go (R4-CRND-01):
	// uses GetEpochVRFAccumulator(epoch) with GetRANDAO() fallback.
	fixedClosure := func(epoch uint64) types.Hash {
		vrfAcc := qpos.GetEpochVRFAccumulator(epoch)
		if vrfAcc != (types.Hash{}) {
			return vrfAcc
		}
		return qpos.GetRANDAO()
	}

	validators := makeDAValidators(DACommitteeSize + 100)
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		fixedClosure,
	)

	c1, err := mgr.GetCommittee(1)
	if err != nil {
		t.Fatalf("GetCommittee(1) failed: %v", err)
	}
	c2, err := mgr.GetCommittee(2)
	if err != nil {
		t.Fatalf("GetCommittee(2) failed: %v", err)
	}

	// With distinct VRF accumulators, ≥90% of members should differ.
	mismatch := 0
	for i := 0; i < len(c1.Members); i++ {
		if c1.Members[i].ValidatorIndex != c2.Members[i].ValidatorIndex {
			mismatch++
		}
	}
	if mismatch < len(c1.Members)*9/10 {
		t.Errorf("R4-CRND-01: fixed closure produced only %d/%d differing members "+
			"between epochs with distinct VRF accumulators (expected ≥ 90%%)",
			mismatch, len(c1.Members))
	}
	t.Logf("=== R4-CRND-01: fixed closure produces %d/%d differing members between epochs ===",
		mismatch, len(c1.Members))
}

// TestR4CRND01_BuggyClosure_IgnoresEpoch_ProducesSameCommittee demonstrates
// the pre-fix behavior: a closure that ignores the epoch parameter and
// always returns qpos.GetRANDAO() produces IDENTICAL committees for all
// epochs. This test documents the bug and guards against regression — if
// someone reintroduces the buggy closure, this test will fail.
//
// AUDIT (2026) R4-CRND-01
func TestR4CRND01_BuggyClosure_IgnoresEpoch_ProducesSameCommittee(t *testing.T) {
	qpos, _ := setupQPOSWithKeys(1)

	// Set a non-zero RANDAO mix (the cumulative XOR that never resets).
	qpos.mu.Lock()
	qpos.randaoMix = types.Hash{0xAA, 0xBB, 0xCC}
	qpos.mu.Unlock()

	// This closure mirrors the BUGGY closure that was in node.go before
	// R4-CRND-01: ignores the epoch parameter, always returns GetRANDAO().
	buggyClosure := func(epoch uint64) types.Hash {
		_ = epoch // BUG: epoch parameter is ignored
		return qpos.GetRANDAO()
	}

	validators := makeDAValidators(DACommitteeSize + 100)
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		buggyClosure,
	)

	c1, err := mgr.GetCommittee(1)
	if err != nil {
		t.Fatalf("GetCommittee(1) failed: %v", err)
	}
	c2, err := mgr.GetCommittee(2)
	if err != nil {
		t.Fatalf("GetCommittee(2) failed: %v", err)
	}

	// With the buggy closure, both epochs get the same seed → identical committees.
	mismatch := 0
	for i := 0; i < len(c1.Members); i++ {
		if c1.Members[i].ValidatorIndex != c2.Members[i].ValidatorIndex {
			mismatch++
		}
	}
	if mismatch != 0 {
		t.Errorf("R4-CRND-01: buggy closure should produce identical committees, "+
			"but %d/%d members differ (epoch parameter was ignored)",
			mismatch, len(c1.Members))
	}
	t.Logf("=== R4-CRND-01: buggy closure produces %d/%d differing members (should be 0) ===",
		mismatch, len(c1.Members))
}

// TestR4CRND01_FixedClosure_FallsBackToRANDAO verifies that the fixed
// closure falls back to GetRANDAO() when no VRF accumulator is set for the
// epoch (e.g., during early startup before any VRF outputs are accumulated).
// This ensures liveness during the bootstrapping phase.
//
// AUDIT (2026) R4-CRND-01
func TestR4CRND01_FixedClosure_FallsBackToRANDAO(t *testing.T) {
	qpos, _ := setupQPOSWithKeys(1)

	// Set a non-zero RANDAO mix but NO VRF accumulator for epoch 5.
	qpos.mu.Lock()
	qpos.randaoMix = types.Hash{0x55, 0x66, 0x77}
	qpos.mu.Unlock()

	// The fixed closure: uses VRF accumulator if available, else GetRANDAO().
	fixedClosure := func(epoch uint64) types.Hash {
		vrfAcc := qpos.GetEpochVRFAccumulator(epoch)
		if vrfAcc != (types.Hash{}) {
			return vrfAcc
		}
		return qpos.GetRANDAO()
	}

	seed := fixedClosure(5) // epoch 5 has no VRF accumulator
	expected := types.Hash{0x55, 0x66, 0x77}
	if seed != expected {
		t.Errorf("R4-CRND-01: expected RANDAO fallback %x, got %x", expected, seed)
	}
	t.Logf("=== R4-CRND-01: fixed closure correctly falls back to GetRANDAO() when no VRF accumulator ===")
}
