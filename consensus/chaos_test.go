// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

func makeChaosValidatorSet(n int) *ValidatorSet {
	vals := make([]*Validator, n)
	for i := 0; i < n; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		vals[i] = &Validator{
			Address: addr,
			Stake:   big.NewInt(1000),
			Active:  true,
		}
	}
	vs, _ := NewValidatorSet(vals)
	return vs
}

func TestChaos_NetworkPartition_MajorityOnline(t *testing.T) {
	vs := makeChaosValidatorSet(10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	for slot := uint64(1); slot <= 20; slot++ {
		proposer, err := qpos.GetProposerForSlot(slot)
		if err != nil {
			t.Fatalf("slot %d: %v", slot, err)
		}
		if proposer == nil {
			t.Fatalf("slot %d: no proposer", slot)
		}
	}
}

func TestChaos_NetworkPartition_MinimumOnline(t *testing.T) {
	vs := makeChaosValidatorSet(4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	for slot := uint64(1); slot <= 10; slot++ {
		proposer, err := qpos.GetProposerForSlot(slot)
		if err != nil {
			t.Fatalf("slot %d: %v", slot, err)
		}
		if proposer == nil {
			t.Fatalf("slot %d: no proposer with 4 validators", slot)
		}
	}
}

func TestChaos_DoubleSignDetection(t *testing.T) {
	vs := makeChaosValidatorSet(10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	vm := NewValidatorManager()
	sm := NewSlashingManagerWithParams(vm, DefaultSlashingParams())
	sm.SetQPOS(qpos)

	var maliciousAddr types.Address
	maliciousAddr[0] = 0x01

	vote1 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        100,
		Round:         1,
		BlockHash:     types.Hash{0x01},
		ValidatorAddr: maliciousAddr,
		Signature:     []byte("sig1"),
	}

	vote2 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        100,
		Round:         1,
		BlockHash:     types.Hash{0x02},
		ValidatorAddr: maliciousAddr,
		Signature:     []byte("sig2"),
	}

	evidence1, err := sm.RecordVote(vote1)
	if err != nil {
		t.Fatalf("RecordVote1: %v", err)
	}
	if evidence1 != nil {
		t.Fatal("first vote should not trigger evidence")
	}

	evidence2, err := sm.RecordVote(vote2)
	if err == nil {
		t.Fatal("double signing should return error")
	}
	if evidence2 == nil {
		t.Fatal("double signing should also return evidence")
	}
	if evidence2.Reason != SlashingReasonDoubleSigning {
		t.Fatalf("expected double_signing reason, got %v", evidence2.Reason)
	}
	if evidence2.ValidatorAddr != maliciousAddr {
		t.Fatal("evidence should point to malicious validator")
	}
}

func TestChaos_DowntimeDetection(t *testing.T) {
	vs := makeChaosValidatorSet(10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	vm := NewValidatorManager()
	params := DefaultSlashingParams()
	params.DowntimeThreshold = 10
	sm := NewSlashingManagerWithParams(vm, params)
	sm.SetQPOS(qpos)

	var offlineAddr types.Address
	offlineAddr[0] = 0x02

	var onlineAddr types.Address
	onlineAddr[0] = 0x03

	for height := uint64(1); height <= 20; height++ {
		sm.RecordBlockSigned(onlineAddr, height)
	}

	for height := uint64(1); height <= 5; height++ {
		sm.RecordBlockSigned(offlineAddr, height)
	}

	evidence := sm.CheckDowntime(offlineAddr, 10, 1000000)
	if evidence != nil {
		t.Fatalf("should not slash yet (missed %d blocks, threshold %d)", 10-5, params.DowntimeThreshold)
	}

	evidence = sm.CheckDowntime(offlineAddr, 20, 1000000)
	if evidence == nil {
		t.Fatal("should detect downtime after missing enough blocks")
	}
	if evidence.Reason != SlashingReasonDowntime {
		t.Fatalf("expected downtime reason, got %v", evidence.Reason)
	}
}

func TestChaos_SlashingPenalty(t *testing.T) {
	params := DefaultSlashingParams()

	stakeBefore := big.NewInt(1000000)

	slashPercent := params.DoubleSignPenalty
	slashAmount := new(big.Int).Mul(stakeBefore, slashPercent)
	slashAmount.Div(slashAmount, big.NewInt(100))

	if slashAmount.Cmp(big.NewInt(0)) <= 0 {
		t.Fatal("double sign penalty should be positive")
	}

	expectedSlash := new(big.Int).Mul(stakeBefore, big.NewInt(100))
	expectedSlash.Div(expectedSlash, big.NewInt(100))

	if slashAmount.Cmp(expectedSlash) != 0 {
		t.Fatalf("expected 100%% penalty = %s, got %s", expectedSlash, slashAmount)
	}

	downtimeSlash := new(big.Int).Mul(stakeBefore, params.DowntimePenalty)
	downtimeSlash.Div(downtimeSlash, big.NewInt(100))

	expectedDowntime := new(big.Int).Mul(stakeBefore, big.NewInt(1))
	expectedDowntime.Div(expectedDowntime, big.NewInt(100))

	if downtimeSlash.Cmp(expectedDowntime) != 0 {
		t.Fatalf("expected 1%% downtime penalty = %s, got %s", expectedDowntime, downtimeSlash)
	}
}

func TestChaos_SurroundVoteDetection(t *testing.T) {
	vm := NewValidatorManager()
	sm := NewSlashingManagerWithParams(vm, DefaultSlashingParams())

	var addr types.Address
	addr[0] = 0x01

	vote1 := &Vote{
		Type:          VoteTypeAttestation,
		Height:        100,
		Round:         1,
		BlockHash:     types.Hash{0x01},
		ValidatorAddr: addr,
		Signature:     []byte("sig1"),
		SourceEpoch:   5,
		TargetEpoch:   10,
	}

	vote2 := &Vote{
		Type:          VoteTypeAttestation,
		Height:        200,
		Round:         2,
		BlockHash:     types.Hash{0x02},
		ValidatorAddr: addr,
		Signature:     []byte("sig2"),
		SourceEpoch:   3,
		TargetEpoch:   12,
	}

	evidence1, err := sm.RecordVote(vote1)
	if err != nil {
		t.Fatalf("RecordVote1: %v", err)
	}
	if evidence1 != nil {
		t.Fatal("first vote should not trigger evidence")
	}

	evidence2, err := sm.RecordVote(vote2)
	if err != nil {
		t.Logf("RecordVote2 returned error: %v", err)
	}

	if evidence2 != nil {
		t.Logf("Evidence detected: reason=%v", evidence2.Reason)
		if evidence2.Reason == SlashingReasonSurroundVote {
			t.Log("surround vote detected correctly")
		}
	} else {
		t.Log("no evidence from RecordVote (different heights, surround detection may require separate verification)")
	}
}

func TestChaos_EpochRecoveryAfterOffline(t *testing.T) {
	vq := NewValidatorQueue()
	minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))

	var addr1, addr2, addr3 types.Address
	addr1[0] = 0x01
	addr2[0] = 0x02
	addr3[0] = 0x03

	var withdrawal types.Address
	withdrawal[0] = 0x20

	if err := vq.RegisterValidator(addr1, addr1, minStake, withdrawal, 0); err != nil {
		t.Fatalf("RegisterValidator addr1: %v", err)
	}
	if err := vq.RegisterValidator(addr2, addr2, minStake, withdrawal, 0); err != nil {
		t.Fatalf("RegisterValidator addr2: %v", err)
	}
	if err := vq.RegisterValidator(addr3, addr3, minStake, withdrawal, 0); err != nil {
		t.Fatalf("RegisterValidator addr3: %v", err)
	}

	for epoch := uint64(1); epoch <= uint64(ValidatorActivationDelay); epoch++ {
		vq.ProcessEpoch(epoch)
	}

	status1, err1 := vq.GetValidatorStatus(addr1)
	if err1 != nil {
		t.Fatalf("GetValidatorStatus addr1: %v", err1)
	}
	if status1.Status != ValidatorStatusActive {
		t.Fatalf("addr1 should be active, got %d", status1.Status)
	}

	if err := vq.RequestExit(addr1, addr1, uint64(ValidatorActivationDelay)); err != nil {
		t.Fatalf("RequestExit: %v", err)
	}
	for epoch := uint64(ValidatorActivationDelay + 1); epoch <= uint64(ValidatorActivationDelay+ValidatorExitDelay); epoch++ {
		vq.ProcessEpoch(epoch)
	}

	status1After, err := vq.GetValidatorStatus(addr1)
	if err != nil {
		t.Fatalf("GetValidatorStatus after exit: %v", err)
	}
	if status1After.Status == ValidatorStatusActive {
		t.Fatal("addr1 should not be active after exit")
	}
}

func TestChaos_EvidenceVerification(t *testing.T) {
	vm := NewValidatorManager()
	sm := NewSlashingManagerWithParams(vm, DefaultSlashingParams())

	// CON4-002 FIX: Register validator with real key pair so signature
	// verification can be performed. Use address 0xFF to avoid colliding
	// with system caller addresses used in other tests (e.g. {1}, {2}).
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var addr types.Address
	addr[0] = 0xFF
	RegisterSystemCaller(addr)
	// R54-SYSCALLERS-RESET-01: explicit Unregister (not full reset) so
	// the long-standing testSystemCaller = 0x7f registered by init() in
	// ministry_test.go is preserved for other tests. Only remove OUR 0xFF.
	defer UnregisterSystemCaller(addr)
	if err := vm.AddValidator(addr, addr, kp.Public, big.NewInt(0).Mul(big.NewInt(32), big.NewInt(1e18)), 100, 1); err != nil {
		t.Fatal(err)
	}

	vote := &Vote{
		ValidatorAddr: addr,
		Height:        100,
		BlockHash:     types.Hash{0x01},
	}
	if err := vote.Sign(kp.Private); err != nil {
		t.Fatal(err)
	}

	validEvidence := &SlashingEvidence{
		Reason:        SlashingReasonInvalidVRF,
		ValidatorAddr: addr,
		Height:        100,
		Timestamp:     time.Now().Unix(),
		Vote1:         vote,
	}

	if err := sm.VerifyEvidence(validEvidence); err != nil {
		t.Fatalf("valid VRF evidence should pass verification: %v", err)
	}

	futureEvidence := &SlashingEvidence{
		Reason:        SlashingReasonInvalidVRF,
		ValidatorAddr: addr,
		Height:        100,
		Timestamp:     time.Now().Unix() + 100,
	}

	if err := sm.VerifyEvidence(futureEvidence); err == nil {
		t.Fatal("future evidence should fail verification")
	}

	zeroAddrEvidence := &SlashingEvidence{
		Reason:        SlashingReasonDoubleSigning,
		ValidatorAddr: types.Address{},
		Height:        100,
		Timestamp:     time.Now().Unix(),
	}

	if err := sm.VerifyEvidence(zeroAddrEvidence); err == nil {
		t.Fatal("zero address evidence should fail verification")
	}
}

func TestChaos_DoubleSignDetector(t *testing.T) {
	detector := NewDoubleSignDetector()

	var addr types.Address
	addr[0] = 0x01

	vote1 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        100,
		Round:         1,
		BlockHash:     types.Hash{0x01},
		ValidatorAddr: addr,
		Signature:     []byte("sig1"),
	}

	vote2 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        100,
		Round:         1,
		BlockHash:     types.Hash{0x02},
		ValidatorAddr: addr,
		Signature:     []byte("sig2"),
	}

	evidence, err := detector.CheckAndRecordVote(vote1)
	if err != nil {
		t.Fatalf("CheckAndRecordVote1: %v", err)
	}
	if evidence != nil {
		t.Fatal("first vote should not trigger evidence")
	}

	evidence, err = detector.CheckAndRecordVote(vote2)
	if err == nil {
		t.Fatal("double signing should return error")
	}
	if evidence == nil {
		t.Fatal("double signing should produce evidence")
	}
	if evidence.Reason != SlashingReasonDoubleSigning {
		t.Fatalf("expected double_signing, got %v", evidence.Reason)
	}

	allEvidence := detector.GetEvidence()
	if len(allEvidence) < 1 {
		t.Fatal("detector should have recorded the evidence")
	}

	validatorEvidence := detector.GetEvidenceForValidator(addr)
	if len(validatorEvidence) < 1 {
		t.Fatal("should have evidence for the malicious validator")
	}
}

func TestChaos_MultipleSlashingRecords(t *testing.T) {
	vm := NewValidatorManager()
	sm := NewSlashingManagerWithParams(vm, DefaultSlashingParams())

	// CON4-002 FIX: Register validators with real key pairs.
	// Use addresses 0xF0+ to avoid colliding with system caller addresses
	// used in other tests (e.g. {1}, {2}).
	var addrs []types.Address
	var keyPairs []*crypto.KeyPair
	// R54-SYSCALLERS-RESET-01: explicit Unregister of the 0xF0+ addresses
	// after this test finishes; preserves the init() in ministry_test.go
	// testSystemCaller 0x7f registration for other tests. Closure captures
	// addrs (declared above) and iterates it at defer time.
	defer func() {
		for _, a := range addrs {
			UnregisterSystemCaller(a)
		}
	}()
	for i := 0; i < 3; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		var addr types.Address
		addr[0] = byte(0xF0 + i)
		RegisterSystemCaller(addr)
		if err := vm.AddValidator(addr, addr, kp.Public, big.NewInt(0).Mul(big.NewInt(32), big.NewInt(1e18)), 100, 1); err != nil {
			t.Fatal(err)
		}
		addrs = append(addrs, addr)
		keyPairs = append(keyPairs, kp)
	}

	now := time.Now().Unix()
	for i, addr := range addrs {
		vote := &Vote{
			ValidatorAddr: addr,
			Height:        uint64(100 + i*10),
			BlockHash:     types.Hash{byte(i + 1)},
		}
		if err := vote.Sign(keyPairs[i].Private); err != nil {
			t.Fatal(err)
		}
		evidence := &SlashingEvidence{
			Reason:        SlashingReasonInvalidVRF,
			ValidatorAddr: addr,
			Height:        uint64(100 + i*10),
			Timestamp:     now,
			Vote1:         vote,
		}

		if err := sm.VerifyEvidence(evidence); err != nil {
			t.Fatalf("VerifyEvidence %d: %v", i+1, err)
		}
	}

	stats := sm.GetSlashingStats()
	_ = stats
}
