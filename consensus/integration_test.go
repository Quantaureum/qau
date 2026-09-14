// Quantaureum Node source, version 1.0.0.
//go:build integration

package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func makeTestValidatorSet(n int) (*ValidatorSet, error) {
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
	return NewValidatorSet(vals)
}

func TestQPOS_EpochTransition(t *testing.T) {
	vs, err := makeTestValidatorSet(5)
	if err != nil {
		t.Fatalf("makeTestValidatorSet: %v", err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	epoch0 := qpos.GetCurrentEpoch()
	if epoch0 != 0 {
		t.Errorf("expected initial epoch 0, got %d", epoch0)
	}

	summary := qpos.GetEpochSummary(0)
	if summary == nil {
		t.Error("expected epoch 0 summary")
	}
}

func TestQPOS_FinalityAdvancement(t *testing.T) {
	vs, err := makeTestValidatorSet(5)
	if err != nil {
		t.Fatalf("makeTestValidatorSet: %v", err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	justified, finalized, _ := qpos.CheckFinality()
	_ = justified
	_ = finalized

	slot := qpos.GetCurrentSlot()
	t.Logf("current slot: %d", slot)
}

func TestQPOS_ProposerSelection(t *testing.T) {
	vs, err := makeTestValidatorSet(5)
	if err != nil {
		t.Fatalf("makeTestValidatorSet: %v", err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	proposer, err := qpos.GetProposerForSlot(1)
	if err != nil {
		t.Fatalf("GetProposerForSlot: %v", err)
	}
	if proposer == nil {
		t.Fatal("expected a proposer for slot 1")
	}

	if !proposer.Active {
		t.Error("proposer should be active")
	}
}

func TestQPOS_CommitteeSelection(t *testing.T) {
	vs, err := makeTestValidatorSet(5)
	if err != nil {
		t.Fatalf("makeTestValidatorSet: %v", err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	committee, err := qpos.GetCommitteeForSlot(1)
	if err != nil {
		t.Fatalf("GetCommitteeForSlot: %v", err)
	}
	if len(committee) == 0 {
		t.Error("expected non-empty committee")
	}
}

func TestValidatorQueue_EpochProcessing(t *testing.T) {
	vq := NewValidatorQueue()

	var addr1, addr2, addr3 types.Address
	addr1[0] = 1
	addr2[0] = 2
	addr3[0] = 3

	minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))

	if err := vq.RegisterValidator(addr1, addr1, minStake, addr1, 0); err != nil {
		t.Fatalf("RegisterValidator addr1: %v", err)
	}
	if err := vq.RegisterValidator(addr2, addr2, minStake, addr2, 0); err != nil {
		t.Fatalf("RegisterValidator addr2: %v", err)
	}

	activated, exited, activatedAddrs := vq.ProcessEpoch(ValidatorActivationDelay)
	if activated != 2 {
		t.Errorf("expected 2 activated validators, got %d", activated)
	}
	if exited != 0 {
		t.Errorf("expected 0 exited validators, got %d", exited)
	}
	if len(activatedAddrs) != 2 {
		t.Errorf("expected 2 activated addresses, got %d", len(activatedAddrs))
	}

	if err := vq.RequestExit(addr1, addr1, ValidatorActivationDelay); err != nil {
		t.Fatalf("RequestExit addr1: %v", err)
	}

	activated, exited, _ = vq.ProcessEpoch(ValidatorActivationDelay + ValidatorExitDelay)
	if activated != 0 {
		t.Errorf("expected 0 activated, got %d", activated)
	}
	if exited != 1 {
		t.Errorf("expected 1 exited, got %d", exited)
	}

	if err := vq.RegisterValidator(addr3, addr3, minStake, addr3, ValidatorActivationDelay); err != nil {
		t.Fatalf("RegisterValidator addr3: %v", err)
	}

	activated, exited, _ = vq.ProcessEpoch(ValidatorActivationDelay * 2)
	if activated != 1 {
		t.Errorf("expected 1 activated, got %d", activated)
	}
}
