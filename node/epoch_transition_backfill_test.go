// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

type epochTransitionTestSigner struct {
	groupKey []byte
}

func (s *epochTransitionTestSigner) SignBlock(int, []byte) ([]byte, error) { return nil, nil }
func (s *epochTransitionTestSigner) SignVote(int, []byte) ([]byte, error)  { return nil, nil }
func (s *epochTransitionTestSigner) VerifyBlock([]byte, []byte, []byte) bool {
	return false
}
func (s *epochTransitionTestSigner) VerifyVote([]byte, []byte, []byte) bool { return false }
func (s *epochTransitionTestSigner) GroupPublicKey() []byte {
	return append([]byte(nil), s.groupKey...)
}
func (s *epochTransitionTestSigner) IsThresholdMode() bool { return true }

// Threshold implements consensus.ThresholdKeySigner. Returning 0 keeps the
// chamber-based quorum unchanged for this mock.
func (s *epochTransitionTestSigner) Threshold() int { return 0 }

func (s *epochTransitionTestSigner) AggregatePartialSignatures([]int, map[int][]byte, []byte) ([]byte, error) {
	return nil, nil
}

type epochTransitionTestRunner struct {
	started chan struct{}
	release chan struct{}
	key     []byte

	mu    sync.Mutex
	calls int
}

func (r *epochTransitionTestRunner) RunDistributedDKG(uint64, int, int) ([]byte, error) {
	return r.key, nil
}

func (r *epochTransitionTestRunner) RunDistributedReshare(uint64, []int, []int, int) ([]byte, error) {
	r.mu.Lock()
	r.calls++
	first := r.calls == 1
	r.mu.Unlock()
	if first {
		close(r.started)
	}
	<-r.release
	return r.key, nil
}

func (r *epochTransitionTestRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func newEpochTransitionTestBlockProducer(t *testing.T) (*BlockProducer, *consensus.QPOS, *consensus.ThreeChambersCoordinator, *epochTransitionTestRunner) {
	t.Helper()
	validators := make([]*consensus.Validator, 9)
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
	qpos.InitChambers()

	groupKey := bytes.Repeat([]byte{0x42}, crypto.Dilithium3PublicKeySize)
	qpos.SetThresholdSigner(&epochTransitionTestSigner{groupKey: groupKey})
	runner := &epochTransitionTestRunner{
		started: make(chan struct{}),
		release: make(chan struct{}),
		key:     groupKey,
	}
	coordinator := qpos.GetChambersCoordinator()
	coordinator.SetRequireDistributedDKG(true)
	coordinator.SetDistributedDKGRunner(runner)
	return &BlockProducer{qpos: qpos}, qpos, coordinator, runner
}

func TestEnsureEpochStateForBlockTransitionsAfterMissedBoundary(t *testing.T) {
	bp, qpos, coordinator, runner := newEpochTransitionTestBlockProducer(t)
	defer close(runner.release)

	bp.ensureEpochStateForBlock(&encoding.BlockHeader{
		Slot:       consensus.SlotsPerEpoch + 1,
		Epoch:      1,
		ParentHash: types.Hash{0xA1},
	})

	select {
	case <-runner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("reshare did not start for the first non-boundary block of the epoch")
	}
	if !qpos.HasEpochRoot(1) {
		t.Fatal("epoch root was not backfilled for the missed boundary slot")
	}
	executive := coordinator.GetExecutiveChamber()
	if executive.Epoch() != 1 {
		t.Fatalf("executive epoch = %d, want 1", executive.Epoch())
	}

	bp.ensureEpochStateForBlock(&encoding.BlockHeader{
		Slot:       consensus.SlotsPerEpoch + 2,
		Epoch:      1,
		ParentHash: types.Hash{0xA2},
	})
	if got := runner.callCount(); got != 1 {
		t.Fatalf("reshare calls = %d, want 1 for repeated blocks in the same epoch", got)
	}
}
