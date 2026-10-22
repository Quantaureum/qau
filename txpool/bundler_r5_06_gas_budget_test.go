// Quantaureum Node source, version 1.0.0.
package txpool

import (
	"math"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

// R5-06 (2026-10-21 fifth-round audit): buildBundle used to sum an operation's
// three gas fields in uint64 and compare the wrapped total against the block gas
// limit. Validate() bounds only VerificationGasLimit — CallGasLimit and
// PreVerificationGas are arbitrary uint64s decoded from the wire — so two values
// near 2^63 wrapped the claim down to something that fit, and the operation was
// then simulated (account code executed on the live state) and bundled with an
// effectively unbounded gas claim. The budget is now summed in big.Int and
// checked BEFORE the simulation, so an impossible claim never costs a simulation
// at all and is not re-tried every bundle cycle.

// r5GasStateDB is a minimal qvm.StateDB whose only job is to count how many
// simulation frames the bundler opened (beginValidationFrame calls Snapshot once
// per simulated operation).
type r5GasStateDB struct {
	snapshots int
	depth     int
}

func (s *r5GasStateDB) GetBalance(addr qvm.Address) *big.Int          { return new(big.Int) }
func (s *r5GasStateDB) SetBalance(addr qvm.Address, balance *big.Int) {}
func (s *r5GasStateDB) GetNonce(addr qvm.Address) uint64              { return 0 }
func (s *r5GasStateDB) SetNonce(addr qvm.Address, nonce uint64)       {}
func (s *r5GasStateDB) GetCode(addr qvm.Address) []byte               { return nil }
func (s *r5GasStateDB) SetCode(addr qvm.Address, code []byte)         {}
func (s *r5GasStateDB) GetCodeHash(addr qvm.Address) qvm.Hash         { return qvm.Hash{} }
func (s *r5GasStateDB) GetCodeSize(addr qvm.Address) int              { return 0 }
func (s *r5GasStateDB) GetState(addr qvm.Address, key qvm.Hash) qvm.Hash {
	return qvm.Hash{}
}
func (s *r5GasStateDB) SetState(addr qvm.Address, key, value qvm.Hash) {}
func (s *r5GasStateDB) Exist(addr qvm.Address) bool                    { return false }
func (s *r5GasStateDB) Empty(addr qvm.Address) bool                    { return true }
func (s *r5GasStateDB) SelfDestruct(addr qvm.Address)                  {}
func (s *r5GasStateDB) HasSelfDestructed(addr qvm.Address) bool        { return false }

func (s *r5GasStateDB) Snapshot() int {
	s.snapshots++
	id := s.depth
	s.depth++
	return id
}

// RevertToSnapshot mirrors the state stack semantics the bundler relies on.
func (s *r5GasStateDB) RevertToSnapshot(id int) {
	if id < 0 || id > s.depth {
		return
	}
	s.depth = id
}

func (s *r5GasStateDB) AddAddressToAccessList(addr qvm.Address) {}
func (s *r5GasStateDB) AddSlotToAccessList(addr qvm.Address, slot qvm.Hash) {
}
func (s *r5GasStateDB) AddressInAccessList(addr qvm.Address) bool { return false }
func (s *r5GasStateDB) SlotInAccessList(addr qvm.Address, slot qvm.Hash) (bool, bool) {
	return false, false
}

const r5BundleGasLimit = uint64(30000000) // buildBundle's block context limit

// r5GasUserOp builds an operation that passes UserOperation.Validate() with the
// two wire-controlled gas fields set explicitly.
func r5GasUserOp(sender byte, callGas, preGas uint64) *encoding.UserOperation {
	return &encoding.UserOperation{
		Sender:               types.Address{sender},
		Nonce:                uint64(sender),
		CallGasLimit:         callGas,
		VerificationGasLimit: 100000, // capped by Validate()
		PreVerificationGas:   preGas,
		MaxFeePerGas:         big.NewInt(2_000_000_000),
		MaxPriorityFeePerGas: big.NewInt(1_500_000_000),
		Signature:            []byte{0xde, 0xad},
	}
}

// r5GasBundler returns a bundler whose sender accounts have no code, so
// SimulateValidation fails at its codeless-sender guard: every operation the
// budget gate lets through is simulated once and then dropped from the mempool,
// which is exactly the observable the tests below distinguish on.
func r5GasBundler(t *testing.T, ops ...*encoding.UserOperation) (*Bundler, *r5GasStateDB, []types.Hash) {
	t.Helper()

	st := &r5GasStateDB{}
	b := NewBundler(&BundlerConfig{ChainID: 1668}, qvm.NewEntryPoint(nil), nil, st)

	var hashes []types.Hash
	b.mu.Lock()
	for _, uo := range ops {
		h := uo.Hash(qvm.EntryPointAddress, b.chainID)
		entry := &userOpEntry{userOp: uo, hash: h, fee: new(big.Int).Set(uo.MaxPriorityFeePerGas)}
		b.userOpMempool[h] = entry
		hashes = append(hashes, h)
	}
	b.mu.Unlock()
	return b, st, hashes
}

func r5Candidates(b *Bundler, hashes []types.Hash) []*userOpEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	candidates := make([]*userOpEntry, 0, len(hashes))
	for _, h := range hashes {
		if entry, ok := b.userOpMempool[h]; ok {
			candidates = append(candidates, entry)
		}
	}
	return candidates
}

// TestR5_06_WrappedGasClaimIsSkippedBeforeSimulation is the regression pin: the
// wrapped uint64 sum (2^63 + 2^63 + 100000 → 100000) fits the 30M budget, so the
// old code paid a full account-code simulation for it. It must now be rejected
// by the budget gate without any simulation.
func TestR5_06_WrappedGasClaimIsSkippedBeforeSimulation(t *testing.T) {
	uo := r5GasUserOp(0x11, uint64(1)<<63, uint64(1)<<63)

	// The exact overflow premise, restated so the test breaks if the fixture
	// stops being adversarial.
	wrapped := uo.CallGasLimit + uo.VerificationGasLimit + uo.PreVerificationGas
	if wrapped >= r5BundleGasLimit {
		t.Fatalf("fixture no longer wraps under uint64 addition (wrapped=%d)", wrapped)
	}

	b, st, hashes := r5GasBundler(t, uo)
	bundle := b.buildBundle(r5Candidates(b, hashes))

	if len(bundle.UserOps) != 0 {
		t.Fatalf("an operation claiming 2^64 gas was bundled")
	}
	if st.snapshots != 0 {
		t.Fatalf("wrapped gas claim still cost %d simulation frame(s); the budget check must run before simulation", st.snapshots)
	}
	if b.GetUserOperation(hashes[0]) == nil {
		t.Fatal("an operation that was never bundled was dropped from the mempool")
	}
}

// TestR5_06_LegitimateClaimStillReachesSimulation is the complement: the gate
// must not reject claims that genuinely fit.
func TestR5_06_LegitimateClaimStillReachesSimulation(t *testing.T) {
	uo := r5GasUserOp(0x22, 21000, 21000)

	b, st, hashes := r5GasBundler(t, uo)
	bundle := b.buildBundle(r5Candidates(b, hashes))

	if len(bundle.UserOps) != 0 {
		t.Fatalf("legitimate operation should not be bundled when its simulation fails")
	}
	if st.snapshots != 1 {
		t.Fatalf("legitimate operation opened %d simulation frames, want 1", st.snapshots)
	}
	if b.GetUserOperation(hashes[0]) != nil {
		t.Fatal("operation that failed simulation must leave the mempool")
	}
}

// TestR5_06_OpClaimingMoreThanTheBlockLimitSkipsSimulation pins the other branch
// of the same gate: a claim that is merely too big (no wrapping involved) is
// dropped before any account code runs.
func TestR5_06_OpClaimingMoreThanTheBlockLimitSkipsSimulation(t *testing.T) {
	uo := r5GasUserOp(0x31, r5BundleGasLimit+1, 0)

	b, st, hashes := r5GasBundler(t, uo)
	bundle := b.buildBundle(r5Candidates(b, hashes))

	if len(bundle.UserOps) != 0 {
		t.Fatal("an operation claiming more than the block gas limit was bundled")
	}
	if st.snapshots != 0 {
		t.Fatalf("%d simulation frames opened, want 0", st.snapshots)
	}
	if b.GetUserOperation(hashes[0]) == nil {
		t.Fatal("the skipped operation was dropped from the mempool instead of staying queued")
	}
}

// TestR5_06_UserOpGasBudgetDoesNotWrap pins the helper's arithmetic directly.
func TestR5_06_UserOpGasBudgetDoesNotWrap(t *testing.T) {
	two63 := new(big.Int).Lsh(big.NewInt(1), 63)
	maxU64 := new(big.Int).SetUint64(math.MaxUint64)

	cases := []struct {
		name                          string
		call, verification, preVerify uint64
		want                          *big.Int
	}{
		{
			name: "mirrored 2^63 halves", call: uint64(1) << 63, verification: 100000, preVerify: uint64(1) << 63,
			want: new(big.Int).Add(new(big.Int).Lsh(two63, 1), big.NewInt(100000)),
		},
		{
			name: "three maximal fields", call: math.MaxUint64, verification: math.MaxUint64, preVerify: math.MaxUint64,
			want: new(big.Int).Mul(maxU64, big.NewInt(3)),
		},
		{
			name: "plain transfer", call: 21000, verification: 100000, preVerify: 21000,
			want: big.NewInt(142000),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := userOpGasBudget(&encoding.UserOperation{
				CallGasLimit:         tc.call,
				VerificationGasLimit: tc.verification,
				PreVerificationGas:   tc.preVerify,
			})
			if got.Cmp(tc.want) != 0 {
				t.Fatalf("gas budget = %s, want %s", got, tc.want)
			}
		})
	}
}
