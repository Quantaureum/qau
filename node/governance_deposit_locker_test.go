// Quantaureum Node source, version 1.0.0.
// Package node — R3-09 deposit locker tests.
package node

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/types"
)

func fixedBalance(v int64) func(types.Address) (*big.Int, error) {
	return func(types.Address) (*big.Int, error) {
		return big.NewInt(v), nil
	}
}

func newTestDepositLocker(t *testing.T, balance int64) (*governanceDepositLocker, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "governance", "deposit-locks.json")
	l, err := newGovernanceDepositLocker(path, fixedBalance(balance))
	if err != nil {
		t.Fatalf("newGovernanceDepositLocker: %v", err)
	}
	return l, path
}

func TestGovernanceDepositLockerReserveAndRelease(t *testing.T) {
	l, _ := newTestDepositLocker(t, 250)
	addr := types.BytesToAddress([]byte{0x01})
	deposit := big.NewInt(100)

	if err := l.LockDeposit(addr, deposit, 1); err != nil {
		t.Fatalf("lock proposal 1: %v", err)
	}
	if err := l.LockDeposit(addr, deposit, 2); err != nil {
		t.Fatalf("lock proposal 2: %v", err)
	}
	if err := l.LockDeposit(addr, deposit, 3); err == nil {
		t.Fatal("third lock must be rejected: reservations exceed free balance")
	}
	if got := l.ReservedAmount(addr); got.Cmp(big.NewInt(200)) != 0 {
		t.Fatalf("reserved after two locks = %s, want 200", got)
	}

	if err := l.UnlockDeposit(addr, deposit, 1); err != nil {
		t.Fatalf("unlock proposal 1: %v", err)
	}
	if err := l.LockDeposit(addr, deposit, 3); err != nil {
		t.Fatalf("lock proposal 3 after release: %v", err)
	}
	if got := l.ReservedAmount(addr); got.Cmp(big.NewInt(200)) != 0 {
		t.Fatalf("reserved after release+lock = %s, want 200", got)
	}

	if err := l.SlashDeposit(addr, deposit, 2); err != nil {
		t.Fatalf("slash proposal 2: %v", err)
	}
	if got := l.ReservedAmount(addr); got.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("reserved after slash = %s, want 100", got)
	}
	if err := l.LockDeposit(addr, big.NewInt(200), 4); err == nil {
		t.Fatal("lock of 200 with 100 already reserved and 250 free must fail")
	}

	// Unlock and slash are idempotent per proposal ID.
	if err := l.UnlockDeposit(addr, deposit, 99); err != nil {
		t.Fatalf("unlock unknown proposal: %v", err)
	}
	if err := l.UnlockDeposit(addr, deposit, 3); err != nil {
		t.Fatalf("unlock proposal 3: %v", err)
	}
	if err := l.UnlockDeposit(addr, deposit, 3); err != nil {
		t.Fatalf("second unlock of proposal 3 must be a no-op: %v", err)
	}
	if got := l.ReservedAmount(addr); got.Sign() != 0 {
		t.Fatalf("reserved after all releases = %s, want 0", got)
	}
}

func TestGovernanceDepositLockerIdempotentLock(t *testing.T) {
	l, path := newTestDepositLocker(t, 100)
	addr := types.BytesToAddress([]byte{0x02})
	deposit := big.NewInt(100)

	if err := l.LockDeposit(addr, deposit, 1); err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if err := l.LockDeposit(addr, deposit, 1); err != nil {
		t.Fatalf("repeated identical lock must be a no-op: %v", err)
	}
	if got := l.ReservedAmount(addr); got.Cmp(deposit) != 0 {
		t.Fatalf("reserved after duplicate lock = %s, want %s", got, deposit)
	}
	if err := l.LockDeposit(addr, big.NewInt(50), 1); err == nil {
		t.Fatal("same proposal ID with a different amount must fail")
	}
	if err := l.LockDeposit(types.BytesToAddress([]byte{0x03}), deposit, 1); err == nil {
		t.Fatal("same proposal ID with a different proposer must fail")
	}

	// A failed release due to a mismatched proposer must keep the lock.
	if err := l.UnlockDeposit(types.BytesToAddress([]byte{0x03}), deposit, 1); err == nil {
		t.Fatal("release by a different proposer must fail")
	}
	if got := l.ReservedAmount(addr); got.Cmp(deposit) != 0 {
		t.Fatalf("reserved after rejected release = %s, want %s", got, deposit)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("lock file was not persisted: %v", err)
	}
}

func TestGovernanceDepositLockerPersistsAcrossReload(t *testing.T) {
	l, path := newTestDepositLocker(t, 150)
	addr := types.BytesToAddress([]byte{0x04})
	other := types.BytesToAddress([]byte{0x05})

	if err := l.LockDeposit(addr, big.NewInt(100), 1); err != nil {
		t.Fatalf("lock proposal 1: %v", err)
	}
	if err := l.LockDeposit(other, big.NewInt(50), 2); err != nil {
		t.Fatalf("lock proposal 2: %v", err)
	}

	reloaded, err := newGovernanceDepositLocker(path, fixedBalance(150))
	if err != nil {
		t.Fatalf("reload locker: %v", err)
	}
	if got := reloaded.ReservedAmount(addr); got.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("reserved after reload = %s, want 100", got)
	}
	if got := reloaded.ReservedAmount(other); got.Cmp(big.NewInt(50)) != 0 {
		t.Fatalf("other reserved after reload = %s, want 50", got)
	}
	// Persisted reservations must still count against the balance.
	if err := reloaded.LockDeposit(addr, big.NewInt(100), 3); err == nil {
		t.Fatal("reloaded ledger must reject a lock exceeding free balance")
	}

	if err := reloaded.UnlockDeposit(addr, big.NewInt(100), 1); err != nil {
		t.Fatalf("unlock proposal 1: %v", err)
	}
	again, err := newGovernanceDepositLocker(path, fixedBalance(150))
	if err != nil {
		t.Fatalf("second reload: %v", err)
	}
	if got := again.ReservedAmount(addr); got.Sign() != 0 {
		t.Fatalf("reserved after unlock+reload = %s, want 0", got)
	}
	if got := again.ReservedAmount(other); got.Cmp(big.NewInt(50)) != 0 {
		t.Fatalf("other reserved after second reload = %s, want 50", got)
	}
}

func TestGovernanceDepositLockerZeroAndNegative(t *testing.T) {
	l, path := newTestDepositLocker(t, 0)
	addr := types.BytesToAddress([]byte{0x06})

	if err := l.LockDeposit(addr, big.NewInt(0), 1); err != nil {
		t.Fatalf("zero deposit must be a no-op: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("zero deposit must not create a lock file, stat err = %v", err)
	}
	if err := l.LockDeposit(addr, big.NewInt(-1), 2); err == nil {
		t.Fatal("negative deposit must be rejected")
	}
	if err := l.LockDeposit(addr, nil, 3); err == nil {
		t.Fatal("nil deposit must be rejected")
	}
}

func TestGovernanceDepositLockerRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deposit-locks.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	if _, err := newGovernanceDepositLocker(path, fixedBalance(100)); err == nil {
		t.Fatal("corrupt lock file must fail initialization instead of silently resetting")
	}
}

func TestGovernanceDepositLockerRejectsDuplicateEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deposit-locks.json")
	addr := types.BytesToAddress([]byte{0x07}).ToHexAddress()
	data := `{"locks":[{"proposalId":1,"proposer":"` + addr + `","amount":"100"},` +
		`{"proposalId":1,"proposer":"` + addr + `","amount":"100"}]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatalf("write lock file: %v", err)
	}
	if _, err := newGovernanceDepositLocker(path, fixedBalance(100)); err == nil {
		t.Fatal("duplicate proposal IDs in the lock file must fail initialization")
	}
}
