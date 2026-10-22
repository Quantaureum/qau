// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/quantaureum/qau/types"
)

// governanceDepositLocker enforces the governance proposal deposit at the node
// integration layer (R3-09). economics.CreateProposal cannot move balances
// itself (it sits below the execution layer) and an RPC-created proposal is
// not a consensus transaction, so the locker reserves the deposit against the
// proposer's free on-chain balance: at most
// floor(freeBalance / ProposalDeposit) proposals can be outstanding per
// address. Reservations are persisted in the governance data directory so a
// restart cannot reset them.
//
// GovernanceManager releases the reservation (UnlockDeposit) when a proposal
// reaches a terminal state. SlashDeposit has the same ledger effect: the
// reservation is removed; actual value settlement, if any, belongs to the
// execution layer.
//
// R4-03 trust boundary (known limitation, not a consensus guarantee):
//   - Reservations live in this node's data directory and are checked only in
//     the RPC admission path (economics.CreateProposal). They are not part of
//     block state, so validators do not enforce them and a proposer with access
//     to N endpoints gets N independent quotas. The guard therefore raises the
//     cost of same-endpoint proposal spam; it does not make proposals free of
//     cost network-wide.
//   - Nothing is debited: the proposer's balance stays spendable while
//     reservations are held, and no code path calls SlashDeposit, so a bad
//     proposal is never charged. Turning the deposit into a real cost needs
//     execution-layer settlement (deposit transfer at proposal inclusion plus a
//     slash rule), which is a protocol change rather than a node-level fix.
//
// The balance reader takes n.mu.RLock briefly to snapshot the state pointer; no
// path holds n.mu and then acquires the GovernanceManager or locker lock, so the
// gm.mu -> locker.mu -> n.mu order used here has no inverse today.
type governanceDepositLocker struct {
	mu      sync.Mutex
	path    string
	balance func(types.Address) (*big.Int, error)
	locks   map[uint64]governanceDepositLock
}

type governanceDepositLock struct {
	proposer types.Address
	amount   *big.Int
}

type governanceDepositLockJSON struct {
	ProposalID uint64 `json:"proposalId"`
	Proposer   string `json:"proposer"`
	Amount     string `json:"amount"`
}

type governanceDepositLockFile struct {
	Locks []governanceDepositLockJSON `json:"locks"`
}

// newGovernanceDepositLocker loads existing reservations from path. A corrupt
// or unreadable lock file is an initialization error: silently starting with
// an empty ledger would let a restart re-open the deposit bypass.
func newGovernanceDepositLocker(path string, balance func(types.Address) (*big.Int, error)) (*governanceDepositLocker, error) {
	if path == "" {
		return nil, fmt.Errorf("governance deposit lock path is empty")
	}
	if balance == nil {
		return nil, fmt.Errorf("governance deposit balance reader is nil")
	}
	l := &governanceDepositLocker{
		path:    path,
		balance: balance,
		locks:   make(map[uint64]governanceDepositLock),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return nil, fmt.Errorf("read governance deposit locks: %w", err)
	}
	var file governanceDepositLockFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse governance deposit locks: %w", err)
	}
	for _, entry := range file.Locks {
		addr, err := types.ParseHexAddress(entry.Proposer)
		if err != nil {
			return nil, fmt.Errorf("deposit lock for proposal %d: invalid proposer: %w", entry.ProposalID, err)
		}
		amount, ok := new(big.Int).SetString(entry.Amount, 10)
		if !ok || amount.Sign() <= 0 {
			return nil, fmt.Errorf("deposit lock for proposal %d: invalid amount %q", entry.ProposalID, entry.Amount)
		}
		if _, duplicate := l.locks[entry.ProposalID]; duplicate {
			return nil, fmt.Errorf("duplicate deposit lock for proposal %d", entry.ProposalID)
		}
		l.locks[entry.ProposalID] = governanceDepositLock{proposer: addr, amount: amount}
	}
	return l, nil
}

// LockDeposit reserves amount for proposalID. It is idempotent for the same
// (proposer, amount) pair and fails if the proposer's free balance does not
// cover this deposit plus every reservation already held for the address.
// A zero amount is a no-op: a governance configuration with ProposalDeposit=0
// requires no reservation.
func (l *governanceDepositLocker) LockDeposit(addr types.Address, amount *big.Int, proposalID uint64) error {
	if amount == nil || amount.Sign() < 0 {
		return fmt.Errorf("governance deposit must not be negative")
	}
	if amount.Sign() == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if existing, ok := l.locks[proposalID]; ok {
		if existing.proposer == addr && existing.amount.Cmp(amount) == 0 {
			return nil
		}
		return fmt.Errorf("proposal %d already holds a deposit lock for another proposer or amount", proposalID)
	}

	balance, err := l.balance(addr)
	if err != nil {
		return fmt.Errorf("query proposer free balance: %w", err)
	}
	if balance == nil {
		return fmt.Errorf("proposer free balance is unavailable")
	}
	reserved := new(big.Int)
	for _, lock := range l.locks {
		if lock.proposer == addr {
			reserved.Add(reserved, lock.amount)
		}
	}
	required := new(big.Int).Add(reserved, amount)
	if balance.Cmp(required) < 0 {
		return fmt.Errorf("insufficient free balance for governance deposit: balance %s, reserved %s, requested %s",
			balance.String(), reserved.String(), amount.String())
	}

	l.locks[proposalID] = governanceDepositLock{proposer: addr, amount: new(big.Int).Set(amount)}
	if err := l.saveLocked(); err != nil {
		delete(l.locks, proposalID)
		return err
	}
	return nil
}

// UnlockDeposit releases a reservation. Idempotent on proposalID.
func (l *governanceDepositLocker) UnlockDeposit(addr types.Address, amount *big.Int, proposalID uint64) error {
	return l.release(addr, amount, proposalID)
}

// SlashDeposit removes a reservation. Idempotent on proposalID.
func (l *governanceDepositLocker) SlashDeposit(addr types.Address, amount *big.Int, proposalID uint64) error {
	return l.release(addr, amount, proposalID)
}

func (l *governanceDepositLocker) release(addr types.Address, amount *big.Int, proposalID uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	lock, ok := l.locks[proposalID]
	if !ok {
		return nil
	}
	if lock.proposer != addr {
		return fmt.Errorf("deposit lock for proposal %d belongs to a different proposer", proposalID)
	}
	if amount != nil && lock.amount.Cmp(amount) != 0 {
		return fmt.Errorf("deposit lock for proposal %d is %s, not %s", proposalID, lock.amount.String(), amount.String())
	}

	delete(l.locks, proposalID)
	if err := l.saveLocked(); err != nil {
		l.locks[proposalID] = lock
		return err
	}
	return nil
}

// ReservedAmount reports how much of addr's balance is currently reserved.
// Used by tests and operator diagnostics.
func (l *governanceDepositLocker) ReservedAmount(addr types.Address) *big.Int {
	l.mu.Lock()
	defer l.mu.Unlock()

	total := new(big.Int)
	for _, lock := range l.locks {
		if lock.proposer == addr {
			total.Add(total, lock.amount)
		}
	}
	return total
}

// saveLocked writes the ledger atomically (temp file + rename) so a crash
// cannot leave a half-written lock file. Callers must hold l.mu.
func (l *governanceDepositLocker) saveLocked() error {
	ids := make([]uint64, 0, len(l.locks))
	for id := range l.locks {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	file := governanceDepositLockFile{Locks: make([]governanceDepositLockJSON, 0, len(ids))}
	for _, id := range ids {
		lock := l.locks[id]
		file.Locks = append(file.Locks, governanceDepositLockJSON{
			ProposalID: id,
			Proposer:   lock.proposer.ToHexAddress(),
			Amount:     lock.amount.String(),
		})
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal governance deposit locks: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(l.path), 0700); err != nil {
		return fmt.Errorf("create governance deposit lock dir: %w", err)
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write governance deposit locks: %w", err)
	}
	if err := os.Rename(tmp, l.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace governance deposit locks: %w", err)
	}
	return nil
}
