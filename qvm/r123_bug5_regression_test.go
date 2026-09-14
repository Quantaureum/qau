// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"testing"
)

// R123 BUG-5 regression lock: after claim cleanup the owner must be intact (before the fix, reversed SSTORE order
// wrote the queue key into slot 0, corrupting the owner)
func TestR123Bug5OwnerSurvivesClaim(t *testing.T) {
	f := newStqauFixture(t)
	f.mustDeposit(t, f.alice, stqauE18(100))
	if _, err := f.callValue(f.owner, stSelInjectRewards, 8_000_000, stqauE18(100)); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if _, err := f.call(f.alice, stqauWithdrawInput(stqauE18(100)), 8_000_000); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	f.ctx.BlockNumber = 1_000 + stqauUnbondBlocks + 1
	if _, err := f.call(f.alice, stSelClaimWithdrawal, 8_000_000); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// owner still equals the deployer
	out, err := f.call(f.alice, stSelOwner, 200_000)
	if err != nil {
		t.Fatalf("owner(): %v", err)
	}
	if got := new(big.Int).SetBytes(out); got.Cmp(new(big.Int).SetBytes(padAddressWord(f.owner))) != 0 {
		t.Fatalf("owner corrupted after claim: %x, want %x", got, padAddressWord(f.owner))
	}
	// duplicate claim rejected (queue already drained)
	if _, err := f.call(f.alice, stSelClaimWithdrawal, 8_000_000); err == nil {
		t.Fatal("double claim should revert")
	}
	// the extract gate is still owner-protected (if slot 0 were corrupted, the owner check would fail)
	in := append(append([]byte{}, stSelExtract...), u256(stqauE18(1))...)
	if _, err := f.call(f.alice, in, 8_000_000); err == nil {
		t.Fatal("non-owner extract should still revert after claim (owner intact)")
	}
}
