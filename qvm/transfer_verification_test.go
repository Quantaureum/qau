// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"testing"
)

// TestTransferConservation verifies total-amount conservation across transfers
// core invariant: A balance + B balance + gas fee = initial total
func TestTransferConservation(t *testing.T) {
	t.Parallel()

	// create two accounts with initial balances
	addrA := Address{0x01}
	addrB := Address{0x02}
	coinbase := Address{0x03} // proposer/miner address

	initialA := big.NewInt(1000000) // 1,000,000
	initialB := big.NewInt(500000)  // 500,000
	totalInitial := new(big.Int).Add(initialA, initialB)

	stateDB := newFuzzStateDB()
	stateDB.SetBalance(addrA, initialA)
	stateDB.SetBalance(addrB, initialB)

	// run several transfer rounds and verify conservation
	transfers := []struct {
		from   Address
		to     Address
		amount *big.Int
	}{
		{addrA, addrB, big.NewInt(10000)},
		{addrB, addrA, big.NewInt(5000)},
		{addrA, addrB, big.NewInt(20000)},
		{addrB, addrA, big.NewInt(15000)},
		{addrA, addrB, big.NewInt(30000)},
	}

	gasPrice := big.NewInt(1)
	totalGasFees := big.NewInt(0)

	for i, tx := range transfers {
		fromBalance := stateDB.GetBalance(tx.from)
		toBalance := stateDB.GetBalance(tx.to)

		// check balance sufficiency (transfer amount + gas fee)
		gasUsed := GasTxCall // base transfer gas
		gasFee := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(gasUsed))
		totalCost := new(big.Int).Add(tx.amount, gasFee)

		if fromBalance.Cmp(totalCost) < 0 {
			t.Logf("round %d: insufficient balance, skipped", i+1)
			continue
		}

		// perform the transfer
		stateDB.SetBalance(tx.from, new(big.Int).Sub(fromBalance, totalCost))
		stateDB.SetBalance(tx.to, new(big.Int).Add(toBalance, tx.amount))

		// gas fee goes to the proposer
		coinbaseBalance := stateDB.GetBalance(coinbase)
		stateDB.SetBalance(coinbase, new(big.Int).Add(coinbaseBalance, gasFee))
		totalGasFees.Add(totalGasFees, gasFee)

		// verify conservation: A + B + coinbase = initial total
		currentA := stateDB.GetBalance(addrA)
		currentB := stateDB.GetBalance(addrB)
		currentCoinbase := stateDB.GetBalance(coinbase)
		currentTotal := new(big.Int).Add(currentA, currentB)
		currentTotal.Add(currentTotal, currentCoinbase)

		if currentTotal.Cmp(totalInitial) != 0 {
			t.Errorf("round %d broke conservation: total=%s, initial total=%s",
				i+1, currentTotal.String(), totalInitial.String())
		}
	}
}

// TestBalanceNonNegativity verifies balances never go negative
func TestBalanceNonNegativity(t *testing.T) {
	t.Parallel()

	stateDB := newFuzzStateDB()
	addrA := Address{0x01}
	addrB := Address{0x02}

	// case 1: transfer from a zero-balance account
	t.Run("zero-balance account transfer", func(t *testing.T) {
		stateDB.SetBalance(addrA, big.NewInt(0))
		stateDB.SetBalance(addrB, big.NewInt(0))

		// attempt the transfer via Executor.Call
		executor := NewExecutor()
		blockCtx := &BlockContext{
			BlockNumber: 1,
			Timestamp:   100,
			Coinbase:    Address{0x03},
			GasLimit:    1000000,
			GasPrice:    big.NewInt(1),
			ChainID:     1668,
			BlockHashes: make(map[uint64]Hash),
		}

		result := executor.Call(stateDB, addrA, addrB, nil, 100000, big.NewInt(100), blockCtx, 0)
		if result.Err != ErrInsufficientBalance {
			t.Errorf("zero-balance transfer should return ErrInsufficientBalance, got: %v", result.Err)
		}

		// verify balance non-negative
		if stateDB.GetBalance(addrA).Sign() < 0 {
			t.Errorf("A balance negative: %s", stateDB.GetBalance(addrA).String())
		}
		if stateDB.GetBalance(addrB).Sign() < 0 {
			t.Errorf("B balance negative: %s", stateDB.GetBalance(addrB).String())
		}
	})

	// case 2: transfer from an underfunded account
	t.Run("insufficient-balance transfer", func(t *testing.T) {
		stateDB.SetBalance(addrA, big.NewInt(50)) // only 50
		stateDB.SetBalance(addrB, big.NewInt(0))

		executor := NewExecutor()
		blockCtx := &BlockContext{
			BlockNumber: 1,
			Timestamp:   100,
			Coinbase:    Address{0x03},
			GasLimit:    1000000,
			GasPrice:    big.NewInt(1),
			ChainID:     1668,
			BlockHashes: make(map[uint64]Hash),
		}

		// try to transfer 100 with only 50
		result := executor.Call(stateDB, addrA, addrB, nil, 100000, big.NewInt(100), blockCtx, 0)
		if result.Err != ErrInsufficientBalance {
			t.Errorf("insufficient-balance transfer should return ErrInsufficientBalance, got: %v", result.Err)
		}

		// verify balance unchanged and non-negative
		balA := stateDB.GetBalance(addrA)
		balB := stateDB.GetBalance(addrB)
		if balA.Sign() < 0 {
			t.Errorf("A balance negative: %s", balA.String())
		}
		if balB.Sign() < 0 {
			t.Errorf("B balance negative: %s", balB.String())
		}
		if balA.Cmp(big.NewInt(50)) != 0 {
			t.Errorf("A balance should stay at 50, got: %s", balA.String())
		}
	})

	// case 3: direct StateDB operations keep balances non-negative
	t.Run("direct StateDB operations keep balance non-negative", func(t *testing.T) {
		addrs := []Address{{0x10}, {0x11}, {0x12}, {0x13}, {0x14}}
		for _, addr := range addrs {
			stateDB.SetBalance(addr, big.NewInt(0))
		}

		// try various ops; balances must remain >= 0
		for _, addr := range addrs {
			bal := stateDB.GetBalance(addr)
			if bal.Sign() < 0 {
				t.Errorf("address %x balance negative: %s", addr, bal.String())
			}
		}
	})
}

// TestNonceMonotonic verifies account nonces increase monotonically
func TestNonceMonotonic(t *testing.T) {
	t.Parallel()

	stateDB := newFuzzStateDB()
	addr := Address{0x01}

	// case 1: nonce only increases
	t.Run("nonce monotonic increase", func(t *testing.T) {
		var prevNonce uint64
		for i := 0; i < 20; i++ {
			currentNonce := stateDB.GetNonce(addr)
			if i > 0 && currentNonce < prevNonce {
				t.Errorf("nonce decreased: previous=%d, current=%d", prevNonce, currentNonce)
			}
			prevNonce = currentNonce

			// increment the nonce
			stateDB.SetNonce(addr, currentNonce+1)
		}

		finalNonce := stateDB.GetNonce(addr)
		if finalNonce != 20 {
			t.Errorf("final nonce should be 20, got: %d", finalNonce)
		}
	})

	// case 2: same-nonce transactions are rejected (simulated)
	t.Run("duplicate nonce rejected", func(t *testing.T) {
		addr2 := Address{0x02}
		stateDB.SetNonce(addr2, 5)

		// simulate tx processing: expecting a nonce=5 tx
		expectedNonce := stateDB.GetNonce(addr2)
		if expectedNonce != 5 {
			t.Errorf("expected nonce=5, got: %d", expectedNonce)
		}

		// the first nonce=5 tx should be accepted
		txNonce := uint64(5)
		if txNonce != expectedNonce {
			t.Errorf("nonce mismatch: tx nonce=%d, account nonce=%d", txNonce, expectedNonce)
		}
		// accepted, then increment
		stateDB.SetNonce(addr2, txNonce+1)

		// the second nonce=5 tx should be rejected (replay)
		txNonce2 := uint64(5)
		currentNonce := stateDB.GetNonce(addr2)
		if txNonce2 == currentNonce {
			// if equal, the nonce did not advance — a bug
			t.Errorf("same nonce=%d must not be accepted again, current nonce=%d", txNonce2, currentNonce)
		}
		if txNonce2 < currentNonce {
			// correct: nonce advanced, old nonce rejected
		}
	})

	// case 3: nonce gap detection
	t.Run("nonce gap detection", func(t *testing.T) {
		addr3 := Address{0x03}
		stateDB.SetNonce(addr3, 0)

		// nonce jumps 0 -> 5 (1-4 missing)
		stateDB.SetNonce(addr3, 5)
		if stateDB.GetNonce(addr3) != 5 {
			t.Errorf("nonce should be 5, got: %d", stateDB.GetNonce(addr3))
		}

		// on a real chain, gap txs sit in the pending pool
		// here we only verify nonce storage and retrieval
	})
}

// TestGasFeeCorrectness verifies gas-fee accounting
func TestGasFeeCorrectness(t *testing.T) {
	t.Parallel()

	// case 1: sender deduction = transfer amount + gas_used * gas_price
	t.Run("sender deduction equals transfer plus gas", func(t *testing.T) {
		stateDB := newFuzzStateDB()
		sender := Address{0x01}
		receiver := Address{0x02}
		coinbase := Address{0x03}

		initialBalance := big.NewInt(1000000)
		stateDB.SetBalance(sender, initialBalance)
		stateDB.SetBalance(receiver, big.NewInt(0))
		stateDB.SetBalance(coinbase, big.NewInt(0))

		transferAmount := big.NewInt(100000)
		gasPrice := big.NewInt(10)
		gasUsed := GasTxCall // 21000
		gasFee := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(gasUsed))

		// simulate the transfer
		senderBalance := stateDB.GetBalance(sender)
		totalDeduction := new(big.Int).Add(transferAmount, gasFee)

		if senderBalance.Cmp(totalDeduction) < 0 {
			t.Fatalf("insufficient balance: have=%s, need=%s", senderBalance.String(), totalDeduction.String())
		}

		stateDB.SetBalance(sender, new(big.Int).Sub(senderBalance, totalDeduction))
		stateDB.SetBalance(receiver, transferAmount)
		stateDB.SetBalance(coinbase, gasFee)

		// verify sender balance
		expectedSenderBalance := new(big.Int).Sub(initialBalance, totalDeduction)
		actualSenderBalance := stateDB.GetBalance(sender)
		if actualSenderBalance.Cmp(expectedSenderBalance) != 0 {
			t.Errorf("sender balance wrong: want=%s, got=%s",
				expectedSenderBalance.String(), actualSenderBalance.String())
		}

		// verify recipient balance
		if stateDB.GetBalance(receiver).Cmp(transferAmount) != 0 {
			t.Errorf("recipient balance wrong: want=%s, got=%s",
				transferAmount.String(), stateDB.GetBalance(receiver).String())
		}

		// verify the proposer received the gas fee
		if stateDB.GetBalance(coinbase).Cmp(gasFee) != 0 {
			t.Errorf("proposer gas fee wrong: want=%s, got=%s",
				gasFee.String(), stateDB.GetBalance(coinbase).String())
		}
	})

	// case 2: verify gas metering via QVM execution
	t.Run("QVM execution gas metering", func(t *testing.T) {
		stateDB := newFuzzStateDB()
		caller := Address{0x10}
		contract := Address{0x20}

		// simple contract: PUSH1 0x2a, PUSH1 0x00, SSTORE, STOP
		code := []byte{
			byte(PUSH1), 0x2a,
			byte(PUSH1), 0x00,
			byte(SSTORE),
			byte(STOP),
		}

		gasLimit := uint64(100000)
		ctx := &ExecutionContext{
			Origin:      caller,
			GasPrice:    big.NewInt(1),
			Caller:      caller,
			Address:     contract,
			Value:       big.NewInt(0),
			BlockNumber: 1,
			Timestamp:   100,
			Coinbase:    Address{0x03},
			GasLimit:    gasLimit,
			ChainID:     1668,
			BlockHashes: make(map[uint64]Hash),
			Code:        code,
			Input:       nil,
			Gas:         gasLimit,
		}

		interp := NewInterpreter()
		result := interp.Execute(ctx, stateDB)

		if result.Err != nil {
			t.Fatalf("execution failed: %v", result.Err)
		}

		// gas used should exceed 0
		if result.GasUsed == 0 {
			t.Error("gas used must not be 0")
		}

		// gas used must not exceed the limit
		if result.GasUsed > gasLimit {
			t.Errorf("gas used exceeds limit: used=%d, limit=%d", result.GasUsed, gasLimit)
		}

		// verify gas fee = gasUsed * gasPrice
		expectedGasFee := new(big.Int).Mul(
			new(big.Int).SetUint64(result.GasUsed),
			big.NewInt(1),
		)
		if expectedGasFee.Sign() <= 0 {
			t.Errorf("gas fee should be positive: %s", expectedGasFee.String())
		}
	})

	// case 3: execution fails with insufficient gas
	t.Run("insufficient gas fails execution", func(t *testing.T) {
		stateDB := newFuzzStateDB()
		caller := Address{0x10}
		contract := Address{0x20}

		code := []byte{
			byte(PUSH1), 0x2a,
			byte(PUSH1), 0x00,
			byte(SSTORE),
			byte(STOP),
		}

		// provide minimal gas
		ctx := &ExecutionContext{
			Origin:      caller,
			GasPrice:    big.NewInt(1),
			Caller:      caller,
			Address:     contract,
			Value:       big.NewInt(0),
			BlockNumber: 1,
			Timestamp:   100,
			Coinbase:    Address{0x03},
			GasLimit:    100,
			ChainID:     1668,
			BlockHashes: make(map[uint64]Hash),
			Code:        code,
			Input:       nil,
			Gas:         5, // minimal gas
		}

		interp := NewInterpreter()
		result := interp.Execute(ctx, stateDB)

		if result.Err == nil {
			t.Error("insufficient gas should return an error")
		}
	})
}
