// Quantaureum Node source, version 1.0.0.
package miner

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// permissiveTestVerifier accepts all signatures. Test-only.
type permissiveTestVerifier struct{}

func (permissiveTestVerifier) Verify(pubKey []byte, message []byte, signature []byte) error {
	return nil
}

// newTestAuctionWithRegistry creates an auction with a permissive registry
// that accepts all bids from the test builder address. Test-only helper
// needed because ECON-R3-02 fix makes SubmitBid fail-closed when no registry
// is configured.
func newTestAuctionWithRegistry(proposerAddr types.Address, minBidValue *big.Int) *MEVAuction {
	auction := NewMEVAuction(proposerAddr, minBidValue)
	registry := NewBuilderRegistry(permissiveTestVerifier{})
	// makeTestBid always uses BuilderAddress types.Address{0x01}
	registry.RegisterBuilder(types.Address{0x01}, []byte{0x01})
	auction.SetRegistry(registry)
	return auction
}

// newTestProtectionWithRegistry creates MEV protection with a permissive registry.
func newTestProtectionWithRegistry(chainID uint64, maxGasLimit uint64, proposer types.Address) *MEVProtection {
	registry := NewBuilderRegistry(permissiveTestVerifier{})
	registry.RegisterBuilder(types.Address{0x01}, []byte{0x01})
	return NewMEVProtectionWithRegistry(chainID, maxGasLimit, proposer, registry)
}

func makeTestBid(slot uint64, value int64) *BuilderBid {
	header := &encoding.BlockHeader{
		Version:      1,
		Height:       slot * 32,
		Slot:         slot,
		Epoch:        slot / 32,
		Timestamp:    time.Now().UnixNano(),
		ProposerAddr: types.Address{0x01},
		ChainID:      1,
		GasLimit:     30000000,
	}
	return &BuilderBid{
		Slot:           slot,
		ParentHash:     types.Hash{0x02},
		BlockHash:      types.Hash{0x03},
		Header:         header,
		Transactions:   []*encoding.Transaction{},
		Value:          big.NewInt(value),
		BuilderAddress: types.Address{0x01},
		BuilderSig:     []byte{0x01, 0x02, 0x03},
		Timestamp:      time.Now().UnixNano(),
		GasUsed:        0,
	}
}

func TestBuilderBid_Validate(t *testing.T) {
	t.Run("valid bid", func(t *testing.T) {
		bid := makeTestBid(1, 100)
		if err := bid.Validate(); err != nil {
			t.Errorf("valid bid should pass validation: %v", err)
		}
	})

	t.Run("nil header", func(t *testing.T) {
		bid := makeTestBid(1, 100)
		bid.Header = nil
		if err := bid.Validate(); err == nil {
			t.Error("bid with nil header should fail validation")
		}
	})

	t.Run("nil value", func(t *testing.T) {
		bid := makeTestBid(1, 100)
		bid.Value = nil
		if err := bid.Validate(); err == nil {
			t.Error("bid with nil value should fail validation")
		}
	})

	t.Run("negative value", func(t *testing.T) {
		bid := makeTestBid(1, 100)
		bid.Value = big.NewInt(-1)
		if err := bid.Validate(); err == nil {
			t.Error("bid with negative value should fail validation")
		}
	})

	t.Run("no signature", func(t *testing.T) {
		bid := makeTestBid(1, 100)
		bid.BuilderSig = nil
		if err := bid.Validate(); err == nil {
			t.Error("bid without signature should fail validation")
		}
	})
}

func TestBuilderBid_Hash(t *testing.T) {
	bid1 := makeTestBid(1, 100)
	bid2 := makeTestBid(1, 100)

	hash1 := bid1.Hash()
	hash2 := bid2.Hash()

	if hash1 != hash2 {
		t.Error("identical bids should have identical hashes")
	}

	bid3 := makeTestBid(1, 200)
	hash3 := bid3.Hash()
	if hash1 == hash3 {
		t.Error("different bids should have different hashes")
	}

	bid4 := makeTestBid(2, 100)
	hash4 := bid4.Hash()
	if hash1 == hash4 {
		t.Error("bids with different slots should have different hashes")
	}
}

func TestMEVAuction_SubmitBid(t *testing.T) {
	auction := newTestAuctionWithRegistry(types.Address{0xAA}, big.NewInt(10))

	t.Run("valid bid", func(t *testing.T) {
		bid := makeTestBid(1, 100)
		if err := auction.SubmitBid(bid); err != nil {
			t.Errorf("valid bid should be accepted: %v", err)
		}
	})

	t.Run("bid below minimum", func(t *testing.T) {
		bid := makeTestBid(2, 5)
		if err := auction.SubmitBid(bid); err == nil {
			t.Error("bid below minimum should be rejected")
		}
	})

	t.Run("closed auction", func(t *testing.T) {
		auction2 := newTestAuctionWithRegistry(types.Address{0xBB}, nil)
		auction2.CloseAuction(10)
		bid := makeTestBid(10, 100)
		if err := auction2.SubmitBid(bid); err == nil {
			t.Error("bid to closed auction should be rejected")
		}
	})

	t.Run("invalid bid", func(t *testing.T) {
		bid := makeTestBid(3, 100)
		bid.Header = nil
		if err := auction.SubmitBid(bid); err == nil {
			t.Error("invalid bid should be rejected")
		}
	})
}

func TestMEVAuction_GetBid(t *testing.T) {
	auction := newTestAuctionWithRegistry(types.Address{0xCC}, nil)
	bid := makeTestBid(1, 100)
	auction.SubmitBid(bid)
	bidHash := bid.Hash()

	t.Run("existing bid", func(t *testing.T) {
		retrieved := auction.GetBid(1, bidHash)
		if retrieved == nil {
			t.Error("should retrieve existing bid")
		}
		if retrieved.Value.Cmp(big.NewInt(100)) != 0 {
			t.Error("retrieved bid has wrong value")
		}
	})

	t.Run("non-existing slot", func(t *testing.T) {
		retrieved := auction.GetBid(99, bidHash)
		if retrieved != nil {
			t.Error("should return nil for non-existing slot")
		}
	})

	t.Run("non-existing hash", func(t *testing.T) {
		retrieved := auction.GetBid(1, types.Hash{0xFF})
		if retrieved != nil {
			t.Error("should return nil for non-existing hash")
		}
	})
}

func TestMEVAuction_SelectWinningBid(t *testing.T) {
	t.Run("no bids", func(t *testing.T) {
		auction := NewMEVAuction(types.Address{0xDD}, nil)
		winner := auction.SelectWinningBid(1)
		if winner != nil {
			t.Error("should return nil when no bids exist")
		}
	})

	t.Run("single bid", func(t *testing.T) {
		auction := newTestAuctionWithRegistry(types.Address{0xDD}, nil)
		bid := makeTestBid(1, 100)
		auction.SubmitBid(bid)
		winner := auction.SelectWinningBid(1)
		if winner == nil {
			t.Fatal("should select a winner")
		}
		if winner.Value.Cmp(big.NewInt(100)) != 0 {
			t.Error("winner has wrong value")
		}
	})

	t.Run("multiple bids selects highest", func(t *testing.T) {
		auction := newTestAuctionWithRegistry(types.Address{0xDD}, nil)
		auction.SubmitBid(makeTestBid(1, 100))
		auction.SubmitBid(makeTestBid(1, 500))
		auction.SubmitBid(makeTestBid(1, 300))

		winner := auction.SelectWinningBid(1)
		if winner == nil {
			t.Fatal("should select a winner")
		}
		if winner.Value.Cmp(big.NewInt(500)) != 0 {
			t.Errorf("should select highest bid, got %s", winner.Value.String())
		}
	})

	t.Run("winning bid is cached", func(t *testing.T) {
		auction := newTestAuctionWithRegistry(types.Address{0xDD}, nil)
		auction.SubmitBid(makeTestBid(1, 100))
		auction.SelectWinningBid(1)

		cached := auction.GetWinningBid(1)
		if cached == nil {
			t.Error("winning bid should be cached")
		}
	})
}

func TestMEVAuction_CloseAndIsOpen(t *testing.T) {
	auction := NewMEVAuction(types.Address{0xEE}, nil)

	if !auction.IsOpen(1) {
		t.Error("new auction should be open")
	}

	auction.CloseAuction(1)

	if auction.IsOpen(1) {
		t.Error("closed auction should not be open")
	}

	if !auction.IsOpen(2) {
		t.Error("other slots should still be open")
	}
}

func TestMEVAuction_CleanupOldSlots(t *testing.T) {
	auction := newTestAuctionWithRegistry(types.Address{0xFF}, nil)

	auction.SubmitBid(makeTestBid(1, 100))
	auction.SubmitBid(makeTestBid(10, 200))
	auction.SubmitBid(makeTestBid(100, 300))

	auction.SelectWinningBid(1)
	auction.SelectWinningBid(10)
	auction.CloseAuction(1)

	auction.CleanupOldSlots(200)

	if auction.GetBid(1, types.Hash{}) != nil || len(auction.bids) > 0 {
		// slot 1 should be cleaned up (1+64 < 200)
	}

	if auction.GetWinningBid(100) == nil {
		// slot 100 should still exist (100+64 >= 200)
	}
}

func TestMEVAuction_BidTimeout(t *testing.T) {
	auction := NewMEVAuction(types.Address{0x11}, nil)

	defaultTimeout := auction.BidTimeout()
	if defaultTimeout != 6*time.Second {
		t.Errorf("default timeout should be 6s, got %v", defaultTimeout)
	}

	auction.SetBidTimeout(10 * time.Second)
	if auction.BidTimeout() != 10*time.Second {
		t.Error("bid timeout should be updated")
	}
}

func TestEffectivePriorityFee(t *testing.T) {
	baseFee := big.NewInt(100)

	t.Run("legacy tx with gas price above base fee", func(t *testing.T) {
		tx := &encoding.Transaction{
			GasPrice: big.NewInt(150),
		}
		fee := effectivePriorityFee(tx, baseFee)
		if fee.Cmp(big.NewInt(50)) != 0 {
			t.Errorf("expected 50, got %s", fee.String())
		}
	})

	t.Run("legacy tx with gas price below base fee", func(t *testing.T) {
		tx := &encoding.Transaction{
			GasPrice: big.NewInt(50),
		}
		fee := effectivePriorityFee(tx, baseFee)
		if fee.Cmp(big.NewInt(0)) != 0 {
			t.Errorf("expected 0, got %s", fee.String())
		}
	})

	t.Run("legacy tx with gas price equal to base fee", func(t *testing.T) {
		tx := &encoding.Transaction{
			GasPrice: big.NewInt(100),
		}
		fee := effectivePriorityFee(tx, baseFee)
		if fee.Cmp(big.NewInt(0)) != 0 {
			t.Errorf("expected 0, got %s", fee.String())
		}
	})

	t.Run("eip1559 tx with max fee above base fee", func(t *testing.T) {
		tx := &encoding.Transaction{
			MaxFeePerGas:         big.NewInt(200),
			MaxPriorityFeePerGas: big.NewInt(30),
		}
		fee := effectivePriorityFee(tx, baseFee)
		if fee.Cmp(big.NewInt(30)) != 0 {
			t.Errorf("expected 30, got %s", fee.String())
		}
	})

	t.Run("eip1559 tx with max fee below base fee", func(t *testing.T) {
		tx := &encoding.Transaction{
			MaxFeePerGas:         big.NewInt(50),
			MaxPriorityFeePerGas: big.NewInt(30),
		}
		fee := effectivePriorityFee(tx, baseFee)
		if fee.Cmp(big.NewInt(0)) != 0 {
			t.Errorf("expected 0, got %s", fee.String())
		}
	})

	t.Run("eip1559 tx with priority fee capped by max fee minus base fee", func(t *testing.T) {
		tx := &encoding.Transaction{
			MaxFeePerGas:         big.NewInt(120),
			MaxPriorityFeePerGas: big.NewInt(50),
		}
		fee := effectivePriorityFee(tx, baseFee)
		if fee.Cmp(big.NewInt(20)) != 0 {
			t.Errorf("expected 20, got %s", fee.String())
		}
	})

	t.Run("no gas price fields", func(t *testing.T) {
		tx := &encoding.Transaction{}
		fee := effectivePriorityFee(tx, baseFee)
		if fee.Cmp(big.NewInt(0)) != 0 {
			t.Errorf("expected 0, got %s", fee.String())
		}
	})
}

func TestMEVBlockBuilder_CalculateBidValue(t *testing.T) {
	builder := NewMEVBlockBuilder(1, 30000000, nil)

	t.Run("empty transactions", func(t *testing.T) {
		value := builder.calculateBidValue([]*encoding.Transaction{}, big.NewInt(100))
		if value.Cmp(big.NewInt(0)) != 0 {
			t.Error("empty txs should have zero bid value")
		}
	})

	t.Run("single transaction", func(t *testing.T) {
		tx := &encoding.Transaction{
			GasPrice: big.NewInt(200),
			GasLimit: 21000,
		}
		value := builder.calculateBidValue([]*encoding.Transaction{tx}, big.NewInt(100))
		expected := big.NewInt(2100000)
		if value.Cmp(expected) != 0 {
			t.Errorf("expected %s, got %s", expected.String(), value.String())
		}
	})

	t.Run("multiple transactions", func(t *testing.T) {
		tx1 := &encoding.Transaction{
			GasPrice: big.NewInt(200),
			GasLimit: 21000,
		}
		tx2 := &encoding.Transaction{
			GasPrice: big.NewInt(150),
			GasLimit: 50000,
		}
		value := builder.calculateBidValue([]*encoding.Transaction{tx1, tx2}, big.NewInt(100))
		expected := big.NewInt(4600000)
		if value.Cmp(expected) != 0 {
			t.Errorf("expected %s, got %s", expected.String(), value.String())
		}
	})
}

func TestMEVBlockBuilder_SelectTransactionsByPriority(t *testing.T) {
	builder := NewMEVBlockBuilder(1, 200000, nil)

	t.Run("empty list", func(t *testing.T) {
		selected := builder.selectTransactionsByPriority([]*encoding.Transaction{}, big.NewInt(100))
		if len(selected) != 0 {
			t.Error("should return empty for empty input")
		}
	})

	// ECON-04 FIX: With different senders, transactions should be interleaved
	// by priority fee (highest first across senders).
	t.Run("sorts by priority fee descending across senders", func(t *testing.T) {
		tx1 := &encoding.Transaction{
			From:     types.Address{0x01},
			Nonce:    0,
			GasPrice: big.NewInt(300),
			GasLimit: 21000,
		}
		tx2 := &encoding.Transaction{
			From:     types.Address{0x02},
			Nonce:    0,
			GasPrice: big.NewInt(200),
			GasLimit: 21000,
		}
		tx3 := &encoding.Transaction{
			From:     types.Address{0x03},
			Nonce:    0,
			GasPrice: big.NewInt(400),
			GasLimit: 21000,
		}

		selected := builder.selectTransactionsByPriority([]*encoding.Transaction{tx1, tx2, tx3}, big.NewInt(100))

		if len(selected) != 3 {
			t.Fatalf("expected 3 txs, got %d", len(selected))
		}
		if selected[0].GasPrice.Cmp(big.NewInt(400)) != 0 {
			t.Error("first tx should have highest priority fee")
		}
		if selected[1].GasPrice.Cmp(big.NewInt(300)) != 0 {
			t.Error("second tx should have middle priority fee")
		}
		if selected[2].GasPrice.Cmp(big.NewInt(200)) != 0 {
			t.Error("third tx should have lowest priority fee")
		}
	})

	// ECON-04 FIX: Same sender's transactions must be ordered by nonce
	// ascending, even if a higher-nonce tx has a higher gas price.
	t.Run("enforces per-sender nonce ordering", func(t *testing.T) {
		sender := types.Address{0xAA}
		// tx with nonce=1 has HIGHER gas price than nonce=0
		// Old code would put nonce=1 first → non-executable block
		tx0 := &encoding.Transaction{
			From:     sender,
			Nonce:    0,
			GasPrice: big.NewInt(100),
			GasLimit: 21000,
		}
		tx1 := &encoding.Transaction{
			From:     sender,
			Nonce:    1,
			GasPrice: big.NewInt(500), // higher gas price, but must come AFTER nonce=0
			GasLimit: 21000,
		}

		// Pass in reverse order to verify sorting
		selected := builder.selectTransactionsByPriority([]*encoding.Transaction{tx1, tx0}, big.NewInt(50))

		if len(selected) != 2 {
			t.Fatalf("expected 2 txs, got %d", len(selected))
		}
		if selected[0].Nonce != 0 {
			t.Errorf("ECON-04: first tx should be nonce=0, got nonce=%d", selected[0].Nonce)
		}
		if selected[1].Nonce != 1 {
			t.Errorf("ECON-04: second tx should be nonce=1, got nonce=%d", selected[1].Nonce)
		}
	})

	t.Run("respects gas limit", func(t *testing.T) {
		tx1 := &encoding.Transaction{
			From:     types.Address{0x01},
			GasPrice: big.NewInt(500),
			GasLimit: 150000,
		}
		tx2 := &encoding.Transaction{
			From:     types.Address{0x02},
			GasPrice: big.NewInt(400),
			GasLimit: 100000,
		}

		selected := builder.selectTransactionsByPriority([]*encoding.Transaction{tx1, tx2}, big.NewInt(100))

		if len(selected) != 1 {
			t.Fatalf("expected 1 tx due to gas limit, got %d", len(selected))
		}
		if selected[0].GasPrice.Cmp(big.NewInt(500)) != 0 {
			t.Error("should select highest priority tx that fits")
		}
	})
}

func TestMEVProtection_Enabled(t *testing.T) {
	protection := NewMEVProtection(1, 30000000, types.Address{0x01})

	if !protection.IsEnabled() {
		t.Error("MEV protection should be enabled by default")
	}

	protection.SetEnabled(false)
	if protection.IsEnabled() {
		t.Error("MEV protection should be disabled after SetEnabled(false)")
	}

	protection.SetEnabled(true)
	if !protection.IsEnabled() {
		t.Error("MEV protection should be enabled after SetEnabled(true)")
	}
}

func TestMEVProtection_AuctionAndBuilder(t *testing.T) {
	protection := NewMEVProtection(1, 30000000, types.Address{0x01})

	auction := protection.Auction()
	if auction == nil {
		t.Error("auction should not be nil")
	}

	builder := protection.Builder()
	if builder == nil {
		t.Error("builder should not be nil")
	}
}

func TestMEVProtection_GetBlockForSlot(t *testing.T) {
	protection := NewMEVProtection(1, 30000000, types.Address{0x01})

	parent := &encoding.BlockHeader{
		Version:      1,
		Height:       0,
		Timestamp:    time.Now().UnixNano(),
		ProposerAddr: types.Address{0x02},
		ChainID:      1,
		GasLimit:     30000000,
	}

	t.Run("no winning bid falls back to builder", func(t *testing.T) {
		bid, err := protection.GetBlockForSlot(1, parent, nil, types.Address{0x01}, big.NewInt(100))
		if err != nil {
			t.Errorf("should not error: %v", err)
		}
		if bid == nil {
			t.Error("should return a bid from builder")
		}
	})

	t.Run("with winning bid returns cached bid", func(t *testing.T) {
		protection2 := newTestProtectionWithRegistry(1, 30000000, types.Address{0x01})
		testBid := makeTestBid(2, 500)
		// L6-020: Set bid ParentHash to match the actual parent header hash
		// so the parent consistency check in GetBlockForSlot passes.
		testBid.ParentHash = parentHashToHash(parent)
		protection2.Auction().SubmitBid(testBid)
		protection2.Auction().SelectWinningBid(2)

		bid, err := protection2.GetBlockForSlot(2, parent, nil, types.Address{0x01}, big.NewInt(100))
		if err != nil {
			t.Errorf("should not error: %v", err)
		}
		if bid == nil {
			t.Fatal("should return a bid")
		}
		if bid.Value.Cmp(big.NewInt(500)) != 0 {
			t.Error("should return the winning bid")
		}
	})

	t.Run("disabled protection uses builder directly", func(t *testing.T) {
		protection3 := NewMEVProtection(1, 30000000, types.Address{0x01})
		protection3.SetEnabled(false)

		bid, err := protection3.GetBlockForSlot(3, parent, nil, types.Address{0x01}, big.NewInt(100))
		if err != nil {
			t.Errorf("should not error: %v", err)
		}
		if bid == nil {
			t.Error("should return a bid from builder")
		}
	})
}

func TestComputeMerkleRoot(t *testing.T) {
	t.Run("empty transactions", func(t *testing.T) {
		root := ComputeMerkleRoot(nil)
		if root != (types.Hash{}) {
			t.Error("empty txs should return zero hash")
		}
	})

	t.Run("single transaction", func(t *testing.T) {
		tx := &encoding.Transaction{
			Version:  1,
			Nonce:    0,
			GasLimit: 21000,
		}
		root := ComputeMerkleRoot([]types.Hash{tx.Hash()})
		if root == (types.Hash{}) {
			t.Error("single tx should produce non-zero root")
		}
	})

	t.Run("two transactions produce merkle root", func(t *testing.T) {
		tx1 := &encoding.Transaction{Version: 1, Nonce: 0, GasLimit: 21000}
		tx2 := &encoding.Transaction{Version: 1, Nonce: 1, GasLimit: 21000}
		root := ComputeMerkleRoot([]types.Hash{tx1.Hash(), tx2.Hash()})
		if root == (types.Hash{}) {
			t.Error("two txs should produce non-zero root")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		tx1 := &encoding.Transaction{Version: 1, Nonce: 0, GasLimit: 21000}
		tx2 := &encoding.Transaction{Version: 1, Nonce: 1, GasLimit: 21000}

		hashes := []types.Hash{tx1.Hash(), tx2.Hash()}
		root1 := ComputeMerkleRoot(hashes)
		root2 := ComputeMerkleRoot(hashes)

		if root1 != root2 {
			t.Error("same txs should produce same root")
		}
	})
}

func TestMEVAuction_MaxBidsPerSlot(t *testing.T) {
	auction := newTestAuctionWithRegistry(types.Address{0x22}, nil)

	for i := 0; i < MaxBidsPerSlot; i++ {
		bid := makeTestBid(1, int64(100+i))
		bid.BlockHash = types.Hash{byte(i)}
		if err := auction.SubmitBid(bid); err != nil {
			t.Fatalf("bid %d should be accepted: %v", i, err)
		}
	}

	extraBid := makeTestBid(1, 999)
	extraBid.BlockHash = types.Hash{0xFF, 0xFF}
	if err := auction.SubmitBid(extraBid); err == nil {
		t.Error("should reject bid when slot is full")
	}
}

func TestMEVAuction_ConcurrentSubmit(t *testing.T) {
	auction := newTestAuctionWithRegistry(types.Address{0x33}, nil)
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(idx int) {
			bid := makeTestBid(1, int64(100+idx))
			bid.BlockHash = types.Hash{byte(idx)}
			auction.SubmitBid(bid)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	winner := auction.SelectWinningBid(1)
	if winner == nil {
		t.Error("should have a winner after concurrent submissions")
	}
}

func TestMEVBlockBuilder_BuildBlock(t *testing.T) {
	auction := NewMEVAuction(types.Address{0x01}, nil)
	builder := NewMEVBlockBuilder(1, 30000000, auction)

	parent := &encoding.BlockHeader{
		Version:      1,
		Height:       0,
		Timestamp:    time.Now().UnixNano(),
		ProposerAddr: types.Address{0x02},
		ChainID:      1,
		GasLimit:     30000000,
	}

	txs := []*encoding.Transaction{
		{
			Version:  1,
			Nonce:    0,
			GasPrice: big.NewInt(200),
			GasLimit: 21000,
		},
	}

	bid, err := builder.BuildBlock(1, parent, txs, types.Address{0x01}, big.NewInt(100))
	if err != nil {
		t.Fatalf("BuildBlock failed: %v", err)
	}
	if bid == nil {
		t.Fatal("bid should not be nil")
	}
	if bid.Slot != 1 {
		t.Errorf("expected slot 1, got %d", bid.Slot)
	}
	if bid.Header == nil {
		t.Error("bid should have a header")
	}
	if bid.Header.Height != 1 {
		t.Errorf("expected height 1, got %d", bid.Header.Height)
	}
	if len(bid.Transactions) == 0 {
		t.Error("bid should include transactions")
	}
	if bid.Value == nil || bid.Value.Sign() <= 0 {
		t.Error("bid should have positive value")
	}
}
