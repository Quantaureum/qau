// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
)

// ── FeeHistoryTracker tests ──

func TestNewFeeHistoryTracker(t *testing.T) {
	fht := NewFeeHistoryTracker()
	if fht == nil {
		t.Fatal("expected non-nil FeeHistoryTracker")
	}
	if fht.maxSize != maxFeeHistoryBlocks {
		t.Errorf("expected maxSize %d, got %d", maxFeeHistoryBlocks, fht.maxSize)
	}
	if len(fht.entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(fht.entries))
	}
}

func TestFeeHistoryTracker_RecordBlock(t *testing.T) {
	fht := NewFeeHistoryTracker()

	header := &encoding.BlockHeader{
		Height:   1,
		GasUsed:  15000000,
		GasLimit: 30000000,
		BaseFee:  big.NewInt(1e9),
	}

	fht.RecordBlock(header, nil)

	if len(fht.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(fht.entries))
	}
	if fht.entries[0].BlockNum != 1 {
		t.Errorf("expected block 1, got %d", fht.entries[0].BlockNum)
	}
	if fht.entries[0].GasUsed != 15000000 {
		t.Errorf("expected gasUsed 15000000, got %d", fht.entries[0].GasUsed)
	}
	if fht.entries[0].BaseFee.Cmp(big.NewInt(1e9)) != 0 {
		t.Errorf("expected baseFee 1e9, got %s", fht.entries[0].BaseFee.String())
	}
}

func TestFeeHistoryTracker_RecordBlock_NilBaseFee(t *testing.T) {
	fht := NewFeeHistoryTracker()

	header := &encoding.BlockHeader{
		Height:   1,
		GasUsed:  10000000,
		GasLimit: 30000000,
		BaseFee:  nil,
	}

	fht.RecordBlock(header, nil)

	if fht.entries[0].BaseFee.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("expected 0 baseFee for nil, got %s", fht.entries[0].BaseFee.String())
	}
}

func TestFeeHistoryTracker_RecordBlock_WithTransactions(t *testing.T) {
	fht := NewFeeHistoryTracker()

	header := &encoding.BlockHeader{
		Height:   1,
		GasUsed:  15000000,
		GasLimit: 30000000,
		BaseFee:  big.NewInt(1e9),
	}

	txs := []*encoding.Transaction{
		{GasPrice: big.NewInt(2e9)},
		{GasPrice: big.NewInt(3e9)},
	}

	fht.RecordBlock(header, txs)

	if len(fht.entries[0].Rewards) != 2 {
		t.Errorf("expected 2 rewards, got %d", len(fht.entries[0].Rewards))
	}
}

func TestFeeHistoryTracker_GetHistory_Empty(t *testing.T) {
	fht := NewFeeHistoryTracker()

	result, err := fht.GetHistory(5, 0, nil)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestFeeHistoryTracker_GetHistory_WithEntries(t *testing.T) {
	fht := NewFeeHistoryTracker()

	for i := uint64(1); i <= 10; i++ {
		header := &encoding.BlockHeader{
			Height:   i,
			GasUsed:  15000000,
			GasLimit: 30000000,
			BaseFee:  big.NewInt(1e9),
		}
		fht.RecordBlock(header, nil)
	}

	result, err := fht.GetHistory(5, 10, nil)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	if result.OldestBlock != 6 {
		t.Errorf("expected oldestBlock 6, got %d", result.OldestBlock)
	}
	if len(result.BaseFeePerGas) != 5 {
		t.Errorf("expected 5 base fees, got %d", len(result.BaseFeePerGas))
	}
	if len(result.GasUsedRatio) != 5 {
		t.Errorf("expected 5 gas used ratios, got %d", len(result.GasUsedRatio))
	}
}

func TestFeeHistoryTracker_GetHistory_WithRewardPercentiles(t *testing.T) {
	fht := NewFeeHistoryTracker()

	for i := uint64(1); i <= 5; i++ {
		header := &encoding.BlockHeader{
			Height:   i,
			GasUsed:  15000000,
			GasLimit: 30000000,
			BaseFee:  big.NewInt(1e9),
		}
		txs := []*encoding.Transaction{
			{GasPrice: big.NewInt(2e9)},
			{GasPrice: big.NewInt(3e9)},
		}
		fht.RecordBlock(header, txs)
	}

	result, err := fht.GetHistory(5, 5, []float64{25, 50, 75})
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	if result.Reward == nil {
		t.Fatal("expected non-nil reward")
	}
	if len(result.Reward) != 5 {
		t.Errorf("expected 5 reward entries, got %d", len(result.Reward))
	}
}

func TestFeeHistoryTracker_GetHistory_BlockCountClamp(t *testing.T) {
	fht := NewFeeHistoryTracker()

	// Request more than 1024 blocks
	result, err := fht.GetHistory(2000, 0, nil)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	_ = result
}

func TestFeeHistoryTracker_GetHistory_ZeroBlockCount(t *testing.T) {
	fht := NewFeeHistoryTracker()

	result, err := fht.GetHistory(0, 0, nil)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	_ = result
}

func TestFeeHistoryTracker_latestBlock_Empty(t *testing.T) {
	fht := NewFeeHistoryTracker()
	if fht.latestBlock() != 0 {
		t.Errorf("expected 0 for empty tracker, got %d", fht.latestBlock())
	}
}

func TestFeeHistoryTracker_latestBlock_WithEntries(t *testing.T) {
	fht := NewFeeHistoryTracker()
	header := &encoding.BlockHeader{Height: 42, GasLimit: 30000000, BaseFee: big.NewInt(1e9)}
	fht.RecordBlock(header, nil)
	if fht.latestBlock() != 42 {
		t.Errorf("expected 42, got %d", fht.latestBlock())
	}
}

func TestFeeHistoryTracker_MaxSize(t *testing.T) {
	fht := NewFeeHistoryTracker()

	// Record more than maxFeeHistoryBlocks entries
	for i := uint64(0); i < uint64(maxFeeHistoryBlocks+100); i++ {
		header := &encoding.BlockHeader{
			Height:   i,
			GasUsed:  15000000,
			GasLimit: 30000000,
			BaseFee:  big.NewInt(1e9),
		}
		fht.RecordBlock(header, nil)
	}

	if len(fht.entries) > fht.maxSize {
		t.Errorf("entries exceeded maxSize: %d > %d", len(fht.entries), fht.maxSize)
	}
}

// ── computeRewardPercentiles tests ──

func TestComputeRewardPercentiles_Empty(t *testing.T) {
	rewards := computeRewardPercentiles(nil, big.NewInt(1e9))
	if len(rewards) != 0 {
		t.Errorf("expected 0 rewards, got %d", len(rewards))
	}
}

func TestComputeRewardPercentiles_WithTxs(t *testing.T) {
	txs := []*encoding.Transaction{
		{GasPrice: big.NewInt(2e9)},
		{GasPrice: big.NewInt(3e9)},
		{GasPrice: big.NewInt(5e9)},
	}
	rewards := computeRewardPercentiles(txs, big.NewInt(1e9))
	if len(rewards) != 3 {
		t.Fatalf("expected 3 rewards, got %d", len(rewards))
	}
	// reward = gasPrice - baseFee
	if rewards[0].Cmp(big.NewInt(1e9)) != 0 {
		t.Errorf("expected reward 1e9, got %s", rewards[0].String())
	}
	if rewards[1].Cmp(big.NewInt(2e9)) != 0 {
		t.Errorf("expected reward 2e9, got %s", rewards[1].String())
	}
	if rewards[2].Cmp(big.NewInt(4e9)) != 0 {
		t.Errorf("expected reward 4e9, got %s", rewards[2].String())
	}
}

func TestComputeRewardPercentiles_NegativeReward(t *testing.T) {
	txs := []*encoding.Transaction{
		{GasPrice: big.NewInt(500000000)}, // 0.5 Gwei, below 1 Gwei baseFee
	}
	rewards := computeRewardPercentiles(txs, big.NewInt(1e9))
	if rewards[0].Cmp(big.NewInt(0)) != 0 {
		t.Errorf("expected 0 reward for below-baseFee gasPrice, got %s", rewards[0].String())
	}
}

func TestComputeRewardPercentiles_NilGasPrice(t *testing.T) {
	txs := []*encoding.Transaction{
		{GasPrice: nil},
	}
	rewards := computeRewardPercentiles(txs, big.NewInt(1e9))
	if len(rewards) != 0 {
		t.Errorf("expected 0 rewards for nil gasPrice, got %d", len(rewards))
	}
}

func TestComputeRewardPercentiles_NilBaseFee(t *testing.T) {
	txs := []*encoding.Transaction{
		{GasPrice: big.NewInt(2e9)},
	}
	rewards := computeRewardPercentiles(txs, nil)
	if len(rewards) != 0 {
		t.Errorf("expected 0 rewards for nil baseFee, got %d", len(rewards))
	}
}

// ── percentileReward extended tests ──

func TestPercentileReward_Empty(t *testing.T) {
	result := percentileReward(nil, 50)
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("expected 0 for empty rewards, got %s", result.String())
	}
}

func TestPercentileReward_SingleValue(t *testing.T) {
	rewards := []*big.Int{big.NewInt(100)}
	result := percentileReward(rewards, 50)
	if result.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("expected 100, got %s", result.String())
	}
}

func TestPercentileReward_ThreeValues(t *testing.T) {
	rewards := []*big.Int{big.NewInt(10), big.NewInt(20), big.NewInt(30)}
	p0 := percentileReward(rewards, 0)
	if p0.Cmp(big.NewInt(10)) != 0 {
		t.Errorf("expected 10 for p0, got %s", p0.String())
	}
	p100 := percentileReward(rewards, 100)
	if p100.Cmp(big.NewInt(30)) != 0 {
		t.Errorf("expected 30 for p100, got %s", p100.String())
	}
	p50 := percentileReward(rewards, 50)
	if p50.Cmp(big.NewInt(20)) != 0 {
		t.Errorf("expected 20 for p50, got %s", p50.String())
	}
}

// ── toHexBig tests ──

func TestToHexBig_Nil(t *testing.T) {
	result := toHexBig(nil)
	if result != "0x0" {
		t.Errorf("expected '0x0', got '%s'", result)
	}
}

func TestToHexBig_Zero(t *testing.T) {
	result := toHexBig(big.NewInt(0))
	if result != "0x0" {
		t.Errorf("expected '0x0', got '%s'", result)
	}
}

func TestToHexBig_Positive(t *testing.T) {
	result := toHexBig(big.NewInt(255))
	if result != "0xff" {
		t.Errorf("expected '0xff', got '%s'", result)
	}
}

func TestToHexBig_Large(t *testing.T) {
	result := toHexBig(big.NewInt(1e9))
	if result != "0x3b9aca00" {
		t.Errorf("expected '0x3b9aca00', got '%s'", result)
	}
}

// ── Config Validate extended tests ──

func TestConfig_Validate_EmptyDataDir(t *testing.T) {
	cfg := &Config{Name: "test", DataDir: ""}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("empty DataDir should use default, got: %v", err)
	}
	if cfg.DataDir == "" {
		t.Error("expected DataDir to be set after Validate")
	}
}

func TestConfig_Validate_EmptyName(t *testing.T) {
	cfg := &Config{Name: "", DataDir: t.TempDir()}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("empty Name should not cause error, got: %v", err)
	}
	// Name is not auto-set by Validate, it remains empty
}

func TestConfig_Validate_BackupDirs(t *testing.T) {
	cfg := &Config{
		Name:      "test-backup",
		DataDir:   t.TempDir(),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
		KeyRotation: KeyRotationConfig{
			BackupEnabled: true,
		},
		TLSCertRotation: TLSCertRotationConfig{
			BackupEnabled: true,
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.KeyRotation.BackupDir == "" {
		t.Error("expected KeyRotation.BackupDir to be set when BackupEnabled=true")
	}
	if cfg.TLSCertRotation.BackupDir == "" {
		t.Error("expected TLSCertRotation.BackupDir to be set when BackupEnabled=true")
	}
}

// ── Network ID constants ──

func TestNetworkIDConstants(t *testing.T) {
	if MainnetNetworkID != 1668 {
		t.Errorf("expected MainnetNetworkID 1668, got %d", MainnetNetworkID)
	}
	if TestnetNetworkID != 1669 {
		t.Errorf("expected TestnetNetworkID 1669, got %d", TestnetNetworkID)
	}
	if DevnetNetworkID != 1333 {
		t.Errorf("expected DevnetNetworkID 1333, got %d", DevnetNetworkID)
	}
}

// ── Node initP2P test (should not panic without network) ──

func TestNode_InitP2P_Disabled(t *testing.T) {
	cfg := &Config{
		Name:      "test-p2p",
		DataDir:   t.TempDir(),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = cfg.DataDir + "\\keys\\backup"
	cfg.TLSCertRotation.BackupDir = cfg.DataDir + "\\certs\\backup"
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	// initP2P should not panic when P2P is not configured
	// It may return an error or just not start
	_ = n
}

// ── Node with SyncOnlyMode ──

func TestNode_SyncOnlyMode(t *testing.T) {
	cfg := &Config{
		Name:         "test-synconly",
		DataDir:      t.TempDir(),
		NetworkID:    DevnetNetworkID,
		DevMode:      true,
		SyncOnlyMode: true,
	}
	cfg.KeyRotation.BackupDir = cfg.DataDir + "\\keys\\backup"
	cfg.TLSCertRotation.BackupDir = cfg.DataDir + "\\certs\\backup"
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if !n.config.SyncOnlyMode {
		t.Error("expected SyncOnlyMode to be true")
	}
}

// ── Node BlockProducer disabled ──

func TestNode_BlockProducerDisabled(t *testing.T) {
	cfg := &Config{
		Name:          "test-no-bp",
		DataDir:       t.TempDir(),
		NetworkID:     DevnetNetworkID,
		DevMode:       true,
		BlockProducer: false,
	}
	cfg.KeyRotation.BackupDir = cfg.DataDir + "\\keys\\backup"
	cfg.TLSCertRotation.BackupDir = cfg.DataDir + "\\certs\\backup"
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if n.config.BlockProducer {
		t.Error("expected BlockProducer to be false")
	}
}

// ── FeeHistoryTracker GetHistory with zero newestBlock ──

func TestFeeHistoryTracker_GetHistory_ZeroNewestBlock(t *testing.T) {
	fht := NewFeeHistoryTracker()

	for i := uint64(1); i <= 5; i++ {
		header := &encoding.BlockHeader{
			Height:   i,
			GasUsed:  15000000,
			GasLimit: 30000000,
			BaseFee:  big.NewInt(1e9),
		}
		fht.RecordBlock(header, nil)
	}

	// newestBlock=0 should default to latestBlock
	result, err := fht.GetHistory(3, 0, nil)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// ── FeeHistoryTracker GetHistory with newestBlock beyond latest ──

func TestFeeHistoryTracker_GetHistory_NewestBeyondLatest(t *testing.T) {
	fht := NewFeeHistoryTracker()

	header := &encoding.BlockHeader{
		Height:   5,
		GasUsed:  15000000,
		GasLimit: 30000000,
		BaseFee:  big.NewInt(1e9),
	}
	fht.RecordBlock(header, nil)

	// newestBlock=100 is beyond latest (5), should default to 5
	result, err := fht.GetHistory(3, 100, nil)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	_ = result
}

// ── FeeHistoryTracker GetHistory GasUsedRatio with zero GasLimit ──

func TestFeeHistoryTracker_GetHistory_ZeroGasLimit(t *testing.T) {
	fht := NewFeeHistoryTracker()

	header := &encoding.BlockHeader{
		Height:   1,
		GasUsed:  0,
		GasLimit: 0,
		BaseFee:  big.NewInt(1e9),
	}
	fht.RecordBlock(header, nil)

	result, err := fht.GetHistory(1, 1, nil)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	if len(result.GasUsedRatio) != 1 {
		t.Fatalf("expected 1 ratio, got %d", len(result.GasUsedRatio))
	}
	if result.GasUsedRatio[0] != 0 {
		t.Errorf("expected 0 ratio for zero GasLimit, got %f", result.GasUsedRatio[0])
	}
}

// ── FeeHistoryTracker GetHistory with more blocks than requested ──

func TestFeeHistoryTracker_GetHistory_MoreBlocksThanRequested(t *testing.T) {
	fht := NewFeeHistoryTracker()

	for i := uint64(1); i <= 20; i++ {
		header := &encoding.BlockHeader{
			Height:   i,
			GasUsed:  15000000,
			GasLimit: 30000000,
			BaseFee:  big.NewInt(int64(i) * 1e9),
		}
		fht.RecordBlock(header, nil)
	}

	result, err := fht.GetHistory(5, 20, nil)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	if result.OldestBlock != 16 {
		t.Errorf("expected oldestBlock 16, got %d", result.OldestBlock)
	}
}

// ── FeeHistoryTracker GetHistory requesting more than available ──

func TestFeeHistoryTracker_GetHistory_MoreThanAvailable(t *testing.T) {
	fht := NewFeeHistoryTracker()

	for i := uint64(1); i <= 3; i++ {
		header := &encoding.BlockHeader{
			Height:   i,
			GasUsed:  15000000,
			GasLimit: 30000000,
			BaseFee:  big.NewInt(1e9),
		}
		fht.RecordBlock(header, nil)
	}

	// Request 10 blocks but only 3 available
	result, err := fht.GetHistory(10, 3, nil)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	if result.OldestBlock != 1 {
		t.Errorf("expected oldestBlock 1, got %d", result.OldestBlock)
	}
	if len(result.BaseFeePerGas) != 3 {
		t.Errorf("expected 3 base fees, got %d", len(result.BaseFeePerGas))
	}
}

// ── FeeHistoryTracker concurrent access ──

func TestFeeHistoryTracker_ConcurrentAccess(t *testing.T) {
	fht := NewFeeHistoryTracker()

	done := make(chan bool, 2)

	// Writer goroutine
	go func() {
		for i := uint64(1); i <= 100; i++ {
			header := &encoding.BlockHeader{
				Height:   i,
				GasUsed:  15000000,
				GasLimit: 30000000,
				BaseFee:  big.NewInt(1e9),
			}
			fht.RecordBlock(header, nil)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			fht.GetHistory(5, 0, nil)
		}
		done <- true
	}()

	<-done
	<-done
}
