// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
)

// ── calculateNextBaseFee tests (EIP-1559) ──

func TestCalculateNextBaseFee_NilBaseFee(t *testing.T) {
	parent := &encoding.BlockHeader{}
	result := calculateNextBaseFee(parent)
	if result.Cmp(big.NewInt(1e9)) != 0 {
		t.Errorf("expected 1 Gwei initial base fee, got %s", result.String())
	}
}

func TestCalculateNextBaseFee_ZeroBaseFee(t *testing.T) {
	parent := &encoding.BlockHeader{
		BaseFee: big.NewInt(0),
	}
	result := calculateNextBaseFee(parent)
	if result.Cmp(big.NewInt(1e9)) != 0 {
		t.Errorf("expected 1 Gwei for zero base fee, got %s", result.String())
	}
}

func TestCalculateNextBaseFee_AtTarget(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 30000000,
		GasUsed:  15000000, // exactly 50% = target
		BaseFee:  big.NewInt(1e9),
	}
	result := calculateNextBaseFee(parent)
	if result.Cmp(big.NewInt(1e9)) != 0 {
		t.Errorf("expected same base fee at target, got %s", result.String())
	}
}

func TestCalculateNextBaseFee_AboveTarget(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 30000000,
		GasUsed:  20000000, // above 50% target
		BaseFee:  big.NewInt(1e9),
	}
	result := calculateNextBaseFee(parent)
	if result.Cmp(big.NewInt(1e9)) <= 0 {
		t.Errorf("expected increased base fee above target, got %s", result.String())
	}
}

func TestCalculateNextBaseFee_BelowTarget(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 30000000,
		GasUsed:  10000000, // below 50% target
		BaseFee:  big.NewInt(1e9),
	}
	result := calculateNextBaseFee(parent)
	if result.Cmp(big.NewInt(1e9)) >= 0 {
		t.Errorf("expected decreased base fee below target, got %s", result.String())
	}
}

func TestCalculateNextBaseFee_ZeroGasLimit(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 0,
		GasUsed:  0,
		BaseFee:  big.NewInt(1e9),
	}
	result := calculateNextBaseFee(parent)
	if result == nil || result.Sign() <= 0 {
		t.Error("expected positive base fee with zero gas limit")
	}
}

func TestCalculateNextBaseFee_FullBlock(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 30000000,
		GasUsed:  30000000, // 100% usage
		BaseFee:  big.NewInt(1e9),
	}
	result := calculateNextBaseFee(parent)
	if result.Cmp(big.NewInt(1e9)) <= 0 {
		t.Errorf("expected increased base fee for full block, got %s", result.String())
	}
}

func TestCalculateNextBaseFee_EmptyBlock(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 30000000,
		GasUsed:  0, // 0% usage
		BaseFee:  big.NewInt(1e9),
	}
	result := calculateNextBaseFee(parent)
	if result.Cmp(big.NewInt(1e9)) >= 0 {
		t.Errorf("expected decreased base fee for empty block, got %s", result.String())
	}
}

func TestCalculateNextBaseFee_NeverGoesNegative(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 30000000,
		GasUsed:  0,
		BaseFee:  big.NewInt(1), // very small base fee
	}
	result := calculateNextBaseFee(parent)
	if result.Sign() <= 0 {
		t.Error("base fee should never go to zero or negative")
	}
}

// ── BlockProducer creation tests ──

func TestNewBlockProducer_DevMode(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false
	cfg.ValidatorEnabled = true
	cfg.ValidatorKey = ""

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 3*time.Second)
	if bp == nil {
		t.Fatal("expected non-nil block producer")
	}
}

func TestBlockProducer_ValidatorAddr(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 3*time.Second)
	addr := bp.ValidatorAddr()
	// In dev mode without a key, address should be empty or generated
	_ = addr
}

func TestBlockProducer_ValidatorKey(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 3*time.Second)
	key := bp.ValidatorKey()
	// Without a key file, key should be nil
	_ = key
}

func TestBlockProducer_QPOS(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 3*time.Second)
	qpos := bp.QPOS()
	// Without initialization, QPOS should be nil
	_ = qpos
}

func TestBlockProducer_QPOSAdvanced(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 3*time.Second)
	qposAdv := bp.QPOSAdvanced()
	_ = qposAdv
}

func TestBlockProducer_MEVProtection(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 3*time.Second)
	mev := bp.MEVProtection()
	_ = mev
}

// ── BlockProducer Start/Stop ──

func TestBlockProducer_StartStop(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 3*time.Second)

	// Start should work
	err = bp.Start()
	if err != nil {
		t.Fatalf("BlockProducer Start failed: %v", err)
	}

	// Stop should work
	bp.Stop()

	// Double stop should not panic
	bp.Stop()
}

// ── computeValidatorAddress ──

func TestComputeValidatorAddress(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 3*time.Second)
	addr := bp.computeValidatorAddress()
	// Without a key, should return empty address
	_ = addr
}

// ── Node Getters ──

func TestNode_Getters(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	// Test all getters don't panic
	_ = n.Config()
	_ = n.ChainID()
	_ = n.NetworkID()
	_ = n.ProtocolVersion()
	_ = n.IsSyncing()
	_ = n.PeerCount()
	_ = n.CurrentBlock()
	_ = n.CurrentHeight()
	_ = n.IsRunning()
	_ = n.GenesisBlock()
	_ = n.ParallelQVM()
	_ = n.MultiCache()
	_ = n.ShutdownHandler()
	_ = n.HealthServer()
	_ = n.RecoveryManager()
}

func TestNode_BlockStore(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bs := n.BlockStore()
	// Before start, block store may be nil
	_ = bs
}

func TestNode_StateDB(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	sdb := n.StateDB()
	_ = sdb
}

func TestNode_TxPool(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	tp := n.TxPool()
	_ = tp
}

func TestNode_P2PHost(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	host := n.P2PHost()
	_ = host
}

// ── Node validateProductionConfig ──

func TestNode_ValidateProductionConfig_DevModeOnMainnet(t *testing.T) {
	// NewNode already validates this in Config.Validate(),
	// so we can't create a node with DevMode on mainnet.
	// Instead, test the config validation directly.
	cfg := &Config{
		Name:      "test",
		DataDir:   t.TempDir(),
		Network:   NetworkMainnet,
		NetworkID: MainnetNetworkID,
		DevMode:   true,
	}
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for dev mode on mainnet in config validation")
	}
}

func TestNode_ValidateProductionConfig_DevModeOnTestnet(t *testing.T) {
	cfg := &Config{
		Name:      "test",
		DataDir:   t.TempDir(),
		Network:   NetworkTestnet,
		NetworkID: TestnetNetworkID,
		DevMode:   true,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for dev mode on testnet")
	}
}

func TestNode_ValidateProductionConfig_ProductionMainnet(t *testing.T) {
	cfg := &Config{
		Name:      "test",
		DataDir:   t.TempDir(),
		NetworkID: MainnetNetworkID,
		DevMode:   false,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	err = n.validateProductionConfig()
	if err != nil {
		t.Errorf("production mainnet should be valid, got: %v", err)
	}
}

// ── Node Start/Stop lifecycle ──
// Note: Full Start/Stop tests are in integration_test.go because BoltDB
// file locking on Windows prevents TempDir cleanup in unit tests.

func TestNode_StopWithoutStart(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	err = n.Stop()
	if err == nil {
		t.Error("expected error for stop without start")
	}
}

// ── Node with nil config ──

func TestNewNode_NilConfig(t *testing.T) {
	n, err := NewNode(nil)
	if err != nil {
		t.Fatalf("NewNode with nil config should use defaults, got: %v", err)
	}
	defer closeNodeDB(n)
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

// ── hashToAddress helper ──

func TestHashToAddress(t *testing.T) {
	addr := hashToAddress("test-string")
	if addr.IsEmpty() {
		t.Error("expected non-empty address from hash")
	}
}

// ── filterHexChars helper ──

func TestFilterHexChars(t *testing.T) {
	tests := []struct {
		input    []byte
		expected []byte
	}{
		{[]byte("0x1234"), []byte("01234")}, // 'x' is not hex
		{[]byte("0x12 34"), []byte("01234")},
		{[]byte("0x12\n34"), []byte("01234")},
		{[]byte("abcxyz"), []byte("abc")}, // 'x' is not hex
		{[]byte(""), []byte("")},
	}
	for _, tt := range tests {
		result := filterHexChars(tt.input)
		if string(result) != string(tt.expected) {
			t.Errorf("filterHexChars(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// ── isHexASCII helper ──

func TestIsHexASCII(t *testing.T) {
	if !isHexASCII([]byte("1234abcd")) {
		t.Error("expected valid hex ASCII to return true")
	}
	if isHexASCII([]byte("12g34")) {
		t.Error("expected invalid hex ASCII to return false")
	}
	if !isHexASCII([]byte("")) {
		t.Error("expected empty string to be valid hex ASCII")
	}
}

// ── Extended EIP-1559 base fee tests ──

func TestCalculateNextBaseFee_SmallBaseFee(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 30000000,
		GasUsed:  0,
		BaseFee:  big.NewInt(2), // very small, should not go to 0
	}
	result := calculateNextBaseFee(parent)
	if result.Sign() <= 0 {
		t.Errorf("base fee should stay positive, got %s", result.String())
	}
	if result.Cmp(big.NewInt(1)) < 0 {
		t.Errorf("base fee should be at least 1, got %s", result.String())
	}
}

func TestCalculateNextBaseFee_LargeBaseFee(t *testing.T) {
	largeFee := new(big.Int).Mul(big.NewInt(1e9), big.NewInt(1000)) // 1000 Gwei
	parent := &encoding.BlockHeader{
		GasLimit: 30000000,
		GasUsed:  20000000, // above target
		BaseFee:  largeFee,
	}
	result := calculateNextBaseFee(parent)
	if result.Cmp(largeFee) <= 0 {
		t.Errorf("expected increased base fee, got %s", result.String())
	}
}

func TestCalculateNextBaseFee_ExactlyHalfGasUsed(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 20000000,
		GasUsed:  10000000, // exactly 50%
		BaseFee:  big.NewInt(2e9),
	}
	result := calculateNextBaseFee(parent)
	if result.Cmp(big.NewInt(2e9)) != 0 {
		t.Errorf("expected same base fee at exactly 50%% usage, got %s", result.String())
	}
}

func TestCalculateNextBaseFee_SlightlyAboveTarget(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 30000000,
		GasUsed:  15000001, // just above 50%
		BaseFee:  big.NewInt(1e9),
	}
	result := calculateNextBaseFee(parent)
	if result.Cmp(big.NewInt(1e9)) <= 0 {
		t.Errorf("expected slightly increased base fee, got %s", result.String())
	}
}

func TestCalculateNextBaseFee_SlightlyBelowTarget(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 30000000,
		GasUsed:  14999999, // just below 50%
		BaseFee:  big.NewInt(1e9),
	}
	result := calculateNextBaseFee(parent)
	if result.Cmp(big.NewInt(1e9)) >= 0 {
		t.Errorf("expected slightly decreased base fee, got %s", result.String())
	}
}

func TestCalculateNextBaseFee_MaxIncreaseRate(t *testing.T) {
	// EIP-1559: max increase per block is ~12.5% (1/8)
	parent := &encoding.BlockHeader{
		GasLimit: 30000000,
		GasUsed:  30000000, // 100% usage → max increase
		BaseFee:  big.NewInt(1e9),
	}
	result := calculateNextBaseFee(parent)
	maxExpected := new(big.Int).Mul(big.NewInt(1e9), big.NewRat(9, 8).Num())
	maxExpected.Div(maxExpected, big.NewRat(9, 8).Denom())
	// The result should not exceed 1.125x the parent base fee
	ratio := new(big.Int).Mul(result, big.NewInt(8))
	expectedMax := new(big.Int).Mul(big.NewInt(1e9), big.NewInt(9))
	if ratio.Cmp(expectedMax) > 0 {
		t.Errorf("base fee increase exceeds 12.5%%: got %s, max expected ~%s", result.String(), expectedMax.String())
	}
}

func TestCalculateNextBaseFee_DefaultGasLimit(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 0,
		GasUsed:  0,
		BaseFee:  big.NewInt(1e9),
	}
	result := calculateNextBaseFee(parent)
	// With zero gas limit, should use default (21000000) and target = 10500000
	// GasUsed=0 < target, so base fee should decrease
	if result == nil || result.Sign() <= 0 {
		t.Error("expected positive base fee with zero gas limit")
	}
}

func TestCalculateNextBaseFee_NegativeBaseFee(t *testing.T) {
	parent := &encoding.BlockHeader{
		GasLimit: 30000000,
		GasUsed:  15000000,
		BaseFee:  big.NewInt(-1), // negative
	}
	result := calculateNextBaseFee(parent)
	// Negative base fee should be treated as nil/zero → return initial 1 Gwei
	if result.Cmp(big.NewInt(1e9)) != 0 {
		t.Errorf("expected 1 Gwei for negative base fee, got %s", result.String())
	}
}

// ── hashToAddress determinism ──

func TestHashToAddress_Deterministic(t *testing.T) {
	addr1 := hashToAddress("test-string")
	addr2 := hashToAddress("test-string")
	if addr1 != addr2 {
		t.Error("hashToAddress should be deterministic for same input")
	}
}

func TestHashToAddress_DifferentInputs(t *testing.T) {
	addr1 := hashToAddress("input-a")
	addr2 := hashToAddress("input-b")
	if addr1 == addr2 {
		t.Error("hashToAddress should produce different addresses for different inputs")
	}
}

// ── filterHexChars extended ──

func TestFilterHexChars_AllHex(t *testing.T) {
	input := []byte("0123456789abcdefABCDEF")
	result := filterHexChars(input)
	if string(result) != string(input) {
		t.Errorf("expected all chars preserved, got %q", result)
	}
}

func TestFilterHexChars_NoHex(t *testing.T) {
	input := []byte("xyz!@#")
	result := filterHexChars(input)
	if len(result) != 0 {
		t.Errorf("expected empty result for non-hex input, got %q", result)
	}
}

// ── isHexASCII extended ──

func TestIsHexASCII_OddLength(t *testing.T) {
	if isHexASCII([]byte("abc")) {
		t.Error("odd-length hex string should return false")
	}
}

func TestIsHexASCII_Uppercase(t *testing.T) {
	if !isHexASCII([]byte("ABCDEF")) {
		t.Error("uppercase hex should be valid")
	}
}

func TestIsHexASCII_MixedCase(t *testing.T) {
	if !isHexASCII([]byte("aAbBcCdDeEfF")) {
		t.Error("mixed case hex should be valid")
	}
}

// ── parseValidatorPrivateKeyFile tests ──

func TestParseValidatorPrivateKeyFile_InvalidFormat(t *testing.T) {
	_, err := parseValidatorPrivateKeyFile([]byte("not-a-key"))
	if err == nil {
		t.Error("expected error for invalid key format")
	}
}

func TestParseValidatorPrivateKeyFile_EmptyData(t *testing.T) {
	_, err := parseValidatorPrivateKeyFile([]byte(""))
	if err == nil {
		t.Error("expected error for empty key data")
	}
}

// ── BlockProducer with default interval ──

func TestNewBlockProducer_DefaultInterval(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	// Zero interval should default to 12 seconds
	bp := NewBlockProducer(n, 0)
	if bp == nil {
		t.Fatal("expected non-nil block producer with zero interval")
	}
	if bp.interval != 12*time.Second {
		t.Errorf("expected default interval 12s, got %v", bp.interval)
	}
}

// ── BlockProducer double start ──

func TestBlockProducer_DoubleStart(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 3*time.Second)

	err = bp.Start()
	if err != nil {
		t.Fatalf("first Start failed: %v", err)
	}

	// Second start should return nil (already running)
	err = bp.Start()
	if err != nil {
		t.Errorf("second Start should return nil, got: %v", err)
	}

	bp.Stop()
}

// ── parseStake tests ──

func TestParseStake_Decimal(t *testing.T) {
	result := parseStake("1000000")
	if result.Cmp(big.NewInt(1000000)) != 0 {
		t.Errorf("expected 1000000, got %s", result.String())
	}
}

func TestParseStake_Hex(t *testing.T) {
	result := parseStake("0xf4240")
	if result.Cmp(big.NewInt(1000000)) != 0 {
		t.Errorf("expected 1000000, got %s", result.String())
	}
}

func TestParseStake_Invalid(t *testing.T) {
	result := parseStake("not-a-number")
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("expected 0 for invalid stake, got %s", result.String())
	}
}

func TestParseStake_Empty(t *testing.T) {
	result := parseStake("")
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("expected 0 for empty stake, got %s", result.String())
	}
}

// ── GetCurrentSlot tests ──

func TestBlockProducer_GetCurrentSlot(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 12*time.Second)
	slot := bp.GetCurrentSlot()
	// Slot should be a non-negative value
	if slot < 0 {
		t.Errorf("expected non-negative slot, got %d", slot)
	}
}

// ── getSlotStartTime tests ──

func TestBlockProducer_GetSlotStartTime(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 12*time.Second)
	startTime := bp.getSlotStartTime(0)
	if startTime.IsZero() {
		t.Error("expected non-zero start time for slot 0")
	}

	// Slot 1 should be after slot 0
	startTime1 := bp.getSlotStartTime(1)
	if !startTime1.After(startTime) {
		t.Error("expected slot 1 start time to be after slot 0")
	}
}

func TestBlockProducer_GetSlotStartTime_Interval(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 6*time.Second)
	startTime0 := bp.getSlotStartTime(0)
	startTime1 := bp.getSlotStartTime(1)
	diff := startTime1.Sub(startTime0)
	if diff != 6*time.Second {
		t.Errorf("expected 6s interval between slots, got %v", diff)
	}
}

// ── computeValidatorAddress determinism ──

func TestComputeValidatorAddress_Deterministic(t *testing.T) {
	cfg1 := DevConfig()
	cfg1.DataDir = t.TempDir()
	cfg1.Name = "test-deterministic"
	cfg1.RPCEnabled = false
	cfg1.WSEnabled = false
	cfg1.MetricsEnabled = false
	cfg1.HealthEnabled = false

	cfg2 := DevConfig()
	cfg2.DataDir = t.TempDir()
	cfg2.Name = "test-deterministic"
	cfg2.RPCEnabled = false
	cfg2.WSEnabled = false
	cfg2.MetricsEnabled = false
	cfg2.HealthEnabled = false

	n1, _ := NewNode(cfg1)
	defer closeNodeDB(n1)
	n2, _ := NewNode(cfg2)
	defer closeNodeDB(n2)

	bp1 := NewBlockProducer(n1, 12*time.Second)
	bp2 := NewBlockProducer(n2, 12*time.Second)

	addr1 := bp1.computeValidatorAddress()
	addr2 := bp2.computeValidatorAddress()

	if addr1 != addr2 {
		t.Error("computeValidatorAddress should be deterministic for same node name")
	}
}

func TestComputeValidatorAddress_DifferentNames(t *testing.T) {
	cfg1 := DevConfig()
	cfg1.DataDir = t.TempDir()
	cfg1.Name = "node-alpha"
	cfg1.RPCEnabled = false
	cfg1.WSEnabled = false
	cfg1.MetricsEnabled = false
	cfg1.HealthEnabled = false

	cfg2 := DevConfig()
	cfg2.DataDir = t.TempDir()
	cfg2.Name = "node-beta"
	cfg2.RPCEnabled = false
	cfg2.WSEnabled = false
	cfg2.MetricsEnabled = false
	cfg2.HealthEnabled = false

	n1, _ := NewNode(cfg1)
	defer closeNodeDB(n1)
	n2, _ := NewNode(cfg2)
	defer closeNodeDB(n2)

	bp1 := NewBlockProducer(n1, 12*time.Second)
	bp2 := NewBlockProducer(n2, 12*time.Second)

	addr1 := bp1.computeValidatorAddress()
	addr2 := bp2.computeValidatorAddress()

	if addr1 == addr2 {
		t.Error("different node names should produce different validator addresses")
	}
}

// ── BlockProducer QPOS engine ──

func TestBlockProducer_QPOSEngine(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, _ := NewNode(cfg)
	defer closeNodeDB(n)
	bp := NewBlockProducer(n, 12*time.Second)

	qpos := bp.QPOS()
	if qpos == nil {
		t.Error("expected non-nil QPOS engine after init")
	}
}

// ── BlockProducer validator set ──

func TestBlockProducer_ValidatorSet(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, _ := NewNode(cfg)
	defer closeNodeDB(n)
	bp := NewBlockProducer(n, 12*time.Second)

	vs := bp.validatorSet
	if vs == nil {
		t.Error("expected non-nil validator set after init")
	}
}

// ── BlockProducer with genesis validators ──

func TestBlockProducer_WithGenesisValidators(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, _ := NewNode(cfg)
	defer closeNodeDB(n)
	// Set genesis on the node directly
	n.genesis = &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Validators: []GenesisValidator{
			{Address: "0x1234567890123456789012345678901234567890", PublicKey: "0xabcd", Stake: "500000"},
			{Address: "0xabcdef0123456789abcdef0123456789abcdef01", PublicKey: "0xef01", Stake: "300000"},
		},
	}

	bp := NewBlockProducer(n, 12*time.Second)

	vs := bp.validatorSet
	if vs == nil {
		t.Fatal("expected non-nil validator set")
	}
	// Should have 2 validators from genesis
	if vs.Size() != 2 {
		t.Errorf("expected 2 validators from genesis, got %d", vs.Size())
	}
}
