// Quantaureum Node source, version 1.0.0.
package params

import (
	"math/big"
	"testing"
)

func TestChainIDs(t *testing.T) {
	if MainnetChainID != 1668 {
		t.Errorf("expected 1668, got %d", MainnetChainID)
	}
	if TestnetChainID != 1669 {
		t.Errorf("expected 1669, got %d", TestnetChainID)
	}
	if DevnetChainID != 1333 {
		t.Errorf("expected 1333, got %d", DevnetChainID)
	}
}

func TestNetworkIDs(t *testing.T) {
	if MainnetNetworkID != MainnetChainID {
		t.Error("network ID should match chain ID")
	}
	if TestnetNetworkID != TestnetChainID {
		t.Error("network ID should match chain ID")
	}
}

func TestBlockParameters(t *testing.T) {
	if BlockGasLimit != 30000000 {
		t.Errorf("expected 30000000, got %d", BlockGasLimit)
	}
	if BlockTime != 12 {
		t.Errorf("expected 12, got %d", BlockTime)
	}
	if MaxBlockSize != 5*1024*1024 {
		t.Errorf("expected 5MB, got %d", MaxBlockSize)
	}
}

func TestTxParameters(t *testing.T) {
	if TxGas != 21000 {
		t.Errorf("expected 21000, got %d", TxGas)
	}
	if TxDataZeroGas != 4 {
		t.Errorf("expected 4, got %d", TxDataZeroGas)
	}
	if TxDataNonZeroGas != 16 {
		t.Errorf("expected 16, got %d", TxDataNonZeroGas)
	}
}

func TestEIP1559Parameters(t *testing.T) {
	if InitialBaseFee != 1000000000 {
		t.Errorf("expected 1 Gwei, got %d", InitialBaseFee)
	}
	if BaseFeeMaxChangeDenom != 8 {
		t.Errorf("expected 8, got %d", BaseFeeMaxChangeDenom)
	}
	if ElasticityMultiplier != 2 {
		t.Errorf("expected 2, got %d", ElasticityMultiplier)
	}
}

func TestStakingParameters(t *testing.T) {
	if MinValidatorStake != 32 {
		t.Errorf("expected 32, got %d", MinValidatorStake)
	}
	if MinDelegatorStake != 1 {
		t.Errorf("expected 1, got %d", MinDelegatorStake)
	}
	if UnbondingPeriod != 21 {
		t.Errorf("expected 21, got %d", UnbondingPeriod)
	}
	if SlashingPenalty != 10 {
		t.Errorf("expected 10, got %d", SlashingPenalty)
	}
}

func TestConsensusParameters(t *testing.T) {
	if ValidatorSetSize != 100 {
		t.Errorf("expected 100, got %d", ValidatorSetSize)
	}
	if EpochLength != 32 {
		t.Errorf("expected 32, got %d", EpochLength)
	}
	if FinalityThreshold != 67 {
		t.Errorf("expected 67, got %d", FinalityThreshold)
	}
}

func TestNetworkParameters(t *testing.T) {
	if MaxPeers != 50 {
		t.Errorf("expected 50, got %d", MaxPeers)
	}
	if DefaultP2PPort != 9000 {
		t.Errorf("expected 9000, got %d", DefaultP2PPort)
	}
	if DefaultRPCPort != 8545 {
		t.Errorf("expected 8545, got %d", DefaultRPCPort)
	}
	if DefaultWSPort != 8546 {
		t.Errorf("expected 8546, got %d", DefaultWSPort)
	}
}

func TestTokenParameters(t *testing.T) {
	expectedSupply := new(big.Int).Mul(big.NewInt(20000000), big.NewInt(1e18))
	if TotalSupply.Cmp(expectedSupply) != 0 {
		t.Errorf("total supply mismatch")
	}
	if Decimals != 18 {
		t.Errorf("expected 18, got %d", Decimals)
	}
	if Symbol != "QAU" {
		t.Errorf("expected QAU, got %s", Symbol)
	}
	if Name != "Quantaureum" {
		t.Errorf("expected Quantaureum, got %s", Name)
	}
}

func TestVersion(t *testing.T) {
	v := Version()
	if v == "" {
		t.Error("expected non-empty version string")
	}
	if v != "1.0.0-stable" {
		t.Errorf("expected 1.0.0-stable, got %s", v)
	}
}

func TestVersionConstants(t *testing.T) {
	if VersionMajor != 1 {
		t.Errorf("expected 1, got %d", VersionMajor)
	}
	if VersionMinor != 0 {
		t.Errorf("expected 0, got %d", VersionMinor)
	}
	if VersionPatch != 0 {
		t.Errorf("expected 0, got %d", VersionPatch)
	}
	if VersionMeta != "stable" {
		t.Errorf("expected stable, got %s", VersionMeta)
	}
}

func TestGasPriceBounds(t *testing.T) {
	if MinGasPrice <= 0 {
		t.Error("min gas price should be positive")
	}
	if MaxGasPrice <= MinGasPrice {
		t.Error("max gas price should be > min gas price")
	}
}

func TestPriorityFeeBounds(t *testing.T) {
	if MinPriorityFee <= 0 {
		t.Error("min priority fee should be positive")
	}
	if MaxPriorityFee <= MinPriorityFee {
		t.Error("max priority fee should be > min priority fee")
	}
}

func TestChainIDRange(t *testing.T) {
	if MinChainID != 1 {
		t.Errorf("expected 1, got %d", MinChainID)
	}
	if MaxChainID != 65535 {
		t.Errorf("expected 65535, got %d", MaxChainID)
	}
}

func TestAllowedZeroChainIDNetworks(t *testing.T) {
	networks := AllowedZeroChainIDNetworks
	if len(networks) == 0 {
		t.Error("expected non-empty networks map")
	}
	expected := []string{"localhost", "127.0.0.1", "hardhat", "ganache", "testnet-local"}
	for _, name := range expected {
		if !networks[name] {
			t.Errorf("expected %s to be allowed", name)
		}
	}
}

func TestIsZeroChainIDAllowed(t *testing.T) {
	tests := []struct {
		name    string
		network string
		want    bool
	}{
		{"localhost", "localhost", true},
		{"loopback", "127.0.0.1", true},
		{"hardhat", "hardhat", true},
		{"ganache", "ganache", true},
		{"testnet_local", "testnet-local", true},
		{"mainnet", "mainnet", false},
		{"unknown", "some-random-network", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsZeroChainIDAllowed(tt.network); got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestCryptographyParameters(t *testing.T) {
	if DilithiumPublicKeySize != 1952 {
		t.Errorf("expected 1952, got %d", DilithiumPublicKeySize)
	}
	if DilithiumPrivateKeySize != 4000 {
		t.Errorf("expected 4000, got %d", DilithiumPrivateKeySize)
	}
	if DilithiumSignatureSize != 3293 {
		t.Errorf("expected 3293, got %d", DilithiumSignatureSize)
	}
	if KyberPublicKeySize != 1184 {
		t.Errorf("expected 1184, got %d", KyberPublicKeySize)
	}
	if KyberPrivateKeySize != 2400 {
		t.Errorf("expected 2400, got %d", KyberPrivateKeySize)
	}
	if KyberCiphertextSize != 1088 {
		t.Errorf("expected 1088, got %d", KyberCiphertextSize)
	}
	if KyberSharedKeySize != 32 {
		t.Errorf("expected 32, got %d", KyberSharedKeySize)
	}
	if AddressLength != 20 {
		t.Errorf("expected 20, got %d", AddressLength)
	}
	if HashLength != 32 {
		t.Errorf("expected 32, got %d", HashLength)
	}
}

func TestQVMParameters(t *testing.T) {
	if MaxCodeSize != 24576 {
		t.Errorf("expected 24576, got %d", MaxCodeSize)
	}
	if MaxCallDepth != 1024 {
		t.Errorf("expected 1024, got %d", MaxCallDepth)
	}
	if MaxStackSize != 1024 {
		t.Errorf("expected 1024, got %d", MaxStackSize)
	}
	if MaxMemorySize != 32*1024*1024 {
		t.Errorf("expected 32MB, got %d", MaxMemorySize)
	}
	if CallGas != 700 {
		t.Errorf("expected 700, got %d", CallGas)
	}
	if CreateGas != 32000 {
		t.Errorf("expected 32000, got %d", CreateGas)
	}
	if SstoreSetGas != 20000 {
		t.Errorf("expected 20000, got %d", SstoreSetGas)
	}
	if SstoreResetGas != 5000 {
		t.Errorf("expected 5000, got %d", SstoreResetGas)
	}
	if SloadGas != 800 {
		t.Errorf("expected 800, got %d", SloadGas)
	}
}

func TestStorageParameters(t *testing.T) {
	if MaxTrieCacheSize != 256 {
		t.Errorf("expected 256, got %d", MaxTrieCacheSize)
	}
	if PruningRetention != 128 {
		t.Errorf("expected 128, got %d", PruningRetention)
	}
	if SnapshotInterval != 1024 {
		t.Errorf("expected 1024, got %d", SnapshotInterval)
	}
}

func TestSyncParameters(t *testing.T) {
	if MaxBlockFetch != 128 {
		t.Errorf("expected 128, got %d", MaxBlockFetch)
	}
	if MaxHeaderFetch != 192 {
		t.Errorf("expected 192, got %d", MaxHeaderFetch)
	}
	if MaxReceiptFetch != 256 {
		t.Errorf("expected 256, got %d", MaxReceiptFetch)
	}
	if SyncTimeout != 30 {
		t.Errorf("expected 30, got %d", SyncTimeout)
	}
}

func TestBlockReward(t *testing.T) {
	if BlockReward != 2e18 {
		t.Errorf("expected 2e18, got %v", BlockReward)
	}
}
