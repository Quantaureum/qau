// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestExperimentalTDilithium3V1EnabledSingleSwitch(t *testing.T) {
	tests := []struct {
		name   string
		enable string
		want   bool
	}{
		{name: "disabled by default"},
		{name: "enabled", enable: "1", want: true},
		{name: "non-one value stays disabled", enable: "true"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", test.enable)
			if got := experimentalTDilithium3V1Enabled(); got != test.want {
				t.Fatalf("experimentalTDilithium3V1Enabled() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestExperimentalTDilithium3V1EnabledForNetworkDoubleGate(t *testing.T) {
	tests := []struct {
		name    string
		enable  string
		mainnet string
		network uint64
		want    bool
	}{
		{name: "experimental gate closed keeps every network off", network: TestnetNetworkID},
		{name: "testnet opens with the experimental gate alone", enable: "1", network: TestnetNetworkID, want: true},
		{name: "devnet opens with the experimental gate alone", enable: "1", network: 1333, want: true},
		{name: "mainnet stays closed without the acknowledgement", enable: "1", network: MainnetNetworkID},
		{name: "mainnet acknowledgement without the experimental gate is not enough", mainnet: "1", network: MainnetNetworkID},
		{name: "mainnet requires both switches", enable: "1", mainnet: "1", network: MainnetNetworkID, want: true},
		{name: "a non-one acknowledgement keeps mainnet closed", enable: "1", mainnet: "true", network: MainnetNetworkID},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", test.enable)
			t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_MAINNET", test.mainnet)
			if got := experimentalTDilithium3V1EnabledForNetwork(test.network); got != test.want {
				t.Fatalf("experimentalTDilithium3V1EnabledForNetwork(%d) = %v, want %v", test.network, got, test.want)
			}
		})
	}
}

func TestThresholdBackendSelectionMatrix(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1", "1")

	allAvailable := map[thresholdBackendKind]bool{
		thresholdBackendLegacyUnsafe:          true,
		thresholdBackendDilithium3V1:          true,
		thresholdBackendMLDSA65ExperimentalV1: true,
	}
	tests := []struct {
		name      string
		protocol  protocol.ThresholdProtocol
		algorithm qcrypto.SignatureAlgorithm
		want      thresholdBackendKind
		wantErr   bool
	}{
		{name: "legacy unsafe", protocol: protocol.ThresholdProtocolLegacyUnsafe, algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, want: thresholdBackendLegacyUnsafe},
		{name: "dilithium v1", protocol: protocol.ThresholdProtocolDilithium3V1, algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, want: thresholdBackendDilithium3V1},
		{name: "mldsa experimental", protocol: protocol.ThresholdProtocolMLDSA65ExperimentalV1, algorithm: qcrypto.SignatureAlgorithmMLDSA65, want: thresholdBackendMLDSA65ExperimentalV1},
		{name: "unknown protocol", protocol: protocol.ThresholdProtocolUnknown, algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, wantErr: true},
		{name: "dilithium protocol with mldsa", protocol: protocol.ThresholdProtocolDilithium3V1, algorithm: qcrypto.SignatureAlgorithmMLDSA65, wantErr: true},
		{name: "mldsa protocol with dilithium", protocol: protocol.ThresholdProtocolMLDSA65ExperimentalV1, algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := selectThresholdBackendKind(test.protocol, test.algorithm, allAvailable)
			if (err != nil) != test.wantErr {
				t.Fatalf("selectThresholdBackendKind() error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && got != test.want {
				t.Fatalf("selected kind = %v, want %v", got, test.want)
			}
		})
	}
}

func TestDilithiumV1SelectionNeverFallsBack(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")

	available := map[thresholdBackendKind]bool{thresholdBackendLegacyUnsafe: true}
	if _, err := selectThresholdBackendKind(
		protocol.ThresholdProtocolDilithium3V1,
		qcrypto.SignatureAlgorithmDilithium3Legacy,
		available,
	); err == nil {
		t.Fatal("Dilithium3 v1 selection fell back to the legacy unsafe backend")
	}
}

func TestDilithiumV1SelectionRequiresEnableSwitch(t *testing.T) {
	available := map[thresholdBackendKind]bool{thresholdBackendDilithium3V1: true}
	tests := []struct {
		name   string
		enable string
	}{
		{name: "disabled by default"},
		{name: "non-one value stays disabled", enable: "true"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", test.enable)
			if _, err := selectThresholdBackendKind(
				protocol.ThresholdProtocolDilithium3V1,
				qcrypto.SignatureAlgorithmDilithium3Legacy,
				available,
			); err == nil {
				t.Fatal("Dilithium3 v1 selected without the enable switch")
			}
		})
	}

	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	kind, err := selectThresholdBackendKind(
		protocol.ThresholdProtocolDilithium3V1,
		qcrypto.SignatureAlgorithmDilithium3Legacy,
		available,
	)
	if err != nil {
		t.Fatalf("select Dilithium3 v1 backend with enable switch: %v", err)
	}
	if kind != thresholdBackendDilithium3V1 {
		t.Fatalf("selected kind = %v, want Dilithium3 v1", kind)
	}
}
