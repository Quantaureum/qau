// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestExperimentalTMLDSAV1EnabledSingleSwitch(t *testing.T) {
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
			t.Setenv("QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1", test.enable)
			if got := experimentalTMLDSAV1Enabled(); got != test.want {
				t.Fatalf("experimentalTMLDSAV1Enabled() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSelectThresholdBackendKindNeverFallsBackForMLDSA(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1", "1")

	if _, err := selectThresholdBackendKind(
		protocol.ThresholdProtocolMLDSA65ExperimentalV1,
		qcrypto.SignatureAlgorithmMLDSA65,
		map[thresholdBackendKind]bool{thresholdBackendLegacyUnsafe: true},
	); err == nil {
		t.Fatal("ML-DSA selection must not fall back to an available legacy signer")
	}
	kind, err := selectThresholdBackendKind(
		protocol.ThresholdProtocolMLDSA65ExperimentalV1,
		qcrypto.SignatureAlgorithmMLDSA65,
		map[thresholdBackendKind]bool{thresholdBackendMLDSA65ExperimentalV1: true, thresholdBackendLegacyUnsafe: true},
	)
	if err != nil {
		t.Fatalf("select ML-DSA backend: %v", err)
	}
	if kind != thresholdBackendTMLDSAV1 {
		t.Fatalf("selected kind = %v, want TMLDSA v1", kind)
	}
}

func TestSelectThresholdBackendKindLegacyAndUnknown(t *testing.T) {
	kind, err := selectThresholdBackendKind(
		protocol.ThresholdProtocolLegacyUnsafe,
		qcrypto.SignatureAlgorithmDilithium3Legacy,
		map[thresholdBackendKind]bool{thresholdBackendLegacyUnsafe: true},
	)
	if err != nil {
		t.Fatalf("select legacy backend: %v", err)
	}
	if kind != thresholdBackendLegacy {
		t.Fatalf("selected kind = %v, want legacy", kind)
	}
	if _, err := selectThresholdBackendKind(
		protocol.ThresholdProtocolLegacyUnsafe,
		qcrypto.SignatureAlgorithmDilithium3Legacy,
		map[thresholdBackendKind]bool{},
	); err == nil {
		t.Fatal("missing legacy backend must fail")
	}
	if _, err := selectThresholdBackendKind(
		protocol.ThresholdProtocolUnknown,
		qcrypto.SignatureAlgorithmUnknown,
		map[thresholdBackendKind]bool{thresholdBackendMLDSA65ExperimentalV1: true, thresholdBackendLegacyUnsafe: true},
	); err == nil {
		t.Fatal("unknown algorithm must fail")
	}
}
