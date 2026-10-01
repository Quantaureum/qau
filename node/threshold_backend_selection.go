// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"
	"os"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

type thresholdBackendKind uint8

const (
	thresholdBackendUnknown thresholdBackendKind = iota
	thresholdBackendLegacyUnsafe
	thresholdBackendDilithium3V1
	thresholdBackendMLDSA65ExperimentalV1

	thresholdBackendLegacy   = thresholdBackendLegacyUnsafe
	thresholdBackendTMLDSAV1 = thresholdBackendMLDSA65ExperimentalV1
)

// experimentalTDilithium3V1Enabled reports whether the threshold Dilithium3 v1
// protocol is selected. Activation is a single operator decision
// (QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1=1) and defaults to off, so a node
// never activates the protocol without an explicit opt-in.
func experimentalTDilithium3V1Enabled() bool {
	return os.Getenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1") == "1"
}

// experimentalTDilithium3V1EnabledForNetwork applies the network scope rule on
// top of the operator gate. Non-mainnet networks need only the experimental
// gate. Mainnet activation additionally requires the explicit
// QAU_ENABLE_TDILITHIUM3_V1_MAINNET=1 acknowledgement, so a mainnet binary
// cannot start the v1 path by carrying the experimental gate alone.
func experimentalTDilithium3V1EnabledForNetwork(networkID uint64) bool {
	if !experimentalTDilithium3V1Enabled() {
		return false
	}
	if networkID != MainnetNetworkID {
		return true
	}
	return os.Getenv("QAU_ENABLE_TDILITHIUM3_V1_MAINNET") == "1"
}

func selectThresholdBackendKind(
	thresholdProtocol protocol.ThresholdProtocol,
	algorithm qcrypto.SignatureAlgorithm,
	available map[thresholdBackendKind]bool,
) (thresholdBackendKind, error) {
	if err := thresholdProtocol.ValidateAlgorithm(algorithm); err != nil {
		return thresholdBackendUnknown, fmt.Errorf("select threshold backend: %w", err)
	}

	var selected thresholdBackendKind
	switch thresholdProtocol {
	case protocol.ThresholdProtocolLegacyUnsafe:
		selected = thresholdBackendLegacyUnsafe
	case protocol.ThresholdProtocolDilithium3V1:
		if !experimentalTDilithium3V1Enabled() {
			return thresholdBackendUnknown, fmt.Errorf("experimental threshold Dilithium3 v1 is disabled")
		}
		selected = thresholdBackendDilithium3V1
	case protocol.ThresholdProtocolMLDSA65ExperimentalV1:
		if !experimentalTMLDSAV1Enabled() {
			return thresholdBackendUnknown, fmt.Errorf("experimental TMLDSA v1 is disabled")
		}
		selected = thresholdBackendMLDSA65ExperimentalV1
	default:
		return thresholdBackendUnknown, fmt.Errorf("unsupported threshold protocol %d", thresholdProtocol)
	}

	if !available[selected] {
		return thresholdBackendUnknown, fmt.Errorf("threshold backend %d is unavailable; fallback is forbidden", selected)
	}
	return selected, nil
}
