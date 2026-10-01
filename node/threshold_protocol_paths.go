// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

type thresholdProtocolPaths struct {
	Root                  string
	Share                 string
	Active                string
	LedgerHead            string
	CandidateHead         string
	ActivationCertificate string
}

func newThresholdProtocolPaths(base string, thresholdProtocol protocol.ThresholdProtocol, generation uint64, committeeVersion uint64, participantID uint32) (thresholdProtocolPaths, error) {
	if base == "" || generation == 0 || committeeVersion == 0 || participantID == 0 {
		return thresholdProtocolPaths{}, fmt.Errorf("invalid threshold persistence identity")
	}
	var namespace string
	switch thresholdProtocol {
	case protocol.ThresholdProtocolDilithium3V1:
		namespace = "dilithium3-v1"
	case protocol.ThresholdProtocolMLDSA65ExperimentalV1:
		namespace = "mldsa65-experimental-v1"
	default:
		return thresholdProtocolPaths{}, fmt.Errorf("unsupported threshold persistence protocol %s", thresholdProtocol)
	}
	root := base + ".threshold-v1"
	protocolRoot := filepath.Join(root, namespace)
	return thresholdProtocolPaths{
		Root:                  protocolRoot,
		Share:                 filepath.Join(protocolRoot, "generations", strconv.FormatUint(generation, 10), "committees", strconv.FormatUint(committeeVersion, 10), "shares", strconv.FormatUint(uint64(participantID), 10)+".enc"),
		Active:                filepath.Join(protocolRoot, "active.enc"),
		LedgerHead:            filepath.Join(protocolRoot, "ledger", "head.enc"),
		CandidateHead:         filepath.Join(protocolRoot, "ledger", "candidate.enc"),
		ActivationCertificate: filepath.Join(protocolRoot, "ledger", "activation-certificate.enc"),
	}, nil
}
