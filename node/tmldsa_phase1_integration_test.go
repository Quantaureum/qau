// Quantaureum Node source, version 1.0.0.
package node

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestTMLDSAPhase1FoundationIntegration(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1", "1")

	publicKey, privateKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ML-DSA-65 key: %v", err)
	}
	request := protocol.SignRequest{
		Protocol: protocol.ThresholdProtocolMLDSA65ExperimentalV1,
		Key: protocol.ThresholdKeyID{
			Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
			Generation: 1,
			PublicKey:  publicKey.Bytes(),
		},
		Committee: protocol.CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}},
		ChainID:   1669,
		Epoch:     1,
		Slot:      33,
		Domain:    protocol.SigningDomainFinality,
		Message:   []byte("phase-1-finality-message"),
		Context:   []byte("qau-finality-v1"),
	}
	request.AttemptNonce[0] = 0x33
	sessionID, err := protocol.SigningSessionID(request)
	if err != nil {
		t.Fatalf("derive signing session: %v", err)
	}

	record, err := protocol.NewSingleUseRecordForProtocol(protocol.ThresholdProtocolMLDSA65ExperimentalV1, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := record.Transition(protocol.SingleUsePrepared, []byte("encrypted-prepared-state"))
	if err != nil {
		t.Fatal(err)
	}
	committed, err := prepared.Transition(protocol.SingleUseCommitted, []byte("public-commitment"))
	if err != nil {
		t.Fatal(err)
	}

	firstNode := testTMLDSAJournalNode(t)
	if err := firstNode.persistTMLDSASigningRecord(prepared); err != nil {
		t.Fatal(err)
	}
	if err := firstNode.persistTMLDSASigningRecord(committed); err != nil {
		t.Fatal(err)
	}
	restartedNode := &Node{config: firstNode.config}
	recovered, found, err := restartedNode.loadTMLDSASigningRecord(sessionID)
	if err != nil {
		t.Fatalf("restart recovery: %v", err)
	}
	if !found || recovered.State != protocol.SingleUseBurned {
		t.Fatalf("recovered state = %v, found=%v", recovered.State, found)
	}

	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(privateKey, request.Message, request.Context, false, signature); err != nil {
		t.Fatalf("sign ML-DSA-65: %v", err)
	}
	if err := qcrypto.VerifySignatureForAlgorithm(
		qcrypto.SignatureAlgorithmMLDSA65,
		request.Key.PublicKey,
		request.Message,
		request.Context,
		signature,
	); err != nil {
		t.Fatalf("verify ML-DSA-65: %v", err)
	}

	kind, err := selectThresholdBackendKind(
		protocol.ThresholdProtocolMLDSA65ExperimentalV1,
		qcrypto.SignatureAlgorithmMLDSA65,
		map[thresholdBackendKind]bool{thresholdBackendMLDSA65ExperimentalV1: true, thresholdBackendLegacyUnsafe: true},
	)
	if err != nil || kind != thresholdBackendTMLDSAV1 {
		t.Fatalf("select v1 backend: kind=%v err=%v", kind, err)
	}
	if _, err := selectThresholdBackendKind(
		protocol.ThresholdProtocolMLDSA65ExperimentalV1,
		qcrypto.SignatureAlgorithmMLDSA65,
		map[thresholdBackendKind]bool{thresholdBackendLegacyUnsafe: true},
	); err == nil {
		t.Fatal("v1 generation fell back to the legacy signer")
	}
}
