// Quantaureum Node source, version 1.0.0.
package node

// Tests of the executor's finality surface: the adapter verifies ordinary mode3
// signatures with the epoch's group key and refuses every single-signer
// operation, the explicit registration binds one activation epoch, and the
// startup refresh picks up an installed share. The seal-side end-to-end path
// (four real shares, four p2p hosts) is the development-network integration.

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// tdilithium3SigningFinalityTestKey returns one DEVNET ONLY mode3 key pair.
func tdilithium3SigningFinalityTestKey(t *testing.T) (*mode3.PublicKey, *mode3.PrivateKey) {
	t.Helper()
	var seed [mode3.SeedSize]byte
	copy(seed[:], "DEVNET ONLY finality signer surface key")
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	return publicKey, privateKey
}

func TestTDilithium3SigningFinalitySignerVerifiesAndRefuses(t *testing.T) {
	publicKey, privateKey := tdilithium3SigningFinalityTestKey(t)
	groupKey := publicKey.Bytes()
	signer, err := newTDilithium3SigningFinalitySigner(groupKey, 4)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if !signer.IsThresholdMode() {
		t.Fatal("adapter does not report threshold mode")
	}
	if signer.Threshold() != int(protocol.ThresholdV1Threshold) {
		t.Fatalf("threshold = %d, want %d", signer.Threshold(), int(protocol.ThresholdV1Threshold))
	}
	returned := signer.GroupPublicKey()
	if !bytes.Equal(returned, groupKey) {
		t.Fatal("adapter reports another group key")
	}
	returned[0] ^= 1
	if bytes.Equal(signer.GroupPublicKey(), returned) {
		t.Fatal("group key copy is mutable through the returned slice")
	}

	message := []byte("QAU-TDILITHIUM3-V1-FINALITY-SURFACE-TEST")
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(privateKey, message, signature)
	if !signer.VerifyBlock(nil, message, signature) {
		t.Fatal("epoch group key did not verify the session signature")
	}
	if !signer.VerifyBlock(groupKey, message, signature) {
		t.Fatal("explicit group key did not verify the session signature")
	}
	if !signer.VerifyVote(nil, message, signature) {
		t.Fatal("vote verification differs from block verification")
	}
	if signer.VerifyBlock(nil, []byte("QAU-TDILITHIUM3-V1-FINALITY-OTHER"), signature) {
		t.Fatal("another message verified")
	}
	tampered := append([]byte(nil), signature...)
	tampered[0] ^= 1
	if signer.VerifyBlock(nil, message, tampered) {
		t.Fatal("tampered signature verified")
	}
	if signer.VerifyBlock(nil, message, nil) {
		t.Fatal("empty signature verified")
	}
	foreign, _ := tdilithium3SigningFinalityTestKeyForeign(t)
	if signer.VerifyBlock(foreign, message, signature) {
		t.Fatal("a foreign verification key was accepted")
	}

	if _, err := signer.SignBlock(0, message); err == nil {
		t.Fatal("single-signer block signing accepted")
	}
	if _, err := signer.SignVote(0, message); err == nil {
		t.Fatal("single-signer vote signing accepted")
	}
	if _, err := signer.AggregatePartialSignatures([]int{0, 1, 2, 3}, nil, message); err == nil {
		t.Fatal("standalone partial signature aggregation accepted")
	}

	for name, key := range map[string][]byte{
		"nil":       nil,
		"short":     []byte("QAU-TDILITHIUM3-V1"),
		"all zeros": make([]byte, qcrypto.Dilithium3PublicKeySize),
	} {
		if _, err := newTDilithium3SigningFinalitySigner(key, 4); err == nil {
			t.Fatalf("%s group key accepted", name)
		}
	}
}

// tdilithium3SigningFinalityTestKeyForeign returns a second DEVNET ONLY key so
// an explicit verification key different from the epoch key can be exercised.
func tdilithium3SigningFinalityTestKeyForeign(t *testing.T) ([]byte, *mode3.PrivateKey) {
	t.Helper()
	var seed [mode3.SeedSize]byte
	copy(seed[:], "DEVNET ONLY finality signer foreign key")
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	return publicKey.Bytes(), privateKey
}

func TestRegisterTDilithium3SigningFinalitySigner(t *testing.T) {
	publicKey, _ := tdilithium3SigningFinalityTestKey(t)
	groupKey := publicKey.Bytes()

	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "0")
	producer, qpos, _, _ := newEpochTransitionTestBlockProducer(t)
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}, blockProducer: producer}
	if err := node.registerTDilithium3SigningFinalitySigner(7, groupKey, 4); err == nil {
		t.Fatal("registration succeeded with the gate closed")
	}

	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	if err := (&Node{config: &Config{NetworkID: TestnetNetworkID}}).
		registerTDilithium3SigningFinalitySigner(7, groupKey, 4); err == nil {
		t.Fatal("registration succeeded without a consensus engine")
	}
	if err := node.registerTDilithium3SigningFinalitySigner(0, groupKey, 4); err == nil {
		t.Fatal("registration succeeded with a zero activation epoch")
	}
	if err := node.registerTDilithium3SigningFinalitySigner(7, []byte("short"), 4); err == nil {
		t.Fatal("registration succeeded with a malformed group key")
	}
	mainnet := &Node{config: &Config{NetworkID: MainnetNetworkID}, blockProducer: producer}
	if err := mainnet.registerTDilithium3SigningFinalitySigner(7, groupKey, 4); err == nil {
		t.Fatal("registration succeeded on the mainnet")
	}

	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(nil)
	if status := qfs.GetQTDFinalityStatus(); status["hasQTDSigner"] == true {
		t.Fatal("signer was not cleared before registration")
	}
	if err := node.registerTDilithium3SigningFinalitySigner(7, groupKey, 4); err != nil {
		t.Fatalf("registration: %v", err)
	}
	status := qfs.GetQTDFinalityStatus()
	if status["hasQTDSigner"] != true || status["isThresholdMode"] != true {
		t.Fatalf("registration left status %v", status)
	}
}

func TestRefreshTDilithium3SigningFinalitySigner(t *testing.T) {
	producer, qpos, _, _ := newEpochTransitionTestBlockProducer(t)
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(nil)
	dataDir := t.TempDir()
	password := "DEVNET ONLY finality signer refresh password"
	node := &Node{
		config:        &Config{NetworkID: TestnetNetworkID, DataDir: dataDir, ValidatorKeyPassword: password},
		blockProducer: producer,
	}

	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "0")
	node.refreshTDilithium3SigningFinalitySigner()
	if qfs.GetQTDFinalityStatus()["hasQTDSigner"] == true {
		t.Fatal("closed gate refreshed the finality surface")
	}

	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	node.refreshTDilithium3SigningFinalitySigner()
	if qfs.GetQTDFinalityStatus()["hasQTDSigner"] == true {
		t.Fatal("refresh registered a surface without an installed share")
	}

	store := newThresholdShareStore(dataDir)
	share := testThresholdStoreShare(t, 2)
	if err := store.Store(share, []byte(password)); err != nil {
		t.Fatal(err)
	}
	certificate, sessionDigest, verifier, bindings := testThresholdActivationCertificate(t, share)
	if err := store.ActivateCandidate(certificate, sessionDigest, share.ActivationEpoch, verifier, bindings, []byte(password)); err != nil {
		t.Fatal(err)
	}
	node.refreshTDilithium3SigningFinalitySigner()
	status := qfs.GetQTDFinalityStatus()
	if status["hasQTDSigner"] != true || status["isThresholdMode"] != true {
		t.Fatalf("refresh with an installed share left status %v", status)
	}
}
