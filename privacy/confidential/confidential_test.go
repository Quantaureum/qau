// Quantaureum Node source, version 1.0.0.
package confidential

import (
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/quantaureum/qau/qrng"
	"github.com/quantaureum/qau/qzkp"
)

// newTestConfidentialManager creates a ConfidentialManager configured for testing.
// Tests use the local groth16 trusted setup (which produces toxic waste) because
// a real MPC ceremony is not available in the test environment. Production code
// MUST use NewConfidentialManager() which defaults to AllowInsecureSetup=false.
func newTestConfidentialManager() *ConfidentialManager {
	q, _ := qrng.New(qrng.DefaultQRNGConfig())
	config := qzkp.DefaultZKConfig(q)
	config.AllowInsecureSetup = true // test-only: local trusted setup
	return NewConfidentialManagerWithConfig(config)
}

func TestPedersenCommit(t *testing.T) {
	pg := NewPedersenGeneratorOrPanic()
	blinding := make([]byte, 32)
	for i := range blinding {
		blinding[i] = byte(i)
	}

	amount := big.NewInt(1000)
	commitment := pg.Commit(amount, blinding)
	if len(commitment) == 0 {
		t.Error("commitment should not be empty")
	}

	if !pg.Verify(commitment, amount, blinding) {
		t.Error("commitment verification should succeed")
	}

	if pg.Verify(commitment, big.NewInt(999), blinding) {
		t.Error("commitment verification should fail for wrong amount")
	}

	differentBlinding := make([]byte, 32)
	copy(differentBlinding, blinding)
	differentBlinding[0] ^= 0xFF

	if pg.Verify(commitment, amount, differentBlinding) {
		t.Error("commitment verification should fail for wrong blinding")
	}
}

func generateKemKeyPair(t *testing.T) (kemPubBytes, kemPrivBytes []byte) {
	t.Helper()
	kemPub, kemPriv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Kyber768 key pair: %v", err)
	}
	kemPubBytes, err = kemPub.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal Kyber768 public key: %v", err)
	}
	kemPrivBytes = make([]byte, kyber768.PrivateKeySize)
	kemPriv.Pack(kemPrivBytes)
	return kemPubBytes, kemPrivBytes
}

func TestEncryptDecryptAmount(t *testing.T) {
	cm := newTestConfidentialManager()

	receiverKemPub, receiverKemPriv := generateKemKeyPair(t)

	senderKey := make([]byte, 32)
	if _, err := rand.Read(senderKey); err != nil {
		t.Fatalf("failed to generate sender key: %v", err)
	}

	amount := big.NewInt(12345)
	encrypted, err := cm.EncryptAmount(amount, receiverKemPub, senderKey)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := cm.DecryptAmount(encrypted, receiverKemPriv, senderKey)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if decrypted.Cmp(amount) != 0 {
		t.Errorf("expected %s, got %s", amount.String(), decrypted.String())
	}
}

func TestRangeProof(t *testing.T) {
	cm := newTestConfidentialManager()

	// run-8 root fix: GenerateRangeProofWithBlinding now produces a
	// circuit-bound proof (TxProof) whose public input is the REAL
	// transaction commitment, so VerifyRangeProof accepts it. The unbound
	// GenerateRangeProof is only for testing input validation.
	pg := NewPedersenGeneratorOrPanic()
	blinding := make([]byte, 32)
	for i := range blinding {
		blinding[i] = byte(i)
	}
	commitment := pg.Commit(big.NewInt(1000), blinding)

	proof, err := cm.GenerateRangeProofWithBlinding(big.NewInt(1000), 128, commitment, blinding)
	if err != nil {
		t.Fatalf("failed to generate range proof: %v", err)
	}
	if proof == nil {
		t.Fatal("range proof should not be nil")
	}
	if proof.TxProof == nil {
		t.Fatal("run-8 fix: proof must carry the circuit-bound TxProof")
	}

	// Positive: verifying against the same commitment succeeds.
	if err := cm.VerifyRangeProof(proof, commitment); err != nil {
		t.Fatalf("VerifyRangeProof (same commitment): %v", err)
	}

	// Negative (replay): the same proof against a DIFFERENT commitment
	// (different amount) must be rejected.
	otherCommitment := pg.Commit(big.NewInt(999), blinding)
	if err := cm.VerifyRangeProof(proof, otherCommitment); !errors.Is(err, ErrRangeProofFailed) {
		t.Fatalf("replay onto different commitment: expected ErrRangeProofFailed, got %v", err)
	}

	// Negative: legacy format (no TxProof) is structurally rejected.
	legacy := &qzkp.RangeProof{BitLength: 128}
	if err := cm.VerifyRangeProof(legacy, commitment); !errors.Is(err, ErrLegacyRangeProofFormat) {
		t.Fatalf("legacy format: expected ErrLegacyRangeProofFormat, got %v", err)
	}
}

func TestBalanceProof(t *testing.T) {
	cm := newTestConfidentialManager()

	inputComms := [][]byte{[]byte("input1"), []byte("input2")}
	outputComms := [][]byte{[]byte("output1"), []byte("output2")}

	proof, err := cm.GenerateBalanceProof(inputComms, outputComms, big.NewInt(100))
	if err != nil {
		t.Fatalf("failed to generate balance proof: %v", err)
	}

	if err := cm.VerifyBalanceProof(proof, inputComms, outputComms, big.NewInt(100)); err != nil {
		t.Fatalf("balance proof verification failed: %v", err)
	}
}

func TestCreateConfidentialTx(t *testing.T) {
	cm := newTestConfidentialManager()

	receiverKemPub1, _ := generateKemKeyPair(t)
	receiverKemPub2, _ := generateKemKeyPair(t)
	senderKemPub, _ := generateKemKeyPair(t)

	inputAmounts := []*big.Int{big.NewInt(10000), big.NewInt(5000)}
	outputAmounts := []*big.Int{big.NewInt(12000), big.NewInt(2900)}
	outputPubKeys := [][]byte{receiverKemPub1, receiverKemPub2}
	fee := big.NewInt(100)

	tx, err := cm.CreateConfidentialTx(inputAmounts, outputAmounts, outputPubKeys, senderKemPub, fee)
	if err != nil {
		t.Fatalf("failed to create confidential tx: %v", err)
	}

	if len(tx.Inputs) != 2 {
		t.Errorf("expected 2 inputs, got %d", len(tx.Inputs))
	}
	if len(tx.Outputs) != 2 {
		t.Errorf("expected 2 outputs, got %d", len(tx.Outputs))
	}
	if tx.Fee.Cmp(fee) != 0 {
		t.Errorf("expected fee %s, got %s", fee.String(), tx.Fee.String())
	}
}

func TestVerifyConfidentialTx(t *testing.T) {
	cm := newTestConfidentialManager()

	receiverKemPub, _ := generateKemKeyPair(t)
	senderKemPub, _ := generateKemKeyPair(t)

	inputAmounts := []*big.Int{big.NewInt(10000)}
	outputAmounts := []*big.Int{big.NewInt(9900)}
	outputPubKeys := [][]byte{receiverKemPub}
	fee := big.NewInt(100)

	tx, _ := cm.CreateConfidentialTx(inputAmounts, outputAmounts, outputPubKeys, senderKemPub, fee)

	// run-8 root fix: verification now succeeds end to end — range proofs
	// are circuit-bound to the real transaction commitments.
	if err := cm.VerifyConfidentialTx(tx); err != nil {
		t.Fatalf("VerifyConfidentialTx: %v", err)
	}
}

func TestConfidentialEndToEnd(t *testing.T) {
	cm := newTestConfidentialManager()

	receiverKemPub, receiverKemPriv := generateKemKeyPair(t)
	senderKemPub, _ := generateKemKeyPair(t)

	inputAmounts := []*big.Int{big.NewInt(50000)}
	outputAmounts := []*big.Int{big.NewInt(49900)}
	outputPubKeys := [][]byte{receiverKemPub}
	fee := big.NewInt(100)

	tx, err := cm.CreateConfidentialTx(inputAmounts, outputAmounts, outputPubKeys, senderKemPub, fee)
	if err != nil {
		t.Fatalf("failed to create tx: %v", err)
	}

	// run-8 root fix: the end-to-end acceptance path is open — range proofs
	// are circuit-bound to the real transaction commitments.
	if err := cm.VerifyConfidentialTx(tx); err != nil {
		t.Fatalf("VerifyConfidentialTx: %v", err)
	}

	if len(tx.Outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(tx.Outputs))
	}

	decrypted, err := cm.DecryptAmount(tx.Outputs[0].EncryptedAmount, receiverKemPriv, tx.Outputs[0].EphemeralPubKey)
	if err != nil {
		t.Fatalf("failed to decrypt output: %v", err)
	}

	if decrypted.Cmp(big.NewInt(49900)) != 0 {
		t.Errorf("expected decrypted amount 49900, got %s", decrypted.String())
	}
}

func TestConfidentialEdgeCases(t *testing.T) {
	t.Run("zero amount", func(t *testing.T) {
		cm := newTestConfidentialManager()
		_, err := cm.GenerateRangeProof(big.NewInt(0), 128, nil)
		if err != nil {
			t.Fatalf("should allow zero amount: %v", err)
		}
	})

	t.Run("amount exceeds range", func(t *testing.T) {
		cm := newTestConfidentialManager()
		maxVal := new(big.Int).Lsh(big.NewInt(1), 127)
		_, err := cm.GenerateRangeProof(maxVal, 128, nil)
		if err == nil {
			t.Error("should reject amount exceeding range")
		}
	})

	t.Run("nil tx verification", func(t *testing.T) {
		cm := newTestConfidentialManager()
		err := cm.VerifyConfidentialTx(nil)
		if err == nil {
			t.Error("should reject nil transaction")
		}
	})

	t.Run("nil range proof", func(t *testing.T) {
		cm := newTestConfidentialManager()
		err := cm.VerifyRangeProof(nil, []byte("test"))
		if !errors.Is(err, ErrRangeProofFailed) {
			t.Errorf("expected ErrRangeProofFailed, got %v", err)
		}
	})

	t.Run("nil balance proof", func(t *testing.T) {
		cm := newTestConfidentialManager()
		err := cm.VerifyBalanceProof(nil, nil, nil, big.NewInt(0))
		if err != ErrBalanceProofFailed {
			t.Errorf("expected ErrBalanceProofFailed, got %v", err)
		}
	})

	t.Run("decrypt short data", func(t *testing.T) {
		amount, err := decryptWithKey([]byte("short"), make([]byte, 32))
		if err != ErrDecryptionFailed {
			t.Error("expected ErrDecryptionFailed for short data")
		}
		if amount != nil {
			t.Error("expected nil amount on error")
		}
	})

	t.Run("verify commitment wrong length", func(t *testing.T) {
		pg := NewPedersenGeneratorOrPanic()
		if pg.Verify([]byte("tooshort"), big.NewInt(10), make([]byte, 32)) {
			t.Error("should fail for wrong length commitment")
		}
	})

	t.Run("create tx with less pub keys", func(t *testing.T) {
		cm := newTestConfidentialManager()
		senderKemPub, _ := generateKemKeyPair(t)
		receiverKemPub, _ := generateKemKeyPair(t)
		_, err := cm.CreateConfidentialTx(
			[]*big.Int{big.NewInt(100)},
			[]*big.Int{big.NewInt(50), big.NewInt(40)},
			[][]byte{receiverKemPub},
			senderKemPub,
			big.NewInt(10),
		)
		if err != ErrMissingPubKey {
			t.Errorf("expected ErrMissingPubKey, got %v", err)
		}
	})
}

func TestErrorVariables(t *testing.T) {
	errors := []struct {
		name string
		err  error
	}{
		{"ErrInvalidCommitment", ErrInvalidCommitment},
		{"ErrCommitmentMismatch", ErrCommitmentMismatch},
		{"ErrEncryptionFailed", ErrEncryptionFailed},
		{"ErrDecryptionFailed", ErrDecryptionFailed},
		{"ErrRangeProofFailed", ErrRangeProofFailed},
		{"ErrBalanceProofFailed", ErrBalanceProofFailed},
		{"ErrInvalidAmount", ErrInvalidAmount},
		{"ErrNegativeAmount", ErrNegativeAmount},
	}
	for _, e := range errors {
		if e.err.Error() == "" {
			t.Errorf("%s should have non-empty error message", e.name)
		}
	}
}

func TestEncryptWithKey_WrongKey(t *testing.T) {
	_, err := encryptWithKey(big.NewInt(100), []byte("short-key"))
	if err != ErrEncryptionFailed {
		t.Errorf("expected ErrEncryptionFailed, got %v", err)
	}
}

func TestDecryptWithKey_TooShort(t *testing.T) {
	key := make([]byte, 32)
	_, err := decryptWithKey([]byte("short"), key)
	if err != ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecryptWithKey_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	encrypted, _ := encryptWithKey(big.NewInt(100), key)

	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF
	_, err := decryptWithKey(encrypted, wrongKey)
	if err != ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestCreateConfidentialTx_MoreOutputsThanKeys(t *testing.T) {
	cm := newTestConfidentialManager()

	receiverKemPub, _ := generateKemKeyPair(t)
	senderKemPub, _ := generateKemKeyPair(t)

	inputAmounts := []*big.Int{big.NewInt(10000), big.NewInt(5000)}
	outputAmounts := []*big.Int{big.NewInt(12000), big.NewInt(2900)}
	outputPubKeys := [][]byte{receiverKemPub}
	fee := big.NewInt(100)

	_, err := cm.CreateConfidentialTx(inputAmounts, outputAmounts, outputPubKeys, senderKemPub, fee)
	if err != ErrMissingPubKey {
		t.Errorf("expected ErrMissingPubKey, got %v", err)
	}
}

func TestVerifyConfidentialTx_Nil(t *testing.T) {
	cm := newTestConfidentialManager()
	err := cm.VerifyConfidentialTx(nil)
	if err != ErrInvalidCommitment {
		t.Errorf("expected ErrInvalidCommitment, got %v", err)
	}
}

func TestVerifyConfidentialTx_TamperedOutput(t *testing.T) {
	cm := newTestConfidentialManager()

	receiverKemPub, _ := generateKemKeyPair(t)
	senderKemPub, _ := generateKemKeyPair(t)

	inputAmounts := []*big.Int{big.NewInt(10000)}
	outputAmounts := []*big.Int{big.NewInt(9900)}
	outputPubKeys := [][]byte{receiverKemPub}
	fee := big.NewInt(100)

	tx, err := cm.CreateConfidentialTx(inputAmounts, outputAmounts, outputPubKeys, senderKemPub, fee)
	if err != nil {
		t.Fatalf("failed to create tx: %v", err)
	}

	tx.Outputs[0].Commitment = []byte("tampered")
	err = cm.VerifyConfidentialTx(tx)
	if err == nil {
		t.Error("should fail with tampered output commitment")
	}
}

// TestR4ZK02_UnboundRangeProof_Rejected verifies that a range proof generated
// without a Schnorr binding (via GenerateRangeProof, not
// GenerateRangeProofWithBlinding) is REJECTED by VerifyRangeProof.
//
// AUDIT (2026) R4-ZK-02: Previously, VerifyRangeProof treated the Schnorr
// binding as optional. An attacker could generate a valid range proof for a
// small value (e.g., 1) using GenerateRangeProof(), attach any Pedersen
// commitment as ExternalCommitment, and pass verification — even though the
// Pedersen commitment might encode a completely different (huge or negative)
// value. Now the Schnorr binding is mandatory (fail-closed).
func TestR4ZK02_UnboundRangeProof_Rejected(t *testing.T) {
	cm := newTestConfidentialManager()

	pg := NewPedersenGeneratorOrPanic()
	blinding := make([]byte, 32)
	for i := range blinding {
		blinding[i] = byte(i)
	}
	// Real commitment encodes a HUGE value (2^120) — out of the 128-bit range.
	bigValue := new(big.Int).Lsh(big.NewInt(1), 120)
	commitment := pg.Commit(bigValue, blinding)

	// Attacker generates a range proof for a SMALL value (1) using the
	// unbound GenerateRangeProof (no Schnorr binding), but attaches the
	// victim's real Pedersen commitment as ExternalCommitment.
	smallValue := big.NewInt(1)
	proof, err := cm.GenerateRangeProof(smallValue, 128, commitment)
	if err != nil {
		t.Fatalf("GenerateRangeProof should succeed for small value: %v", err)
	}

	// VerifyRangeProof MUST reject this proof because it carries no
	// circuit-bound TxProof — without it there is no constraint linking the
	// proven range statement to the real Pedersen commitment (which encodes
	// bigValue, out of the 128-bit range).
	err = cm.VerifyRangeProof(proof, commitment)
	if err == nil {
		t.Fatal("R4-ZK-02: unbound range proof (no TxProof) should be REJECTED")
	}
	// run-8 root fix: legacy-format proofs are structurally rejected.
	if !errors.Is(err, ErrLegacyRangeProofFormat) {
		t.Fatalf("run-8 fix: expected ErrLegacyRangeProofFormat, got %v", err)
	}
}

// TestR4ZK02_BoundRangeProof_Accepted verifies that a range proof generated
// WITH the transaction blinding (via GenerateRangeProofWithBlinding) carries
// the circuit-bound TxProof and is accepted by VerifyRangeProof.
func TestR4ZK02_BoundRangeProof_Accepted(t *testing.T) {
	cm := newTestConfidentialManager()

	pg := NewPedersenGeneratorOrPanic()
	blinding := make([]byte, 32)
	for i := range blinding {
		blinding[i] = byte(i + 1)
	}
	value := big.NewInt(1000)
	commitment := pg.Commit(value, blinding)

	proof, err := cm.GenerateRangeProofWithBlinding(value, 128, commitment, blinding)
	if err != nil {
		t.Fatalf("GenerateRangeProofWithBlinding failed: %v", err)
	}

	if proof.TxProof == nil {
		t.Fatal("run-8 fix: GenerateRangeProofWithBlinding should produce the circuit-bound TxProof")
	}

	// run-8 root fix: the proof binds to the real commitment in-circuit
	// (public input C_tx), so verification succeeds.
	if err := cm.VerifyRangeProof(proof, commitment); err != nil {
		t.Fatalf("VerifyRangeProof: %v", err)
	}
}

// TestR4ZK02_BoundRangeProof_WrongCommitment_Rejected verifies that a bound
// range proof is rejected when verified against a DIFFERENT commitment than
// the one it was generated for.
func TestR4ZK02_BoundRangeProof_WrongCommitment_Rejected(t *testing.T) {
	cm := newTestConfidentialManager()

	pg := NewPedersenGeneratorOrPanic()
	blinding := make([]byte, 32)
	for i := range blinding {
		blinding[i] = byte(i + 1)
	}
	value := big.NewInt(1000)
	commitment := pg.Commit(value, blinding)

	proof, err := cm.GenerateRangeProofWithBlinding(value, 128, commitment, blinding)
	if err != nil {
		t.Fatalf("GenerateRangeProofWithBlinding failed: %v", err)
	}

	// Generate a different commitment (different value)
	wrongCommitment := pg.Commit(big.NewInt(999), blinding)

	// VerifyRangeProof must reject: the circuit's public input is the
	// original commitment, so the proof cannot verify against a different
	// point (constant-time mismatch before any cryptographic work).
	err = cm.VerifyRangeProof(proof, wrongCommitment)
	if err == nil {
		t.Fatal("R4-ZK-02: range proof verified against wrong commitment should be REJECTED")
	}
}

// TestGenerateRangeProofWithBlinding_BitLengthBound pins the unified outer
// bit-length bound: the prover input validation now shares the circuit's own
// limit (qzkp.MaxTxRangeBitLength = 254) instead of the stale 256, so an
// out-of-range width is rejected as input validation (ErrInvalidAmount)
// before any circuit work instead of leaking into ProveTxValueInRange's
// circuit-level rejection. Compile-free: both cases are rejected before
// compilation.
func TestGenerateRangeProofWithBlinding_BitLengthBound(t *testing.T) {
	cm := newTestConfidentialManager()

	pg := NewPedersenGeneratorOrPanic()
	blinding := make([]byte, 32)
	for i := range blinding {
		blinding[i] = byte(i + 3)
	}
	value := big.NewInt(1000)
	commitment := pg.Commit(value, blinding)

	// Above the unified bound (255 > MaxTxRangeBitLength 254): rejected.
	if _, err := cm.GenerateRangeProofWithBlinding(value, 255, commitment, blinding); !errors.Is(err, ErrInvalidAmount) {
		t.Fatalf("bitLength 255: expected ErrInvalidAmount, got %v", err)
	}
	// Zero width: still rejected (PRIV-RP-01).
	if _, err := cm.GenerateRangeProofWithBlinding(value, 0, commitment, blinding); !errors.Is(err, ErrInvalidAmount) {
		t.Fatalf("bitLength 0: expected ErrInvalidAmount, got %v", err)
	}
}

// TestRangeProofPolicyBitWidth_Enforced pins the verifier-side policy bit
// width gate: VerifyRangeProof accepts only TxProofs at
// PolicyTxValueBitLength. The verification layer previously allowed any
// BitLength in [1, qzkp.MaxTxRangeBitLength], so a malicious transaction
// could self-select bitLength=254 and have the verifier accept a
// near-vacuous range statement ([0, 2^254)) instead of the policy range
// ([0, 2^128)).
//
// The negative case generates a GENUINE circuit-bound proof at bitLength=254
// (the prover accepts it; it even verifies at the qzkp layer) and asserts
// that VerifyRangeProof still rejects it as a policy violation.
func TestRangeProofPolicyBitWidth_Enforced(t *testing.T) {
	cm := newTestConfidentialManager()

	pg := NewPedersenGeneratorOrPanic()
	blinding := make([]byte, 32)
	for i := range blinding {
		blinding[i] = byte(i + 2)
	}
	value := big.NewInt(1000)
	commitment := pg.Commit(value, blinding)

	// Sanity: a policy-width proof verifies.
	policyProof, err := cm.GenerateRangeProofWithBlinding(value, PolicyTxValueBitLength, commitment, blinding)
	if err != nil {
		t.Fatalf("GenerateRangeProofWithBlinding (policy width): %v", err)
	}
	if err := cm.VerifyRangeProof(policyProof, commitment); err != nil {
		t.Fatalf("VerifyRangeProof (policy width): %v", err)
	}

	// Negative case: a genuine bound proof at the structural maximum width.
	// The prover accepts 254 <= qzkp.MaxTxRangeBitLength, so only the
	// verifier-side policy gate can stop it.
	wideProof, err := cm.GenerateRangeProofWithBlinding(value, 254, commitment, blinding)
	if err != nil {
		t.Fatalf("GenerateRangeProofWithBlinding (bitLength=254): %v", err)
	}
	if wideProof.TxProof == nil || wideProof.TxProof.BitLength != 254 {
		t.Fatal("expected a circuit-bound TxProof with BitLength 254")
	}

	// The proof is genuine: it verifies at the qzkp layer against the same
	// commitment (the 254-bit circuit was compiled during generation and is
	// cached in this manager's protocol). Only the policy layer rejects it.
	if err := cm.protocol.VerifyTxValueInRange(wideProof.TxProof, commitment); err != nil {
		t.Fatalf("precondition: the 254-bit proof should be valid at the qzkp layer, got %v", err)
	}

	if err := cm.VerifyRangeProof(wideProof, commitment); !errors.Is(err, ErrRangeProofFailed) {
		t.Fatalf("policy bit width: expected ErrRangeProofFailed for a bitLength=254 proof, got %v", err)
	}
}
