// Quantaureum Node source, version 1.0.0.
package qzkp

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/quantaureum/qau/pedersen"
)

func testProtocol(t *testing.T) *SigmaProtocol {
	config := ZKConfig{
		SecurityLevel:      SecurityLevel128,
		Curve:              ecc.BLS12_381,
		AllowInsecureSetup: true, // tests use local trusted setup; production must use MPC ceremony
	}
	return NewSigmaProtocol(config)
}

func TestPreimageProof(t *testing.T) {
	sp := testProtocol(t)

	preimage := []byte("secret-preimage-value")
	preimageInt := new(big.Int).SetBytes(preimage)
	expectedHash := computeNativeMiMC(preimageInt)
	publicHash := expectedHash.Bytes()

	proof, err := sp.ProveKnowledgeOfPreimage(preimage, publicHash)
	if err != nil {
		t.Fatalf("ProveKnowledgeOfPreimage failed: %v", err)
	}
	if len(proof.ProofBytes) == 0 {
		t.Error("proof bytes should not be empty")
	}
	if len(proof.PublicHash) == 0 {
		t.Error("public hash should not be empty")
	}

	err = sp.VerifyKnowledgeOfPreimage(proof, publicHash)
	if err != nil {
		t.Fatalf("VerifyKnowledgeOfPreimage failed: %v", err)
	}
}

func TestPreimageProof_WrongHash(t *testing.T) {
	sp := testProtocol(t)

	preimage := []byte("secret-preimage-value")
	wrongHash := []byte("wrong-hash-value-1234567890ab")

	_, err := sp.ProveKnowledgeOfPreimage(preimage, wrongHash)
	if err == nil {
		t.Error("should fail with wrong public hash")
	}
}

func TestPreimageProof_EmptyWitness(t *testing.T) {
	sp := testProtocol(t)

	_, err := sp.ProveKnowledgeOfPreimage([]byte{}, []byte("hash"))
	if err != ErrInvalidWitness {
		t.Errorf("expected ErrInvalidWitness, got %v", err)
	}
}

func TestPreimageProof_NilProof(t *testing.T) {
	sp := testProtocol(t)

	err := sp.VerifyKnowledgeOfPreimage(nil, []byte("hash"))
	if err != ErrProofVerificationFailed {
		t.Errorf("expected ErrProofVerificationFailed, got %v", err)
	}
}

func TestRangeProof(t *testing.T) {
	sp := testProtocol(t)

	value := big.NewInt(42)
	bitLength := 64

	proof, err := sp.ProveValueInRange(value, bitLength)
	if err != nil {
		t.Fatalf("ProveValueInRange failed: %v", err)
	}
	if len(proof.ProofBytes) == 0 {
		t.Error("proof bytes should not be empty")
	}
	if proof.BitLength != bitLength {
		t.Errorf("expected bit length %d, got %d", bitLength, proof.BitLength)
	}

	// R2-HIGH-08: commitment now includes a random blinding factor (MiMC(value, blinding)),
	// so use the commitment from the proof directly rather than recomputing MiMC(value).
	commitment := proof.Commitment

	err = sp.VerifyValueInRange(proof, commitment)
	if err != nil {
		t.Fatalf("VerifyValueInRange failed: %v", err)
	}
}

func TestRangeProof_OutOfRange(t *testing.T) {
	sp := testProtocol(t)

	value := big.NewInt(1).Lsh(big.NewInt(1), 64)
	bitLength := 64

	_, err := sp.ProveValueInRange(value, bitLength)
	if err != ErrInvalidWitness {
		t.Errorf("expected ErrInvalidWitness, got %v", err)
	}
}

func TestRangeProof_NegativeValue(t *testing.T) {
	sp := testProtocol(t)

	value := big.NewInt(-1)
	bitLength := 64

	_, err := sp.ProveValueInRange(value, bitLength)
	if err != ErrInvalidWitness {
		t.Errorf("expected ErrInvalidWitness, got %v", err)
	}
}

func TestRangeProof_NilProof(t *testing.T) {
	sp := testProtocol(t)

	err := sp.VerifyValueInRange(nil, []byte("commitment"))
	if err != ErrProofVerificationFailed {
		t.Errorf("expected ErrProofVerificationFailed, got %v", err)
	}
}

func TestEqualityProof(t *testing.T) {
	sp := testProtocol(t)

	witness := []byte("shared-secret-witness")
	witnessInt := new(big.Int).SetBytes(witness)
	hashAInt := computeNativeMiMCWithSuffix(witnessInt, 0x41)
	hashBInt := computeNativeMiMCWithSuffix(witnessInt, 0x42)
	publicA := hashAInt.Bytes()
	publicB := hashBInt.Bytes()

	proof, err := sp.ProveEquality(witness, publicA, publicB)
	if err != nil {
		t.Fatalf("ProveEquality failed: %v", err)
	}
	if len(proof.ProofBytes) == 0 {
		t.Error("proof bytes should not be empty")
	}

	err = sp.VerifyEquality(proof, publicA, publicB)
	if err != nil {
		t.Fatalf("VerifyEquality failed: %v", err)
	}
}

func TestEqualityProof_WrongPublicB(t *testing.T) {
	sp := testProtocol(t)

	witness := []byte("shared-secret-witness")
	witnessInt := new(big.Int).SetBytes(witness)
	hashAInt := computeNativeMiMCWithSuffix(witnessInt, 0x41)
	publicA := hashAInt.Bytes()
	wrongB := []byte("wrong-public-b-value-1234567890")

	_, err := sp.ProveEquality(witness, publicA, wrongB)
	if err == nil {
		t.Error("should fail with wrong public B")
	}
}

func TestEqualityProof_EmptyWitness(t *testing.T) {
	sp := testProtocol(t)

	_, err := sp.ProveEquality([]byte{}, []byte("a"), []byte("b"))
	if err != ErrInvalidWitness {
		t.Errorf("expected ErrInvalidWitness, got %v", err)
	}
}

func TestEqualityProof_NilProof(t *testing.T) {
	sp := testProtocol(t)

	err := sp.VerifyEquality(nil, []byte("a"), []byte("b"))
	if err != ErrProofVerificationFailed {
		t.Errorf("expected ErrProofVerificationFailed, got %v", err)
	}
}

func TestMembershipProof(t *testing.T) {
	sp := testProtocol(t)

	leaf := []byte("leaf-data")
	siblings := [][]byte{
		[]byte("sibling-0"),
		[]byte("sibling-1"),
		[]byte("sibling-2"),
	}
	directions := []bool{false, true, false}

	proof, err := sp.ProveMembership(leaf, siblings, directions)
	if err != nil {
		t.Fatalf("ProveMembership failed: %v", err)
	}
	if len(proof.ProofBytes) == 0 {
		t.Error("proof bytes should not be empty")
	}
	if proof.Depth != 3 {
		t.Errorf("expected depth 3, got %d", proof.Depth)
	}

	leafInt := new(big.Int).SetBytes(leaf)
	siblingInts := make([]*big.Int, len(siblings))
	directionInts := make([]*big.Int, len(directions))
	for i, s := range siblings {
		siblingInts[i] = new(big.Int).SetBytes(s)
		if directions[i] {
			directionInts[i] = big.NewInt(1)
		} else {
			directionInts[i] = big.NewInt(0)
		}
	}
	rootInt := computeMerkleRoot(leafInt, siblingInts, directionInts)
	expectedRoot := rootInt.Bytes()

	err = sp.VerifyMembership(proof, expectedRoot)
	if err != nil {
		t.Fatalf("VerifyMembership failed: %v", err)
	}
}

func TestMembershipProof_MismatchedInputs(t *testing.T) {
	sp := testProtocol(t)

	_, err := sp.ProveMembership([]byte("leaf"), [][]byte{{1}, {2}}, []bool{true})
	if err != ErrInvalidWitness {
		t.Errorf("expected ErrInvalidWitness, got %v", err)
	}
}

func TestMembershipProof_NilProof(t *testing.T) {
	sp := testProtocol(t)

	err := sp.VerifyMembership(nil, []byte("root"))
	if err != ErrProofVerificationFailed {
		t.Errorf("expected ErrProofVerificationFailed, got %v", err)
	}
}

func TestBatchVerifier(t *testing.T) {
	sp := testProtocol(t)

	preimages := [][]byte{
		[]byte("preimage-1"),
		[]byte("preimage-2"),
	}

	var proofs []*SchnorrProof
	var publicHashes [][]byte
	for _, pre := range preimages {
		preInt := new(big.Int).SetBytes(pre)
		hashInt := computeNativeMiMC(preInt)
		pubHash := hashInt.Bytes()
		proof, err := sp.ProveKnowledgeOfPreimage(pre, pubHash)
		if err != nil {
			t.Fatalf("ProveKnowledgeOfPreimage failed: %v", err)
		}
		proofs = append(proofs, proof)
		publicHashes = append(publicHashes, pubHash)
	}

	bv := NewBatchVerifier(sp)
	err := bv.VerifySchnorrSequential(proofs, publicHashes)
	if err != nil {
		t.Fatalf("VerifySchnorrSequential failed: %v", err)
	}
}

func TestBatchVerifier_MismatchedLengths(t *testing.T) {
	sp := testProtocol(t)
	bv := NewBatchVerifier(sp)

	err := bv.VerifySchnorrSequential([]*SchnorrProof{}, [][]byte{{1}})
	if err != ErrInvalidStatement {
		t.Errorf("expected ErrInvalidStatement, got %v", err)
	}
}

func TestDefaultZKConfig(t *testing.T) {
	config := DefaultZKConfig(nil)
	if config.SecurityLevel != SecurityLevel256 {
		t.Errorf("expected SecurityLevel256, got %d", config.SecurityLevel)
	}
	if config.Curve != ecc.BLS12_381 {
		t.Errorf("expected BLS12_381, got %v", config.Curve)
	}
	if config.HashFunc == nil {
		t.Error("HashFunc should not be nil")
	}
}

func TestComputeNativeMiMC(t *testing.T) {
	val := big.NewInt(12345)
	hash := computeNativeMiMC(val)
	if hash == nil || hash.Sign() == 0 {
		t.Error("MiMC hash should not be zero")
	}

	sameVal := big.NewInt(12345)
	hash2 := computeNativeMiMC(sameVal)
	if hash.Cmp(hash2) != 0 {
		t.Error("same input should produce same hash")
	}

	diffVal := big.NewInt(54321)
	hash3 := computeNativeMiMC(diffVal)
	if hash.Cmp(hash3) == 0 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestComputeMerkleRoot(t *testing.T) {
	leaf := big.NewInt(100)
	siblings := []*big.Int{big.NewInt(200), big.NewInt(300)}
	directions := []*big.Int{big.NewInt(0), big.NewInt(1)}

	root := computeMerkleRoot(leaf, siblings, directions)
	if root == nil || root.Sign() == 0 {
		t.Error("Merkle root should not be zero")
	}

	root2 := computeMerkleRoot(leaf, siblings, directions)
	if root.Cmp(root2) != 0 {
		t.Error("same inputs should produce same root")
	}
}

func TestBytesEqual(t *testing.T) {
	if !bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Error("equal slices should return true")
	}
	if bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Error("different slices should return false")
	}
	if bytesEqual([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Error("different length slices should return false")
	}
}

// audit-fix L6-017: bytesEqual moved here from qzkp.go. It is only used by
// tests (TestBytesEqual). Production code should use crypto/subtle.ConstantTimeCompare
// for constant-time byte comparison.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// TestBoundRangeProof_Valid verifies that a correctly generated bound range
// proof passes verification. AUDIT (2026) ZK-NN-5.
func TestBoundRangeProof_Valid(t *testing.T) {
	sp := testProtocol(t)
	gen, err := pedersen.NewGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	value := big.NewInt(42)
	blinding := big.NewInt(12345)
	bitLength := 8 // range [0, 256)

	brp, sbp, err := sp.ProveBoundValueInRange(value, blinding, bitLength, gen)
	if err != nil {
		t.Fatalf("ProveBoundValueInRange failed: %v", err)
	}

	if err := sp.VerifyBoundValueInRange(brp, sbp, gen); err != nil {
		t.Fatalf("VerifyBoundValueInRange failed: %v", err)
	}
}

// TestBoundRangeProof_TamperedCommitment verifies that tampering with the
// EcCommitment (to commit to a different value) causes verification to fail.
// AUDIT (2026) ZK-NN-5: This test confirms the fix prevents an attacker
// from using value=5 for the Groth16 range proof while opening the Pedersen
// commitment to an out-of-range value.
func TestBoundRangeProof_TamperedCommitment(t *testing.T) {
	sp := testProtocol(t)
	gen, err := pedersen.NewGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	value := big.NewInt(5) // in range for bitLength=8
	blinding := big.NewInt(999)
	bitLength := 8

	brp, sbp, err := sp.ProveBoundValueInRange(value, blinding, bitLength, gen)
	if err != nil {
		t.Fatalf("ProveBoundValueInRange failed: %v", err)
	}

	// Tamper: replace EcCommitment with a commitment to a different value (1000)
	// The attacker tries to make the Pedersen commitment open to 1000 instead
	// of mimcCommit.
	wrongValue := big.NewInt(1000)
	wrongBlinding := big.NewInt(888)
	wrongCommitment := gen.Commit(wrongValue, wrongBlinding)
	wrongBytes := wrongCommitment.Bytes()

	// Deep copy brp with tampered EcCommitment
	tamperedBRP := &BoundRangeProof{
		ProofBytes:   brp.ProofBytes,
		MimcCommit:   brp.MimcCommit,
		EcCommitment: make([]byte, len(wrongBytes)),
		BitLength:    brp.BitLength,
		BindingHash:  brp.BindingHash,
	}
	copy(tamperedBRP.EcCommitment, wrongBytes)

	// Verification should fail because the Schnorr proof was generated for
	// the original ecCommitment (committing to mimcCommit), not the tampered
	// one (committing to 1000).
	err = sp.VerifyBoundValueInRange(tamperedBRP, sbp, gen)
	if err == nil {
		t.Fatal("VerifyBoundValueInRange should fail with tampered EcCommitment, but it passed")
	}
}

// TestBoundRangeProof_OutOfRangeValue verifies that an out-of-range value
// is rejected by ProveBoundValueInRange.
func TestBoundRangeProof_OutOfRangeValue(t *testing.T) {
	sp := testProtocol(t)
	gen, err := pedersen.NewGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	value := big.NewInt(300) // out of range for bitLength=8 (max 255)
	blinding := big.NewInt(12345)
	bitLength := 8

	_, _, err = sp.ProveBoundValueInRange(value, blinding, bitLength, gen)
	if err == nil {
		t.Fatal("ProveBoundValueInRange should fail for out-of-range value, but it passed")
	}
}

// TestLoadTrustedSetup_PreimageCircuit verifies that loading an externally
// computed trusted setup (simulating MPC ceremony output) allows proof
// generation WITHOUT calling local groth16.Setup. AUDIT (2026) ZK-NN-7.
//
// Key assertion: AllowInsecureSetup=false blocks local setup, but a
// pre-loaded trusted setup should still work. This proves the ZK subsystem
// is usable cross-node when all nodes load the same MPC ceremony output.
func TestLoadTrustedSetup_PreimageCircuit(t *testing.T) {
	// Step 1: Generate pk/vk via local setup (simulating MPC ceremony output).
	// In production, these would come from a real MPC ceremony.
	circuit := &preimageCircuit{}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile preimage circuit: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16.Setup (test ceremony): %v", err)
	}

	// Step 2: Create SigmaProtocol with AllowInsecureSetup=false (production-safe).
	// Without LoadTrustedSetup, ProveKnowledgeOfPreimage would fail because
	// compileCircuit blocks local setup.
	config := ZKConfig{
		SecurityLevel:      SecurityLevel128,
		Curve:              ecc.BLS12_381,
		AllowInsecureSetup: false, // production-safe: blocks local groth16.Setup
	}
	sp := NewSigmaProtocol(config)

	// Step 3: Load the trusted setup.
	if err := sp.LoadTrustedSetup("preimage", &preimageCircuit{}, pk, vk); err != nil {
		t.Fatalf("LoadTrustedSetup failed: %v", err)
	}

	// Step 4: Generate a proof — should use the cached trusted setup, not
	// local groth16.Setup.
	preimage := []byte("trusted-setup-test")
	preimageInt := new(big.Int).SetBytes(preimage)
	hashInt := computeNativeMiMC(preimageInt)
	publicHash := hashInt.Bytes()

	proof, err := sp.ProveKnowledgeOfPreimage(preimage, publicHash)
	if err != nil {
		t.Fatalf("ProveKnowledgeOfPreimage with trusted setup failed: %v", err)
	}

	// Step 5: Verify the proof.
	err = sp.VerifyKnowledgeOfPreimage(proof, publicHash)
	if err != nil {
		t.Fatalf("VerifyKnowledgeOfPreimage failed: %v", err)
	}
}

// TestLoadTrustedSetup_RejectsNil verifies that LoadTrustedSetup rejects
// nil pk/vk. AUDIT (2026) ZK-NN-7.
func TestLoadTrustedSetup_RejectsNil(t *testing.T) {
	sp := testProtocol(t)

	err := sp.LoadTrustedSetup("preimage", &preimageCircuit{}, nil, nil)
	if err == nil {
		t.Fatal("LoadTrustedSetup should reject nil pk/vk")
	}
}

// TestLoadTrustedSetup_BlocksLocalSetup verifies that without a trusted
// setup and with AllowInsecureSetup=false, proof generation fails (local
// groth16.Setup is blocked). AUDIT (2026) ZK-NN-7.
func TestLoadTrustedSetup_BlocksLocalSetup(t *testing.T) {
	config := ZKConfig{
		SecurityLevel:      SecurityLevel128,
		Curve:              ecc.BLS12_381,
		AllowInsecureSetup: false, // production-safe
	}
	sp := NewSigmaProtocol(config)

	preimage := []byte("blocked-setup-test")
	preimageInt := new(big.Int).SetBytes(preimage)
	hashInt := computeNativeMiMC(preimageInt)
	publicHash := hashInt.Bytes()

	_, err := sp.ProveKnowledgeOfPreimage(preimage, publicHash)
	if err == nil {
		t.Fatal("ProveKnowledgeOfPreimage should fail when AllowInsecureSetup=false and no trusted setup loaded")
	}
}
