// Quantaureum Node source, version 1.0.0.
package quantum

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	qaucrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// testPartyKey holds a Dilithium3 key pair for test party registration.
// audit fix (H-3): SubmitShare now requires a real Dilithium3 signature,
// so tests must register parties with real public keys and sign submissions.
type testPartyKey struct {
	priv *qaucrypto.PrivateKey
	pub  *qaucrypto.PublicKey
}

// testPartyKeys caches generated key pairs by party address to avoid
// regenerating expensive Dilithium3 keys for every test run.
var testPartyKeys = make(map[byte]*testPartyKey)

// getTestPartyKey returns a cached or newly-generated Dilithium3 key pair for
// the given party address byte.
func getTestPartyKey(addrByte byte) *testPartyKey {
	if kp, ok := testPartyKeys[addrByte]; ok {
		return kp
	}
	pair, err := qaucrypto.GenerateKeyPair()
	if err != nil {
		panic("failed to generate test key pair: " + err.Error())
	}
	kp := &testPartyKey{priv: pair.Private, pub: pair.Public}
	testPartyKeys[addrByte] = kp
	return kp
}

// registerTestParty registers a party with a real Dilithium3 public key.
func registerTestParty(mpc *MPCManager, addrByte byte) {
	kp := getTestPartyKey(addrByte)
	mpc.RegisterParty(&MPCParty{
		ID:        types.Address{addrByte},
		PublicKey: kp.pub.Bytes(),
	})
}

// signTestShare signs the share submission message for a test party.
func signTestShare(sessionID string, addrByte byte, share, commitment []byte) []byte {
	kp := getTestPartyKey(addrByte)
	msg := buildShareSignatureMessage(sessionID, types.Address{addrByte}, share, commitment)
	sig, err := qaucrypto.Sign(kp.priv, msg)
	if err != nil {
		panic("failed to sign test share: " + err.Error())
	}
	return sig
}

func TestKeyRotationManager(t *testing.T) {
	t.Run("NewKeyRotationManager", func(t *testing.T) {
		krm, err := NewKeyRotationManager(nil)
		if err != nil {
			t.Fatalf("NewKeyRotationManager failed: %v", err)
		}
		if krm == nil {
			t.Fatal("NewKeyRotationManager returned nil")
		}
	})

	t.Run("GenerateKey", func(t *testing.T) {
		krm, _ := NewKeyRotationManager(nil)
		key, err := krm.GenerateKey("Dilithium3")
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		if key.State != KeyStatePending {
			t.Errorf("expected pending state, got %d", key.State)
		}
		if len(key.PublicKey) != 1952 {
			t.Errorf("expected public key size 1952, got %d", len(key.PublicKey))
		}
		if len(key.EncryptedPrivKey) == 0 {
			t.Error("expected non-empty encrypted private key")
		}
		if len(key.PrivKeyNonce) == 0 {
			t.Error("expected non-empty private key nonce")
		}
	})

	t.Run("ActivateKey", func(t *testing.T) {
		krm, _ := NewKeyRotationManager(nil)
		key, _ := krm.GenerateKey("Dilithium3")

		err := krm.ActivateKey(key.ID)
		if err != nil {
			t.Fatalf("ActivateKey failed: %v", err)
		}

		active, err := krm.GetActiveKey()
		if err != nil {
			t.Fatalf("GetActiveKey failed: %v", err)
		}
		if active.ID != key.ID {
			t.Errorf("expected active key %s, got %s", key.ID, active.ID)
		}
	})

	t.Run("ActivateKey not found", func(t *testing.T) {
		krm, _ := NewKeyRotationManager(nil)
		err := krm.ActivateKey("nonexistent")
		if err != ErrInvalidKeyID {
			t.Errorf("expected ErrInvalidKeyID, got %v", err)
		}
	})

	t.Run("RotateKey", func(t *testing.T) {
		krm, _ := NewKeyRotationManager(nil)
		key, _ := krm.GenerateKey("Dilithium3")
		krm.ActivateKey(key.ID)

		record, err := krm.RotateKey("scheduled rotation", 1000)
		if err != nil {
			t.Fatalf("RotateKey failed: %v", err)
		}
		if record.OldKeyID != key.ID {
			t.Errorf("expected old key %s, got %s", key.ID, record.OldKeyID)
		}

		active, _ := krm.GetActiveKey()
		if active.ID == key.ID {
			t.Error("active key should have changed after rotation")
		}
	})

	t.Run("RotateKey no active key", func(t *testing.T) {
		krm, _ := NewKeyRotationManager(nil)
		_, err := krm.RotateKey("test", 100)
		if err != ErrNoActiveKey {
			t.Errorf("expected ErrNoActiveKey, got %v", err)
		}
	})

	t.Run("RevokeKey", func(t *testing.T) {
		krm, _ := NewKeyRotationManager(nil)
		key, _ := krm.GenerateKey("Dilithium3")
		krm.ActivateKey(key.ID)

		err := krm.RevokeKey(key.ID)
		if err != nil {
			t.Fatalf("RevokeKey failed: %v", err)
		}

		_, err = krm.GetActiveKey()
		if err != ErrNoActiveKey {
			t.Errorf("expected ErrNoActiveKey after revoke, got %v", err)
		}
	})

	t.Run("CheckExpiry", func(t *testing.T) {
		krm, _ := NewKeyRotationManager(nil)
		key, _ := krm.GenerateKey("Dilithium3")
		key.ExpiresAt = time.Now().Add(-time.Hour).Unix()
		krm.ActivateKey(key.ID)

		expired := krm.CheckExpiry()
		if len(expired) != 1 {
			t.Errorf("expected 1 expired key, got %d", len(expired))
		}
	})

	t.Run("GetRotationHistory", func(t *testing.T) {
		krm, _ := NewKeyRotationManager(nil)
		key, _ := krm.GenerateKey("Dilithium3")
		krm.ActivateKey(key.ID)
		krm.RotateKey("test", 100)

		history := krm.GetRotationHistory()
		if len(history) != 1 {
			t.Errorf("expected 1 rotation record, got %d", len(history))
		}
	})

	t.Run("DeriveKeyID", func(t *testing.T) {
		krm, _ := NewKeyRotationManager(nil)
		pubKey := []byte("test-public-key")
		id := krm.DeriveKeyID(pubKey)
		if id == "" {
			t.Error("derived key ID is empty")
		}

		id2 := krm.DeriveKeyID(pubKey)
		if id != id2 {
			t.Error("same public key should produce same ID")
		}
	})
}

func TestMultiSigApproval(t *testing.T) {
	t.Run("NewMultiSigApproval", func(t *testing.T) {
		msa := NewMultiSigApproval(3)
		if msa == nil {
			t.Fatal("NewMultiSigApproval returned nil")
		}
	})

	t.Run("Approve", func(t *testing.T) {
		msa := NewMultiSigApproval(2)

		if msa.Approve("op-1", types.Address{1}) {
			t.Error("should not reach threshold with 1 approval")
		}

		if !msa.Approve("op-1", types.Address{2}) {
			t.Error("should reach threshold with 2 approvals")
		}
	})

	t.Run("GetApprovalCount", func(t *testing.T) {
		msa := NewMultiSigApproval(3)
		msa.Approve("op-1", types.Address{1})
		msa.Approve("op-1", types.Address{2})

		if msa.GetApprovalCount("op-1") != 2 {
			t.Errorf("expected 2 approvals, got %d", msa.GetApprovalCount("op-1"))
		}
	})
}

func TestQuantumSignatureAggregator(t *testing.T) {
	t.Run("NewQuantumSignatureAggregator", func(t *testing.T) {
		qsa := NewQuantumSignatureAggregator(3, 10)
		if qsa == nil {
			t.Fatal("NewQuantumSignatureAggregator returned nil")
		}
	})

	t.Run("Aggregate", func(t *testing.T) {
		qsa := NewQuantumSignatureAggregator(2, 10)
		msg := []byte("test message")

		sigs := [][]byte{
			[]byte("signature-1"),
			[]byte("signature-2"),
			[]byte("signature-3"),
		}
		keys := [][]byte{
			[]byte("pubkey-1"),
			[]byte("pubkey-2"),
			[]byte("pubkey-3"),
		}

		agg, err := qsa.Aggregate(msg, sigs, keys)
		if err != nil {
			t.Fatalf("Aggregate failed: %v", err)
		}
		if agg.Count != 3 {
			t.Errorf("expected count 3, got %d", agg.Count)
		}
	})

	t.Run("Aggregate insufficient", func(t *testing.T) {
		qsa := NewQuantumSignatureAggregator(5, 10)
		_, err := qsa.Aggregate([]byte("msg"), [][]byte{[]byte("sig")}, [][]byte{[]byte("key")})
		if err != ErrInsufficientSignatures {
			t.Errorf("expected ErrInsufficientSignatures, got %v", err)
		}
	})

	t.Run("VerifyAggregation", func(t *testing.T) {
		qsa := NewQuantumSignatureAggregator(2, 10)
		msg := []byte("test")
		// R26-017: Use real Dilithium3 keys and signatures since empty pubKeys
		// now cause verification to fail (security fix).
		kp1 := getTestPartyKey(1)
		kp2 := getTestPartyKey(2)
		sig1, _ := qaucrypto.Sign(kp1.priv, msg)
		sig2, _ := qaucrypto.Sign(kp2.priv, msg)
		sigs := [][]byte{sig1, sig2}
		keys := [][]byte{kp1.pub.Bytes(), kp2.pub.Bytes()}

		agg, _ := qsa.Aggregate(msg, sigs, keys)
		if !qsa.VerifyAggregation(agg) {
			t.Error("aggregation should be valid")
		}
	})

	t.Run("MergeAggregations", func(t *testing.T) {
		qsa := NewQuantumSignatureAggregator(2, 10)
		msg := []byte("test")

		a, _ := qsa.Aggregate(msg, [][]byte{[]byte("sig1"), []byte("sig2")}, [][]byte{[]byte("key1"), []byte("key2")})
		b, _ := qsa.Aggregate(msg, [][]byte{[]byte("sig3"), []byte("sig4")}, [][]byte{[]byte("key3"), []byte("key4")})

		merged, err := qsa.MergeAggregations(a, b)
		if err != nil {
			t.Fatalf("MergeAggregations failed: %v", err)
		}
		if merged.Count != 4 {
			t.Errorf("expected merged count 4, got %d", merged.Count)
		}
	})
}

func TestThresholdSignatureScheme(t *testing.T) {
	t.Run("NewThresholdSignatureScheme", func(t *testing.T) {
		tss := NewThresholdSignatureScheme(5, 3)
		if tss == nil {
			t.Fatal("NewThresholdSignatureScheme returned nil")
		}
	})

	t.Run("AddShare", func(t *testing.T) {
		tss := NewThresholdSignatureScheme(5, 3)
		err := tss.AddShare(0, []byte("share-0"), []byte("vk-0"))
		if err != nil {
			t.Fatalf("AddShare failed: %v", err)
		}
		if tss.ShareCount() != 1 {
			t.Errorf("expected 1 share, got %d", tss.ShareCount())
		}
	})

	t.Run("AddShare invalid index", func(t *testing.T) {
		tss := NewThresholdSignatureScheme(5, 3)
		err := tss.AddShare(10, []byte("share"), []byte("vk"))
		if err == nil {
			t.Error("should fail with invalid index")
		}
	})

	t.Run("CombineShares", func(t *testing.T) {
		tss := NewThresholdSignatureScheme(5, 3)
		// R26-018: Use real Dilithium3 keys and signatures since nil verification
		// keys now cause CombineShares to fail (security fix).
		msg := []byte("message")
		kp0 := getTestPartyKey(3)
		kp1 := getTestPartyKey(4)
		kp2 := getTestPartyKey(5)
		share0, _ := qaucrypto.Sign(kp0.priv, msg)
		share1, _ := qaucrypto.Sign(kp1.priv, msg)
		share2, _ := qaucrypto.Sign(kp2.priv, msg)
		tss.AddShare(0, share0, kp0.pub.Bytes())
		tss.AddShare(1, share1, kp1.pub.Bytes())
		tss.AddShare(2, share2, kp2.pub.Bytes())

		sig, err := tss.CombineShares(msg)
		if err != nil {
			t.Fatalf("CombineShares failed: %v", err)
		}
		if len(sig) != 32 {
			t.Errorf("expected signature length 32, got %d", len(sig))
		}
	})

	t.Run("CombineShares insufficient", func(t *testing.T) {
		tss := NewThresholdSignatureScheme(5, 3)
		tss.AddShare(0, []byte("share-0"), []byte("vk-0"))

		_, err := tss.CombineShares([]byte("message"))
		if err == nil {
			t.Error("should fail with insufficient shares")
		}
	})

	t.Run("HasThreshold", func(t *testing.T) {
		tss := NewThresholdSignatureScheme(5, 3)
		if tss.HasThreshold() {
			t.Error("should not have threshold with 0 shares")
		}

		tss.AddShare(0, []byte("s0"), []byte("v0"))
		tss.AddShare(1, []byte("s1"), []byte("v1"))
		tss.AddShare(2, []byte("s2"), []byte("v2"))

		if !tss.HasThreshold() {
			t.Error("should have threshold with 3 shares")
		}
	})
}

func TestZKProver(t *testing.T) {
	t.Run("NewZKProver", func(t *testing.T) {
		zkp := NewZKProver()
		zkp.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests
		if zkp == nil {
			t.Fatal("NewZKProver returned nil")
		}
	})

	t.Run("RegisterCircuit", func(t *testing.T) {
		zkp := NewZKProver()
		zkp.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests
		err := zkp.RegisterCircuit("circuit-1", "Test Circuit")
		if err != nil {
			t.Fatalf("RegisterCircuit failed: %v", err)
		}

		retrieved, ok := zkp.GetCircuit("circuit-1")
		if !ok {
			t.Fatal("circuit not found")
		}
		if retrieved.Name != "Test Circuit" {
			t.Errorf("expected 'Test Circuit', got '%s'", retrieved.Name)
		}
	})

	t.Run("GenerateProof", func(t *testing.T) {
		zkp := NewZKProver()
		zkp.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests
		err := zkp.RegisterCircuit("circuit-1", "Test")
		if err != nil {
			t.Fatalf("RegisterCircuit failed: %v", err)
		}

		privateInput := big.NewInt(42)
		publicInput := computeNativeMiMC(privateInput)

		proof, err := zkp.GenerateProof("circuit-1", privateInput, publicInput)
		if err != nil {
			t.Fatalf("GenerateProof failed: %v", err)
		}
		if proof.CircuitID != "circuit-1" {
			t.Errorf("expected circuit-1, got %s", proof.CircuitID)
		}
	})

	t.Run("GenerateProof nil witness", func(t *testing.T) {
		zkp := NewZKProver()
		zkp.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests
		err := zkp.RegisterCircuit("c1", "Test")
		if err != nil {
			t.Fatalf("RegisterCircuit failed: %v", err)
		}

		_, err = zkp.GenerateProof("c1", nil, big.NewInt(1))
		if err != ErrInvalidWitness {
			t.Errorf("expected ErrInvalidWitness, got %v", err)
		}
	})
}

func TestZKVerifier(t *testing.T) {
	t.Run("NewZKVerifier", func(t *testing.T) {
		zkv := NewZKVerifier()
		if zkv == nil {
			t.Fatal("NewZKVerifier returned nil")
		}
	})

	t.Run("VerifyProof", func(t *testing.T) {
		zkp := NewZKProver()
		zkp.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests
		err := zkp.RegisterCircuit("c1", "Test")
		if err != nil {
			t.Fatalf("RegisterCircuit failed: %v", err)
		}

		circuit, _ := zkp.GetCircuit("c1")

		zkv := NewZKVerifier()
		zkv.RegisterCircuit(circuit)

		privateInput := big.NewInt(42)
		publicInput := computeNativeMiMC(privateInput)

		proof, err := zkp.GenerateProof("c1", privateInput, publicInput)
		if err != nil {
			t.Fatalf("GenerateProof failed: %v", err)
		}

		valid, err := zkv.VerifyProof(proof)
		if err != nil {
			t.Fatalf("VerifyProof failed: %v", err)
		}
		if !valid {
			t.Error("proof should be valid")
		}
	})
}

func TestRangeProofSystem(t *testing.T) {
	t.Run("NewRangeProofSystem", func(t *testing.T) {
		rps := NewRangeProofSystem(64)
		rps.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests
		if rps == nil {
			t.Fatal("NewRangeProofSystem returned nil")
		}
	})

	t.Run("GenerateRangeProof", func(t *testing.T) {
		rps := NewRangeProofSystem(64)
		rps.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests
		value := big.NewInt(50)
		lower := big.NewInt(0)
		upper := big.NewInt(100)

		proof, err := rps.GenerateRangeProof(value, lower, upper)
		if err != nil {
			t.Fatalf("GenerateRangeProof failed: %v", err)
		}
		if proof == nil {
			t.Fatal("proof is nil")
		}
	})

	t.Run("GenerateRangeProof out of range", func(t *testing.T) {
		rps := NewRangeProofSystem(64)
		rps.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests
		_, err := rps.GenerateRangeProof(big.NewInt(200), big.NewInt(0), big.NewInt(100))
		if err == nil {
			t.Error("should fail for out-of-range value")
		}
	})

	t.Run("VerifyRangeProof", func(t *testing.T) {
		rps := NewRangeProofSystem(64)
		rps.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests
		value := big.NewInt(50)
		proof, _ := rps.GenerateRangeProof(value, big.NewInt(0), big.NewInt(100))

		if !rps.VerifyRangeProof(proof) {
			t.Error("range proof should be valid")
		}
	})
}

// TestZKProver_LoadTrustedSetup verifies that loading externally computed
// trusted setup keys (simulating MPC ceremony output) allows proof generation.
// AUDIT (2026) ZK-NN-7: Previously LoadTrustedSetup stored ccs=nil,
// making GenerateProof fail. Now it compiles the circuit so proofs work.
func TestZKProver_LoadTrustedSetup(t *testing.T) {
	// Step 1: Generate pk/vk via local setup (simulating MPC ceremony output).
	circuit := &genericCircuit{}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile generic circuit: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16.Setup (test ceremony): %v", err)
	}

	// Step 2: Load the trusted setup (no SetAllowInsecureSetup needed).
	zkp := NewZKProver()
	if err := zkp.LoadTrustedSetup("trusted-circuit", "Trusted Test Circuit", pk, vk); err != nil {
		t.Fatalf("LoadTrustedSetup failed: %v", err)
	}

	// Step 3: Generate a proof — should succeed using the loaded ccs+pk.
	privateInput := big.NewInt(42)
	publicInput := computeNativeMiMC(privateInput)

	proof, err := zkp.GenerateProof("trusted-circuit", privateInput, publicInput)
	if err != nil {
		t.Fatalf("GenerateProof with trusted setup failed: %v", err)
	}
	if proof == nil {
		t.Fatal("proof is nil")
	}

	// Step 4: Verify the proof using a verifier loaded with the same vk.
	zkv := NewZKVerifier()
	circuitEntry, _ := zkp.GetCircuit("trusted-circuit")
	zkv.RegisterCircuit(circuitEntry)

	valid, err := zkv.VerifyProof(proof)
	if err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}
	if !valid {
		t.Error("proof should be valid")
	}
}

// TestZKProver_LoadTrustedSetup_RejectsNil verifies that LoadTrustedSetup
// rejects nil pk/vk. AUDIT (2026) ZK-NN-7.
func TestZKProver_LoadTrustedSetup_RejectsNil(t *testing.T) {
	zkp := NewZKProver()
	err := zkp.LoadTrustedSetup("nil-test", "Nil Test", nil, nil)
	if err == nil {
		t.Fatal("LoadTrustedSetup should reject nil pk/vk")
	}
}

// TestRangeProofSystem_LoadTrustedRangeSetup verifies that loading externally
// computed trusted setup keys allows range proof generation without local
// groth16.Setup. AUDIT (2026) ZK-NN-7.
func TestRangeProofSystem_LoadTrustedRangeSetup(t *testing.T) {
	// Step 1: Generate pk/vk via local setup (simulating MPC ceremony output).
	circuit := &rangeProofCircuit{bitLen: 64}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile range circuit: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16.Setup (test ceremony): %v", err)
	}

	// Step 2: Load the trusted setup (no SetAllowInsecureSetup needed).
	rps := NewRangeProofSystem(64)
	if err := rps.LoadTrustedRangeSetup(pk, vk); err != nil {
		t.Fatalf("LoadTrustedRangeSetup failed: %v", err)
	}

	// Step 3: Generate a range proof — should succeed using loaded keys.
	value := big.NewInt(50)
	proof, err := rps.GenerateRangeProof(value, big.NewInt(0), big.NewInt(100))
	if err != nil {
		t.Fatalf("GenerateRangeProof with trusted setup failed: %v", err)
	}
	if proof == nil {
		t.Fatal("proof is nil")
	}

	// Step 4: Verify the proof.
	if !rps.VerifyRangeProof(proof) {
		t.Error("range proof should be valid")
	}
}

// TestRangeProofSystem_LoadTrustedRangeSetup_RejectsNil verifies that
// LoadTrustedRangeSetup rejects nil pk/vk. AUDIT (2026) ZK-NN-7.
func TestRangeProofSystem_LoadTrustedRangeSetup_RejectsNil(t *testing.T) {
	rps := NewRangeProofSystem(64)
	err := rps.LoadTrustedRangeSetup(nil, nil)
	if err == nil {
		t.Fatal("LoadTrustedRangeSetup should reject nil pk/vk")
	}
}

func TestMPCManager(t *testing.T) {
	t.Run("NewMPCManager", func(t *testing.T) {
		mpc := NewMPCManager(nil)
		if mpc == nil {
			t.Fatal("NewMPCManager returned nil")
		}
	})

	t.Run("RegisterParty", func(t *testing.T) {
		mpc := NewMPCManager(nil)
		party := &MPCParty{
			ID:        types.Address{1},
			PublicKey: []byte("pubkey"),
			Index:     0,
		}

		err := mpc.RegisterParty(party)
		if err != nil {
			t.Fatalf("RegisterParty failed: %v", err)
		}
		if mpc.GetPartyCount() != 1 {
			t.Errorf("expected 1 party, got %d", mpc.GetPartyCount())
		}
	})

	t.Run("RegisterParty duplicate", func(t *testing.T) {
		mpc := NewMPCManager(nil)
		party := &MPCParty{ID: types.Address{1}, PublicKey: []byte("pk")}
		mpc.RegisterParty(party)

		err := mpc.RegisterParty(party)
		if err == nil {
			t.Error("should fail on duplicate party")
		}
	})

	t.Run("CreateSession", func(t *testing.T) {
		mpc := NewMPCManager(nil)
		mpc.RegisterParty(&MPCParty{ID: types.Address{1}, PublicKey: []byte("pk1")})
		mpc.RegisterParty(&MPCParty{ID: types.Address{2}, PublicKey: []byte("pk2")})
		mpc.RegisterParty(&MPCParty{ID: types.Address{3}, PublicKey: []byte("pk3")})

		session, err := mpc.CreateSession("session-1", []types.Address{{1}, {2}, {3}})
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
		if session.Phase != MPCPhaseSetup {
			t.Errorf("expected setup phase, got %d", session.Phase)
		}
	})

	t.Run("CreateSession insufficient parties", func(t *testing.T) {
		mpc := NewMPCManager(nil)
		_, err := mpc.CreateSession("s1", []types.Address{{1}})
		if err != ErrInsufficientParties {
			t.Errorf("expected ErrInsufficientParties, got %v", err)
		}
	})

	t.Run("SubmitShare", func(t *testing.T) {
		mpc := NewMPCManager(nil)
		registerTestParty(mpc, 1)
		registerTestParty(mpc, 2)
		registerTestParty(mpc, 3)

		session, _ := mpc.CreateSession("session-1", []types.Address{{1}, {2}, {3}})
		session.Phase = MPCPhaseShareDist

		share := []byte("share-data-1")
		// audit fix (MEDIUM-6): compute the commitment as HMAC(sessionSecret, share)
		h := hmacHash(share, session.sessionSecret)
		sig := signTestShare("session-1", 1, share, h)

		err := mpc.SubmitShare("session-1", types.Address{1}, share, h, sig)
		if err != nil {
			t.Fatalf("SubmitShare failed: %v", err)
		}
	})

	t.Run("ComputeResult", func(t *testing.T) {
		mpc := NewMPCManager(nil)
		registerTestParty(mpc, 1)
		registerTestParty(mpc, 2)
		registerTestParty(mpc, 3)
		registerTestParty(mpc, 4)
		registerTestParty(mpc, 5)

		session, _ := mpc.CreateSession("session-1", []types.Address{{1}, {2}, {3}, {4}, {5}})
		session.Phase = MPCPhaseShareDist

		for i := 1; i <= 5; i++ {
			addr := types.Address{byte(i)}
			share := []byte{byte(i), byte(i + 1), byte(i + 2)}
			// audit fix (MEDIUM-6): compute the commitment as HMAC(sessionSecret, share)
			h := hmacHash(share, session.sessionSecret)
			sig := signTestShare("session-1", byte(i), share, h)
			mpc.SubmitShare("session-1", addr, share, h, sig)
		}

		result, err := mpc.ComputeResult("session-1")
		if err != nil {
			t.Fatalf("ComputeResult failed: %v", err)
		}
		if len(result) == 0 {
			t.Errorf("expected non-empty result from Lagrange interpolation")
		}
	})

	t.Run("ReconstructSecret", func(t *testing.T) {
		mpc := NewMPCManager(nil)
		for i := 1; i <= 5; i++ {
			registerTestParty(mpc, byte(i))
		}

		session, _ := mpc.CreateSession("session-1", []types.Address{{1}, {2}, {3}, {4}, {5}})
		session.Phase = MPCPhaseShareDist

		for i := 1; i <= 5; i++ {
			addr := types.Address{byte(i)}
			share := []byte{byte(i)}
			// audit fix (MEDIUM-6): compute the commitment as HMAC(sessionSecret, share)
			h := hmacHash(share, session.sessionSecret)
			sig := signTestShare("session-1", byte(i), share, h)
			mpc.SubmitShare("session-1", addr, share, h, sig)
		}

		mpc.ComputeResult("session-1")
		secret, err := mpc.ReconstructSecret("session-1")
		if err != nil {
			t.Fatalf("ReconstructSecret failed: %v", err)
		}
		if len(secret) == 0 {
			t.Errorf("expected non-empty secret from Lagrange interpolation")
		}
	})
}

func TestSecretSharingScheme(t *testing.T) {
	t.Run("NewSecretSharingScheme", func(t *testing.T) {
		sss, err := NewSecretSharingScheme(3, 5)
		if err != nil {
			t.Fatalf("NewSecretSharingScheme failed: %v", err)
		}
		if sss == nil {
			t.Fatal("NewSecretSharingScheme returned nil")
		}
	})

	t.Run("SplitSecret", func(t *testing.T) {
		sss, err := NewSecretSharingScheme(3, 5)
		if err != nil {
			t.Fatalf("NewSecretSharingScheme failed: %v", err)
		}
		secret := []byte("my-secret-data-for-sharing")

		shares, err := sss.SplitSecret(secret)
		if err != nil {
			t.Fatalf("SplitSecret failed: %v", err)
		}
		if len(shares) != 5 {
			t.Errorf("expected 5 shares, got %d", len(shares))
		}
	})

	t.Run("ReconstructSecret", func(t *testing.T) {
		sss, err := NewSecretSharingScheme(3, 5)
		if err != nil {
			t.Fatalf("NewSecretSharingScheme failed: %v", err)
		}
		secret := []byte("test-secret")

		shares, _ := sss.SplitSecret(secret)

		subset := map[int][]byte{
			1: shares[1],
			2: shares[2],
			3: shares[3],
		}

		reconstructed, err := sss.ReconstructSecret(subset)
		if err != nil {
			t.Fatalf("ReconstructSecret failed: %v", err)
		}
		if len(reconstructed) == 0 {
			t.Error("reconstructed secret is empty")
		}
	})

	t.Run("ReconstructSecret insufficient", func(t *testing.T) {
		sss, err := NewSecretSharingScheme(3, 5)
		if err != nil {
			t.Fatalf("NewSecretSharingScheme failed: %v", err)
		}
		secret := []byte("test")

		shares, _ := sss.SplitSecret(secret)

		_, err = sss.ReconstructSecret(map[int][]byte{1: shares[1]})
		if err != ErrInsufficientParties {
			t.Errorf("expected ErrInsufficientParties, got %v", err)
		}
	})

	// R26-004: ReconstructSecret must reject reconstruction when no
	// commitments are available (i.e. SplitSecret was never called),
	// preventing forged-share injection into an unverified path.
	t.Run("ReconstructSecret without commitments", func(t *testing.T) {
		sss, err := NewSecretSharingScheme(3, 5)
		if err != nil {
			t.Fatalf("NewSecretSharingScheme failed: %v", err)
		}

		// Forge enough shares to pass the threshold check but supply no
		// commitments (SplitSecret was never called).
		forged := map[int][]byte{
			1: []byte("forged-share-1"),
			2: []byte("forged-share-2"),
			3: []byte("forged-share-3"),
		}

		_, err = sss.ReconstructSecret(forged)
		if !errors.Is(err, ErrShareVerificationFailed) {
			t.Fatalf("expected ErrShareVerificationFailed, got %v", err)
		}
	})
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// hmacHash computes HMAC-SHA256(key, data), used to test verifyCommitment
func hmacHash(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func TestKeyRotation_GetKey(t *testing.T) {
	krm, _ := NewKeyRotationManager(nil)
	key, _ := krm.GenerateKey("Dilithium3")

	got, err := krm.GetKey(key.ID)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("expected key %s, got %s", key.ID, got.ID)
	}
}

func TestKeyRotation_GetKey_NotFound(t *testing.T) {
	krm, _ := NewKeyRotationManager(nil)
	_, err := krm.GetKey("nonexistent")
	if err != ErrInvalidKeyID {
		t.Errorf("expected ErrInvalidKeyID, got %v", err)
	}
}

func TestKeyRotation_TimeUntilNextRotation(t *testing.T) {
	krm, _ := NewKeyRotationManager(nil)
	dur := krm.TimeUntilNextRotation()
	_ = dur
}

func TestMPC_GetSession(t *testing.T) {
	mpc := NewMPCManager(nil)
	s, _ := mpc.GetSession("nonexistent")
	if s != nil {
		t.Error("GetSession should return nil for nonexistent session")
	}
}

func TestMPC_GetActiveSessionCount(t *testing.T) {
	mpc := NewMPCManager(nil)
	if mpc.GetActiveSessionCount() != 0 {
		t.Error("expected 0 active sessions initially")
	}
}

func TestQuantumProofGenerator(t *testing.T) {
	qpg := NewQuantumProofGenerator()
	if qpg == nil {
		t.Fatal("expected non-nil")
	}

	t.Run("GenerateChallenge", func(t *testing.T) {
		ch, err := qpg.GenerateChallenge("session-1")
		if err != nil {
			t.Fatalf("GenerateChallenge failed: %v", err)
		}
		if len(ch) != 32 {
			t.Errorf("expected 32-byte challenge, got %d", len(ch))
		}
	})

	t.Run("VerifyResponse_Valid", func(t *testing.T) {
		qpg2 := NewQuantumProofGenerator()
		ch, err := qpg2.GenerateChallenge("session-2")
		if err != nil {
			t.Fatalf("GenerateChallenge failed: %v", err)
		}
		// audit fix (CRITICAL-1): VerifyResponse now verifies via HMAC(sessionSecret, challenge)
		sessionSecret := qpg2.sessionSecrets["session-2"]
		response := make([]byte, 64)
		mac := hmac.New(sha256.New, sessionSecret)
		mac.Write(ch)
		copy(response[:32], mac.Sum(nil))
		if !qpg2.VerifyResponse("session-2", response) {
			t.Error("expected valid response")
		}
	})

	t.Run("VerifyResponse_NotFound", func(t *testing.T) {
		qpg3 := NewQuantumProofGenerator()
		if qpg3.VerifyResponse("unknown", make([]byte, 64)) {
			t.Error("expected false for unknown session")
		}
	})

	t.Run("VerifyResponse_Short", func(t *testing.T) {
		qpg4 := NewQuantumProofGenerator()
		if _, err := qpg4.GenerateChallenge("session-3"); err != nil {
			t.Fatalf("GenerateChallenge failed: %v", err)
		}
		if qpg4.VerifyResponse("session-3", make([]byte, 10)) {
			t.Error("expected false for short response")
		}
	})
}

func TestSignatureErrors(t *testing.T) {
	errors := []error{
		ErrInvalidKeyID,
		ErrKeyExpired,
		ErrNoActiveKey,
		ErrInsufficientSignatures,
		ErrInsufficientParties,
	}
	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error should have message")
		}
	}
}

func TestVerifyAggregation_EdgeCases(t *testing.T) {
	qsa := NewQuantumSignatureAggregator(2, 10)

	t.Run("nil agg", func(t *testing.T) {
		if qsa.VerifyAggregation(nil) {
			t.Error("should return false for nil agg")
		}
	})

	t.Run("count below threshold", func(t *testing.T) {
		agg := &AggregatedSignature{
			Count:     1,
			Threshold: 2,
		}
		if qsa.VerifyAggregation(agg) {
			t.Error("should return false when count < threshold")
		}
	})

	t.Run("tampered aggregated", func(t *testing.T) {
		msg := []byte("test")
		sigs := [][]byte{[]byte("sig1"), []byte("sig2")}
		keys := [][]byte{[]byte("key1"), []byte("key2")}
		agg, _ := qsa.Aggregate(msg, sigs, keys)

		tampered := &AggregatedSignature{
			Message:    agg.Message,
			Signatures: agg.Signatures,
			PublicKeys: agg.PublicKeys,
			Aggregated: []byte("tampered"),
			Count:      agg.Count,
			Threshold:  agg.Threshold,
		}
		if qsa.VerifyAggregation(tampered) {
			t.Error("should return false for tampered aggregated")
		}
	})
}

func TestMergeAggregations_EdgeCases(t *testing.T) {
	qsa := NewQuantumSignatureAggregator(2, 10)

	t.Run("nil a", func(t *testing.T) {
		b, _ := qsa.Aggregate([]byte("msg"), [][]byte{[]byte("sig1"), []byte("sig2")}, [][]byte{[]byte("k1"), []byte("k2")})
		_, err := qsa.MergeAggregations(nil, b)
		if err != ErrAggregationFailed {
			t.Errorf("expected ErrAggregationFailed, got %v", err)
		}
	})

	t.Run("nil b", func(t *testing.T) {
		a, _ := qsa.Aggregate([]byte("msg"), [][]byte{[]byte("sig1"), []byte("sig2")}, [][]byte{[]byte("k1"), []byte("k2")})
		_, err := qsa.MergeAggregations(a, nil)
		if err != ErrAggregationFailed {
			t.Errorf("expected ErrAggregationFailed, got %v", err)
		}
	})
}

func TestBytesEqual(t *testing.T) {
	if !bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Error("should be equal")
	}
	if bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Error("should not be equal")
	}
	if bytesEqual([]byte{1, 2, 3}, []byte{1, 2}) {
		t.Error("should not be equal with diff lengths")
	}
	if !bytesEqual([]byte{}, []byte{}) {
		t.Error("empty slices should be equal")
	}
}

func TestActivateKey_RevokedKey(t *testing.T) {
	krm, _ := NewKeyRotationManager(nil)
	key, _ := krm.GenerateKey("Dilithium3")
	krm.ActivateKey(key.ID)
	krm.RevokeKey(key.ID)

	err := krm.ActivateKey(key.ID)
	if err == nil {
		t.Error("should fail when activating revoked key")
	}
}

func TestActivateKey_ReplaceActive(t *testing.T) {
	krm, _ := NewKeyRotationManager(nil)
	key1, _ := krm.GenerateKey("Dilithium3")
	key2, _ := krm.GenerateKey("Dilithium3")
	krm.ActivateKey(key1.ID)

	err := krm.ActivateKey(key2.ID)
	if err != nil {
		t.Fatalf("ActivateKey failed: %v", err)
	}

	active, _ := krm.GetActiveKey()
	if active.ID != key2.ID {
		t.Errorf("expected active key %s, got %s", key2.ID, active.ID)
	}
}

func TestGetActiveSessionCount_WithSession(t *testing.T) {
	mpc := NewMPCManager(nil)
	mpc.RegisterParty(&MPCParty{ID: types.Address{1}, PublicKey: []byte("pk1")})
	mpc.RegisterParty(&MPCParty{ID: types.Address{2}, PublicKey: []byte("pk2")})
	mpc.RegisterParty(&MPCParty{ID: types.Address{3}, PublicKey: []byte("pk3")})

	mpc.CreateSession("s1", []types.Address{{1}, {2}, {3}})

	if mpc.GetActiveSessionCount() != 1 {
		t.Errorf("expected 1 active session, got %d", mpc.GetActiveSessionCount())
	}
}

func TestRegisterCircuit_Duplicate(t *testing.T) {
	zkp := NewZKProver()
	zkp.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests
	err := zkp.RegisterCircuit("c1", "Test Circuit")
	if err != nil {
		t.Fatalf("first register failed: %v", err)
	}

	circuit, ok := zkp.GetCircuit("c1")
	if !ok {
		t.Fatal("circuit not found")
	}

	err = zkp.RegisterCircuit("c1", "Duplicate")
	if err != nil {
		t.Fatalf("duplicate register should silently succeed: %v", err)
	}

	circuit2, ok := zkp.GetCircuit("c1")
	if !ok {
		t.Fatal("circuit not found after duplicate")
	}
	if circuit2.Name != "Test Circuit" {
		t.Errorf("name should not change on duplicate: got %s", circuit2.Name)
	}
	_ = circuit
}

func TestVerifyRangeProof_WrongValue(t *testing.T) {
	rps := NewRangeProofSystem(64)
	rps.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests
	value := big.NewInt(50)
	proof, _ := rps.GenerateRangeProof(value, big.NewInt(0), big.NewInt(100))

	rps2 := NewRangeProofSystem(64)
	otherValue := big.NewInt(60)
	otherProof, _ := rps2.GenerateRangeProof(otherValue, big.NewInt(0), big.NewInt(100))

	if rps.VerifyRangeProof(otherProof) {
		t.Error("should reject proof from different system instance")
	}
	if rps2.VerifyRangeProof(proof) {
		t.Error("should reject proof from other system")
	}
}

func TestGenerateRangeProof_EdgeValues(t *testing.T) {
	rps := NewRangeProofSystem(64)
	rps.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests

	t.Run("exactly lower bound", func(t *testing.T) {
		proof, err := rps.GenerateRangeProof(big.NewInt(0), big.NewInt(0), big.NewInt(100))
		if err != nil {
			t.Fatalf("GenerateRangeProof failed: %v", err)
		}
		if !rps.VerifyRangeProof(proof) {
			t.Error("should be valid at lower bound")
		}
	})

	t.Run("exactly upper bound", func(t *testing.T) {
		proof, err := rps.GenerateRangeProof(big.NewInt(100), big.NewInt(0), big.NewInt(100))
		if err != nil {
			t.Fatalf("GenerateRangeProof failed: %v", err)
		}
		if !rps.VerifyRangeProof(proof) {
			t.Error("should be valid at upper bound")
		}
	})
}

func TestSubmitShare_InvalidPhase(t *testing.T) {
	mpc := NewMPCManager(nil)
	registerTestParty(mpc, 1)
	registerTestParty(mpc, 2)
	registerTestParty(mpc, 3)

	session, _ := mpc.CreateSession("s1", []types.Address{{1}, {2}, {3}})
	// Session is in MPCPhaseSetup (not MPCPhaseShareDist)

	// R26-019: Signature verification now happens BEFORE the phase check,
	// so we must provide a valid signature to reach the phase check.
	share := []byte("share")
	commitment := hmacHash(share, session.sessionSecret)
	sig := signTestShare("s1", 1, share, commitment)

	err := mpc.SubmitShare("s1", types.Address{1}, share, commitment, sig)
	if err == nil {
		t.Error("should fail when session not in share distribution phase")
	}
}

func TestComputeResult_NotReady(t *testing.T) {
	mpc := NewMPCManager(nil)
	mpc.RegisterParty(&MPCParty{ID: types.Address{1}, PublicKey: []byte("pk1")})
	mpc.RegisterParty(&MPCParty{ID: types.Address{2}, PublicKey: []byte("pk2")})
	mpc.RegisterParty(&MPCParty{ID: types.Address{3}, PublicKey: []byte("pk3")})

	mpc.CreateSession("s1", []types.Address{{1}, {2}, {3}})

	_, err := mpc.ComputeResult("s1")
	if err == nil {
		t.Error("should fail when no shares submitted")
	}
}

func TestReconstructSecret_NotComputed(t *testing.T) {
	mpc := NewMPCManager(nil)
	_, err := mpc.ReconstructSecret("nonexistent")
	if err == nil {
		t.Error("should fail for nonexistent session")
	}
}

func TestGenerateChallenge_Multiple(t *testing.T) {
	qpg := NewQuantumProofGenerator()
	ch1, err := qpg.GenerateChallenge("s1")
	if err != nil {
		t.Fatalf("GenerateChallenge s1 failed: %v", err)
	}
	ch2, err := qpg.GenerateChallenge("s2")
	if err != nil {
		t.Fatalf("GenerateChallenge s2 failed: %v", err)
	}

	if len(ch1) != 32 || len(ch2) != 32 {
		t.Error("challenges should be 32 bytes")
	}
}

func TestVerifyResponse_LargeInput(t *testing.T) {
	qpg := NewQuantumProofGenerator()
	if _, err := qpg.GenerateChallenge("s1"); err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}
	largeResp := make([]byte, 128)
	if qpg.VerifyResponse("s1", largeResp) {
		t.Log("verify response with large input returned true")
	}
}

func TestRotateKey_InProgress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrent rotate test")
	}
	// Verify the rotation lock is functional by checking state
	krm, _ := NewKeyRotationManager(nil)
	// R3-N2 FIX: Disable MinRotationInterval for rapid sequential test rotations.
	krm.policy.MinRotationInterval = 0
	key, _ := krm.GenerateKey("Dilithium3")
	krm.ActivateKey(key.ID)

	// After a successful rotation, rotating should be false
	_, err := krm.RotateKey("test1", 100)
	if err != nil {
		t.Fatalf("first rotate failed: %v", err)
	}

	_, err = krm.RotateKey("test2", 200)
	if err != nil {
		t.Fatalf("second rotate failed: %v", err)
	}
}

func TestGenerateKey_AnyAlgorithm(t *testing.T) {
	krm, _ := NewKeyRotationManager(nil)
	key, err := krm.GenerateKey("AnyAlgorithmName")
	if err != nil {
		t.Fatalf("GenerateKey should accept any algorithm name: %v", err)
	}
	if key.Algorithm != "AnyAlgorithmName" {
		t.Errorf("expected 'AnyAlgorithmName', got '%s'", key.Algorithm)
	}
}

func TestVerifyProof_InvalidCircuit(t *testing.T) {
	zkv := NewZKVerifier()
	proof := &ZKProof{CircuitID: "nonexistent"}
	_, err := zkv.VerifyProof(proof)
	if err == nil {
		t.Error("should fail for unregistered circuit")
	}
}

func TestGenerateProof_NilCircuit(t *testing.T) {
	zkp := NewZKProver()
	zkp.SetAllowInsecureSetup(true) // audit-fix Round3 C-1: allow insecure setup in tests
	_, err := zkp.GenerateProof("nonexistent", big.NewInt(1), big.NewInt(1))
	if err == nil {
		t.Error("should fail for unregistered circuit")
	}
}

// audit-fix L6-017: bytesEqual moved here from zkp.go. It is only used by
// tests (TestBytesEqual). Production code should use crypto/subtle.ConstantTimeCompare
// for constant-time byte comparison.
//
// P5-1 AUDIT NOTE (test-only, constant-time not required): This helper lives
// in a _test.go file and is NEVER linked into production binaries. The audit
// flagged it as a "non-constant-time comparison", but in test code a
// timing side channel is irrelevant — there is no secret to leak and no
// attacker observing the test. (Note: the byte loop below is in fact
// constant-time via XOR accumulation; only the length check short-circuits,
// which is fine for tests.) No change to behavior; this comment documents
// why the lower bar is acceptable here.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
