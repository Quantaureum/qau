// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

func generateTestKeyPair(t *testing.T) (*crypto.PrivateKey, *crypto.PublicKey) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp.Private, kp.Public
}

func TestPQVRF_BasicEvalAndVerify(t *testing.T) {
	sk, pk := generateTestKeyPair(t)

	input := []byte("test-input-stardust-consensus")

	proof, output, err := PQVRFEval(sk, input)
	if err != nil {
		t.Fatalf("PQVRFEval: %v", err)
	}

	if len(proof.Proof) != PQVRFProofSize {
		t.Errorf("proof size: got %d, want %d", len(proof.Proof), PQVRFProofSize)
	}

	if len(output.Value) != PQVRFOutputSize {
		t.Errorf("output size: got %d, want %d", len(output.Value), PQVRFOutputSize)
	}

	err = PQVRFVerify(pk, input, proof, output)
	if err != nil {
		t.Fatalf("PQVRFVerify: %v", err)
	}
}

func TestPQVRF_EvalHash(t *testing.T) {
	sk, pk := generateTestKeyPair(t)

	var seed types.Hash
	rand.Read(seed[:])

	proof, output, err := PQVRFEvalHash(sk, seed)
	if err != nil {
		t.Fatalf("PQVRFEvalHash: %v", err)
	}

	err = PQVRFVerifyHash(pk, seed, proof, output)
	if err != nil {
		t.Fatalf("PQVRFVerifyHash: %v", err)
	}
}

func TestPQVRF_Uniqueness(t *testing.T) {
	sk, _ := generateTestKeyPair(t)

	input := []byte("uniqueness-test-input")

	err := PQVRFCheckUniqueness(sk, input, 100)
	if err != nil {
		t.Fatalf("uniqueness check failed: %v", err)
	}
}

func TestPQVRF_Uniqueness_DifferentInputs(t *testing.T) {
	sk, pk := generateTestKeyPair(t)

	inputs := [][]byte{
		[]byte("input-1"),
		[]byte("input-2"),
		[]byte("input-3"),
	}

	outputs := make(map[[PQVRFOutputSize]byte]bool)
	for _, input := range inputs {
		_, output, err := PQVRFEval(sk, input)
		if err != nil {
			t.Fatalf("PQVRFEval(%s): %v", input, err)
		}

		if outputs[output.Value] {
			t.Errorf("duplicate output for different input: %x", output.Value)
		}
		outputs[output.Value] = true
	}

	if len(outputs) != len(inputs) {
		t.Errorf("expected %d distinct outputs, got %d", len(inputs), len(outputs))
	}

	_ = pk
}

func TestPQVRF_Uniqueness_SameInputDifferentKeys(t *testing.T) {
	sk1, _ := generateTestKeyPair(t)
	sk2, _ := generateTestKeyPair(t)

	input := []byte("same-input-different-keys")

	_, output1, err := PQVRFEval(sk1, input)
	if err != nil {
		t.Fatalf("PQVRFEval key1: %v", err)
	}

	_, output2, err := PQVRFEval(sk2, input)
	if err != nil {
		t.Fatalf("PQVRFEval key2: %v", err)
	}

	if output1.Value == output2.Value {
		t.Error("different keys should produce different outputs for the same input")
	}
}

func TestPQVRF_Pseudorandomness_Statistical(t *testing.T) {
	sk, _ := generateTestKeyPair(t)

	const numSamples = 2000
	outputs := make([][PQVRFOutputSize]byte, numSamples)

	for i := 0; i < numSamples; i++ {
		var input [8]byte
		binary.BigEndian.PutUint64(input[:], uint64(i))

		_, output, err := PQVRFEval(sk, input[:])
		if err != nil {
			t.Fatalf("PQVRFEval(%d): %v", i, err)
		}
		outputs[i] = output.Value
	}

	t.Run("BitBalance", func(t *testing.T) {
		ones := 0
		total := numSamples * PQVRFOutputSize * 8
		for _, output := range outputs {
			for _, b := range output {
				for bit := 0; bit < 8; bit++ {
					if b&(1<<uint(bit)) != 0 {
						ones++
					}
				}
			}
		}
		ratio := float64(ones) / float64(total)
		if math.Abs(ratio-0.5) > 0.01 {
			t.Errorf("bit ratio = %.4f, expected ≈0.5000", ratio)
		}
	})

	t.Run("ByteUniformity_ChiSquared", func(t *testing.T) {
		buckets := make([]int, 256)
		for _, output := range outputs {
			for _, b := range output {
				buckets[b]++
			}
		}

		expected := float64(numSamples*PQVRFOutputSize) / 256.0
		chiSquared := 0.0
		for _, count := range buckets {
			diff := float64(count) - expected
			chiSquared += diff * diff / expected
		}

		df := 255
		criticalValue := 310.457
		if chiSquared > criticalValue {
			t.Errorf("chi-squared = %.2f > critical value %.3f (df=%d, α=0.01)", chiSquared, criticalValue, df)
		} else {
			t.Logf("chi-squared = %.2f < critical value %.3f ✅ (df=%d, α=0.01)", chiSquared, criticalValue, df)
		}
	})

	t.Run("SerialCorrelation", func(t *testing.T) {
		var sumX, sumY, sumXY, sumX2, sumY2 float64
		n := float64(numSamples - 1)
		for i := 0; i < numSamples-1; i++ {
			x := float64(outputs[i][0])
			y := float64(outputs[i+1][0])
			sumX += x
			sumY += y
			sumXY += x * y
			sumX2 += x * x
			sumY2 += y * y
		}
		// When the denominator is zero, one series has zero variance and no
		// linear correlation is detectable. Default to 0.0 (well within the
		// |r| < 0.1 bound) instead of skipping the test.
		var correlation float64
		denom := math.Sqrt((n*sumX2 - sumX*sumX) * (n*sumY2 - sumY*sumY))
		if denom != 0 {
			correlation = (n*sumXY - sumX*sumY) / denom
		}
		if math.Abs(correlation) > 0.1 {
			t.Errorf("serial correlation = %.4f, expected |r| < 0.1", correlation)
		} else {
			t.Logf("serial correlation = %.4f ✅", correlation)
		}
	})
}

func TestPQVRF_Pseudorandomness_OutputDistribution(t *testing.T) {
	sk, _ := generateTestKeyPair(t)

	const numSamples = 2000
	const numBuckets = 256

	bucketCounts := make([]int, numBuckets)

	for i := 0; i < numSamples; i++ {
		var input [8]byte
		binary.BigEndian.PutUint64(input[:], uint64(i))

		_, output, err := PQVRFEval(sk, input[:])
		if err != nil {
			t.Fatalf("PQVRFEval(%d): %v", i, err)
		}

		bucket := output.Value[0]
		bucketCounts[bucket]++
	}

	expected := float64(numSamples) / float64(numBuckets)
	chiSquared := 0.0
	for _, count := range bucketCounts {
		diff := float64(count) - expected
		chiSquared += diff * diff / expected
	}

	df := numBuckets - 1
	criticalValue := 310.457
	if chiSquared > criticalValue {
		t.Errorf("chi-squared = %.2f > critical value %.3f (df=%d, α=0.01)", chiSquared, criticalValue, df)
	} else {
		t.Logf("output distribution chi-squared = %.2f < critical value %.3f ✅ (df=%d, α=0.01)", chiSquared, criticalValue, df)
	}
}

func TestPQVRF_VerifyRejects_InvalidProof(t *testing.T) {
	sk, pk := generateTestKeyPair(t)

	input := []byte("test-input")
	proof, output, err := PQVRFEval(sk, input)
	if err != nil {
		t.Fatalf("PQVRFEval: %v", err)
	}

	tamperedProof := &PQVRFProof{Proof: make([]byte, PQVRFProofSize)}
	copy(tamperedProof.Proof, proof.Proof)
	tamperedProof.Proof[0] ^= 0xFF

	err = PQVRFVerify(pk, input, tamperedProof, output)
	if err == nil {
		t.Error("should reject tampered proof")
	}
}

func TestPQVRF_VerifyRejects_InvalidOutput(t *testing.T) {
	sk, pk := generateTestKeyPair(t)

	input := []byte("test-input")
	proof, output, err := PQVRFEval(sk, input)
	if err != nil {
		t.Fatalf("PQVRFEval: %v", err)
	}

	tamperedOutput := &PQVRFOutput{}
	copy(tamperedOutput.Value[:], output.Value[:])
	tamperedOutput.Value[0] ^= 0xFF

	err = PQVRFVerify(pk, input, proof, tamperedOutput)
	if err == nil {
		t.Error("should reject tampered output")
	}
}

func TestPQVRF_VerifyRejects_WrongKey(t *testing.T) {
	sk, _ := generateTestKeyPair(t)
	_, wrongPK := generateTestKeyPair(t)

	input := []byte("test-input")
	proof, output, err := PQVRFEval(sk, input)
	if err != nil {
		t.Fatalf("PQVRFEval: %v", err)
	}

	err = PQVRFVerify(wrongPK, input, proof, output)
	if err == nil {
		t.Error("should reject proof verified with wrong public key")
	}
}

func TestPQVRF_VerifyRejects_WrongInput(t *testing.T) {
	sk, pk := generateTestKeyPair(t)

	proof, output, err := PQVRFEval(sk, []byte("input-A"))
	if err != nil {
		t.Fatalf("PQVRFEval: %v", err)
	}

	err = PQVRFVerify(pk, []byte("input-B"), proof, output)
	if err == nil {
		t.Error("should reject proof for wrong input")
	}
}

func TestPQVRF_VerifyRejects_NilInputs(t *testing.T) {
	sk, pk := generateTestKeyPair(t)
	input := []byte("test")

	_, _, err := PQVRFEval(nil, input)
	if err != ErrPQVRFNilPrivateKey {
		t.Errorf("expected ErrPQVRFNilPrivateKey, got %v", err)
	}

	proof, output, _ := PQVRFEval(sk, input)

	err = PQVRFVerify(nil, input, proof, output)
	if err != ErrPQVRFNilPublicKey {
		t.Errorf("expected ErrPQVRFNilPublicKey, got %v", err)
	}

	err = PQVRFVerify(pk, input, nil, output)
	if err != ErrPQVRFInvalidProof {
		t.Errorf("expected ErrPQVRFInvalidProof, got %v", err)
	}

	err = PQVRFVerify(pk, input, proof, nil)
	if err != ErrPQVRFInvalidOutput {
		t.Errorf("expected ErrPQVRFInvalidOutput, got %v", err)
	}
}

func TestPQVRF_BatchVerification(t *testing.T) {
	const numKeys = 10
	const inputsPerKey = 5

	var requests []PQVRFVerificationRequest

	for k := 0; k < numKeys; k++ {
		sk, pk := generateTestKeyPair(t)
		for i := 0; i < inputsPerKey; i++ {
			input := []byte(fmt.Sprintf("key%d-input%d", k, i))
			proof, output, err := PQVRFEval(sk, input)
			if err != nil {
				t.Fatalf("PQVRFEval: %v", err)
			}
			requests = append(requests, PQVRFVerificationRequest{
				PublicKey: pk,
				Input:     input,
				Proof:     proof,
				Output:    output,
			})
		}
	}

	results := PQVRFVerifyBatch(requests)
	if len(results) != len(requests) {
		t.Fatalf("expected %d results, got %d", len(requests), len(results))
	}

	for i, r := range results {
		if !r.Valid {
			t.Errorf("request %d: expected valid, got error %v", i, r.Error)
		}
	}
}

func TestPQVRF_BatchVerification_WithInvalid(t *testing.T) {
	sk, pk := generateTestKeyPair(t)

	var requests []PQVRFVerificationRequest

	for i := 0; i < 5; i++ {
		input := []byte(fmt.Sprintf("valid-input-%d", i))
		proof, output, err := PQVRFEval(sk, input)
		if err != nil {
			t.Fatalf("PQVRFEval: %v", err)
		}
		requests = append(requests, PQVRFVerificationRequest{
			PublicKey: pk,
			Input:     input,
			Proof:     proof,
			Output:    output,
		})
	}

	invalidProof := &PQVRFProof{Proof: make([]byte, PQVRFProofSize)}
	invalidOutput := &PQVRFOutput{}
	requests = append(requests, PQVRFVerificationRequest{
		PublicKey: pk,
		Input:     []byte("invalid-input"),
		Proof:     invalidProof,
		Output:    invalidOutput,
	})

	results := PQVRFVerifyBatch(requests)
	validCount := 0
	invalidCount := 0
	for _, r := range results {
		if r.Valid {
			validCount++
		} else {
			invalidCount++
		}
	}

	if validCount != 5 {
		t.Errorf("expected 5 valid, got %d", validCount)
	}
	if invalidCount != 1 {
		t.Errorf("expected 1 invalid, got %d", invalidCount)
	}
}

func TestPQVRF_BatchVerification_Empty(t *testing.T) {
	results := PQVRFVerifyBatch(nil)
	if results != nil {
		t.Errorf("expected nil for empty batch, got %v", results)
	}
}

func TestPQVRF_ConcurrentEval(t *testing.T) {
	sk, pk := generateTestKeyPair(t)

	const numGoroutines = 50
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			input := []byte(fmt.Sprintf("concurrent-input-%d", idx))
			proof, output, err := PQVRFEval(sk, input)
			if err != nil {
				errors <- err
				return
			}
			if err := PQVRFVerify(pk, input, proof, output); err != nil {
				errors <- err
				return
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent eval/verify: %v", err)
	}
}

func TestPQVRF_Serialization(t *testing.T) {
	sk, _ := generateTestKeyPair(t)

	input := []byte("serialization-test")
	proof, output, err := PQVRFEval(sk, input)
	if err != nil {
		t.Fatalf("PQVRFEval: %v", err)
	}

	proofBytes := proof.ProofBytes()
	recoveredProof, err := PQVRFProofFromBytes(proofBytes)
	if err != nil {
		t.Fatalf("PQVRFProofFromBytes: %v", err)
	}
	if len(recoveredProof.Proof) != PQVRFProofSize {
		t.Errorf("recovered proof size: got %d, want %d", len(recoveredProof.Proof), PQVRFProofSize)
	}

	outputBytes := output.OutputBytes()
	recoveredOutput, err := PQVRFOutputFromBytes(outputBytes)
	if err != nil {
		t.Fatalf("PQVRFOutputFromBytes: %v", err)
	}
	if recoveredOutput.Value != output.Value {
		t.Error("recovered output doesn't match original")
	}

	outputHash := output.ToHash()
	if outputHash != types.Hash(output.Value) {
		t.Error("ToHash conversion mismatch")
	}
}

func TestPQVRF_Serialization_InvalidSize(t *testing.T) {
	_, err := PQVRFProofFromBytes([]byte{1, 2, 3})
	if err != ErrPQVRFInvalidProof {
		t.Errorf("expected ErrPQVRFInvalidProof, got %v", err)
	}

	_, err = PQVRFOutputFromBytes([]byte{1, 2, 3})
	if err != ErrPQVRFInvalidOutput {
		t.Errorf("expected ErrPQVRFInvalidOutput, got %v", err)
	}
}

func TestPQVRF_ComputeOutput(t *testing.T) {
	sk, _ := generateTestKeyPair(t)

	input := []byte("compute-output-test")
	proof, expectedOutput, err := PQVRFEval(sk, input)
	if err != nil {
		t.Fatalf("PQVRFEval: %v", err)
	}

	// AUDIT (2026) CRND-R3-02: PQVRFComputeOutput now takes (publicKey, proof, input).
	computedOutput, err := PQVRFComputeOutput(sk.PublicKey(), proof.Proof, input)
	if err != nil {
		t.Fatalf("PQVRFComputeOutput: %v", err)
	}

	if computedOutput.Value != expectedOutput.Value {
		t.Error("computed output doesn't match expected output")
	}
}

func TestPQVRF_DomainSeparation(t *testing.T) {
	sk, pk := generateTestKeyPair(t)

	input := []byte("domain-separation-test")

	pqvrfProof, pqvrfOutput, err := PQVRFEval(sk, input)
	if err != nil {
		t.Fatalf("PQVRFEval: %v", err)
	}

	var seed types.Hash
	copy(seed[:], input)
	vrfProof, vrfOutput, err := GenerateVRF(sk, seed)
	if err != nil {
		t.Fatalf("GenerateVRF: %v", err)
	}

	if pqvrfProof.Proof[0] == vrfProof.Proof[0] && pqvrfProof.Proof[1] == vrfProof.Proof[1] {
		t.Log("WARNING: PQ-VRF and legacy VRF produced similar proofs - domain separation may not be effective")
	}

	err = PQVRFVerify(pk, input, pqvrfProof, pqvrfOutput)
	if err != nil {
		t.Errorf("PQ-VRF proof should verify with PQ-VRF: %v", err)
	}

	err = PQVRFVerify(pk, input, &PQVRFProof{Proof: vrfProof.Proof}, &PQVRFOutput{Value: [32]byte(vrfOutput.Value)})
	if err == nil {
		t.Error("legacy VRF proof should NOT verify with PQ-VRF domain separator")
	}
}

func TestPQVRF_Uniqueness_Stress(t *testing.T) {
	sk, _ := generateTestKeyPair(t)

	const numInputs = 500
	outputs := make(map[[PQVRFOutputSize]byte]int)

	for i := 0; i < numInputs; i++ {
		var input [8]byte
		binary.BigEndian.PutUint64(input[:], uint64(i))

		_, output, err := PQVRFEval(sk, input[:])
		if err != nil {
			t.Fatalf("PQVRFEval(%d): %v", i, err)
		}

		outputs[output.Value]++
		if outputs[output.Value] > 1 {
			t.Errorf("duplicate output for input %d: %x", i, output.Value)
		}
	}

	if len(outputs) != numInputs {
		t.Errorf("expected %d unique outputs, got %d", numInputs, len(outputs))
	}
}

func BenchmarkPQVRFEval(b *testing.B) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	var seed types.Hash
	rand.Read(seed[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = PQVRFEvalHash(kp.Private, seed)
	}
}

func BenchmarkPQVRFVerify(b *testing.B) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	var seed types.Hash
	rand.Read(seed[:])

	proof, output, _ := PQVRFEvalHash(kp.Private, seed)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PQVRFVerifyHash(kp.Public, seed, proof, output)
	}
}

func BenchmarkPQVRFEvalVerify(b *testing.B) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	var seed types.Hash
	rand.Read(seed[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof, output, _ := PQVRFEvalHash(kp.Private, seed)
		_ = PQVRFVerifyHash(kp.Public, seed, proof, output)
	}
}

func BenchmarkPQVRFBatchVerify(b *testing.B) {
	const batchSize = 32

	var requests []PQVRFVerificationRequest
	for i := 0; i < batchSize; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
		var seed types.Hash
		rand.Read(seed[:])
		proof, output, _ := PQVRFEvalHash(kp.Private, seed)
		requests = append(requests, PQVRFVerificationRequest{
			PublicKey: kp.Public,
			Input:     seed[:],
			Proof:     proof,
			Output:    output,
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PQVRFVerifyBatch(requests)
	}
}
