// Quantaureum Node source, version 1.0.0.
package quantum

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	mimc_native "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
)

func BenchmarkZKP_CircuitSetup(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		prover := NewZKProver()
		// R30-P4 FIX: Allow insecure setup for benchmark testing.
		prover.SetAllowInsecureSetup(true)
		prover.RegisterCircuit("bench-circuit", "Benchmark Circuit")
	}
}

func BenchmarkZKP_ProofGeneration(b *testing.B) {
	prover := NewZKProver()
	// R30-P4 FIX: Allow insecure setup for benchmark testing.
	prover.SetAllowInsecureSetup(true)
	if err := prover.RegisterCircuit("bench-circuit", "Benchmark Circuit"); err != nil {
		b.Fatalf("RegisterCircuit: %v", err)
	}

	// L12-028 FIX: Use the same domain-reduction + FillBytes pattern as
	// production computeNativeMiMC() to ensure benchmark reflects real performance.
	privateInput := big.NewInt(42)
	h := mimc_native.NewMiMC()
	var buf [32]byte
	reduced := new(big.Int).Mod(privateInput, ecc.BLS12_381.ScalarField())
	reduced.FillBytes(buf[:])
	h.Write(buf[:])
	publicInput := new(big.Int).SetBytes(h.Sum(nil))
	h.Reset()
	// FIX: Zero sensitive intermediate buffers after use.
	clear(buf[:])
	reduced.SetInt64(0)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := prover.GenerateProof("bench-circuit", privateInput, publicInput)
		if err != nil {
			b.Fatalf("GenerateProof: %v", err)
		}
	}
}

func BenchmarkZKP_ProofVerification(b *testing.B) {
	prover := NewZKProver()
	// R30-P4 FIX: Allow insecure setup for benchmark testing.
	prover.SetAllowInsecureSetup(true)
	if err := prover.RegisterCircuit("bench-circuit", "Benchmark Circuit"); err != nil {
		b.Fatalf("RegisterCircuit: %v", err)
	}

	// L12-028 FIX: Consistent with computeNativeMiMC production code.
	privateInput := big.NewInt(42)
	h := mimc_native.NewMiMC()
	var buf [32]byte
	reduced := new(big.Int).Mod(privateInput, ecc.BLS12_381.ScalarField())
	reduced.FillBytes(buf[:])
	h.Write(buf[:])
	publicInput := new(big.Int).SetBytes(h.Sum(nil))
	h.Reset()
	// FIX: Zero sensitive intermediate buffers after use.
	clear(buf[:])
	reduced.SetInt64(0)

	proof, err := prover.GenerateProof("bench-circuit", privateInput, publicInput)
	if err != nil {
		b.Fatalf("GenerateProof: %v", err)
	}

	circuit, _ := prover.GetCircuit("bench-circuit")
	verifier := NewZKVerifier()
	verifier.RegisterCircuit(circuit)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ok, err := verifier.VerifyProof(proof)
		if err != nil {
			b.Fatalf("VerifyProof: %v", err)
		}
		if !ok {
			b.Fatal("proof verification failed")
		}
	}
}

func BenchmarkZKP_EndToEnd(b *testing.B) {
	prover := NewZKProver()
	// R30-P4 FIX: Allow insecure setup for benchmark testing.
	prover.SetAllowInsecureSetup(true)
	if err := prover.RegisterCircuit("bench-e2e", "E2E Benchmark Circuit"); err != nil {
		b.Fatalf("RegisterCircuit: %v", err)
	}

	circuit, _ := prover.GetCircuit("bench-e2e")
	verifier := NewZKVerifier()
	verifier.RegisterCircuit(circuit)

	privateInput := big.NewInt(12345)
	h := mimc_native.NewMiMC()
	var buf [32]byte
	reduced := new(big.Int).Mod(privateInput, ecc.BLS12_381.ScalarField())
	reduced.FillBytes(buf[:])
	h.Write(buf[:])
	publicInput := new(big.Int).SetBytes(h.Sum(nil))
	h.Reset()
	// FIX: Zero sensitive intermediate buffers after use.
	clear(buf[:])
	reduced.SetInt64(0)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		proof, err := prover.GenerateProof("bench-e2e", privateInput, publicInput)
		if err != nil {
			b.Fatalf("GenerateProof: %v", err)
		}
		ok, err := verifier.VerifyProof(proof)
		if err != nil {
			b.Fatalf("VerifyProof: %v", err)
		}
		if !ok {
			b.Fatal("proof verification failed")
		}
	}
}
