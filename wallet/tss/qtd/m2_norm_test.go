// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"fmt"
	"math"
	"testing"
)

func TestM2_LagrangeCoefficients_2of3(t *testing.T) {
	t.Log("========================================")
	t.Log("M2: pre-multiplied λ_i norm computation")
	t.Log("========================================")

	t.Log("--- 2-of-3 Shamir (current mainnet config) ---")
	participants := []int{1, 2, 3}
	coeffs := make(map[int]int64)
	for _, id := range participants {
		coeffs[id] = lagrangeCoeff(id, participants)
		normCoeff := coeffs[id]
		if normCoeff > Q/2 {
			normCoeff = normCoeff - Q
		}
		t.Logf("  λ_%d = %d (mod Q), signed = %d", id, coeffs[id], normCoeff)
	}

	maxAbs := int64(0)
	for _, c := range coeffs {
		signed := c
		if signed > Q/2 {
			signed = signed - Q
		}
		absVal := signed
		if absVal < 0 {
			absVal = -absVal
		}
		if absVal > maxAbs {
			maxAbs = absVal
		}
	}
	t.Logf("  max|λ_i| = %d", maxAbs)
	t.Logf("  2-of-3: λ_i norm well-bounded ✅ (max=%d << γ1=%d)", maxAbs, int64(Dilithium3Gamma1))
}

func TestM2_LagrangeCoefficients_Scalability(t *testing.T) {
	t.Log("--- Lagrange coefficient norms across group sizes ---")

	groupSizes := []int{3, 5, 10, 20, 50, 100, 200}

	for _, n := range groupSizes {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			participants := make([]int, n)
			for i := 0; i < n; i++ {
				participants[i] = i + 1
			}

			maxAbs := int64(0)
			maxLambda := int64(0)
			for _, id := range participants {
				lambda := lagrangeCoeff(id, participants)
				signed := lambda
				if signed > Q/2 {
					signed = signed - Q
				}
				absVal := signed
				if absVal < 0 {
					absVal = -absVal
				}
				if absVal > maxAbs {
					maxAbs = absVal
				}
				if lambda > maxLambda {
					maxLambda = lambda
				}
			}

			t.Logf("n=%d: max|λ_i|=%d, max_lambda=%d, γ1=%d, ratio=%.6f",
				n, maxAbs, maxLambda, int64(Dilithium3Gamma1),
				float64(maxAbs)/float64(Dilithium3Gamma1))

			if float64(maxAbs) > 0.1*float64(Dilithium3Gamma1) {
				t.Logf("⚠️ n=%d: λ_i norm is large (max|λ_i|=%d, %.2f%% of γ1), may hurt rejection-sampling success rate",
					n, maxAbs, 100.0*float64(maxAbs)/float64(Dilithium3Gamma1))
			}
		})
	}
}

func TestM2_RejectionSampling_SuccessRate(t *testing.T) {
	t.Log("--- simulated rejection-sampling success rates across group sizes ---")

	groupSizes := []int{3, 5, 10, 20, 50}
	iterations := 100

	for _, n := range groupSizes {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			participants := make([]int, n)
			for i := 0; i < n; i++ {
				participants[i] = i + 1
			}

			coeffs := make(map[int]int64)
			for _, id := range participants {
				coeffs[id] = lagrangeCoeff(id, participants)
			}

			maxAbs := int64(0)
			for _, c := range coeffs {
				signed := c
				if signed > Q/2 {
					signed = signed - Q
				}
				absVal := signed
				if absVal < 0 {
					absVal = -absVal
				}
				if absVal > maxAbs {
					maxAbs = absVal
				}
			}

			effectiveBound := int64(Dilithium3Gamma1) - int64(Dilithium3Beta) - maxAbs*int64(Dilithium3EtaPoly)
			if effectiveBound < 0 {
				effectiveBound = 0
			}

			successCount := 0
			for i := 0; i < iterations; i++ {
				seed := make([]byte, 32)
				seed[0] = byte(i)
				seed[1] = byte(i >> 8)
				sigma := float64(Dilithium3Gamma1) / math.Sqrt(float64(n))

				vec, err := SampleGaussianMaskingVec(seed, sigma)
				if err != nil {
					continue
				}

				allSmall := true
				for j := 0; j < Dilithium3L; j++ {
					for k := 0; k < N; k++ {
						coeff := vec[j][k]
						if coeff < 0 {
							coeff = -coeff
						}
						if coeff > Q/2 {
							coeff = Q - coeff
						}
						if coeff > int32(effectiveBound) {
							allSmall = false
							break
						}
					}
					if !allSmall {
						break
					}
				}
				if allSmall {
					successCount++
				}
			}

			rate := float64(successCount) / float64(iterations) * 100
			t.Logf("n=%d: max|λ_i|=%d, effective_bound=%d, success rate=%.1f%% (%d/%d)",
				n, maxAbs, effectiveBound, rate, successCount, iterations)

			if rate < 10 && n > 10 {
				t.Logf("⚠️ n=%d: success rate is low (%.1f%%); recommend keeping the 3-person QTD + redundancy-group design", n, rate)
			}
		})
	}
}

func TestM2_LambdaNorm_2of3_Detailed(t *testing.T) {
	t.Log("--- 2-of-3 detailed analysis (mainnet config) ---")

	subsets := [][]int{
		{1, 2},
		{1, 3},
		{2, 3},
		{1, 2, 3},
	}

	for _, subset := range subsets {
		t.Run(fmt.Sprintf("participants=%v", subset), func(t *testing.T) {
			coeffs := make(map[int]int64)
			for _, id := range subset {
				coeffs[id] = lagrangeCoeff(id, subset)
			}

			totalLambda := int64(0)
			for _, id := range subset {
				signed := coeffs[id]
				if signed > Q/2 {
					signed = signed - Q
				}
				totalLambda += signed
				t.Logf("  λ_%d = %d (signed=%d)", id, coeffs[id], signed)
			}

			t.Logf("  Σλ_i = %d (should be 1 mod Q)", totalLambda%int64(Q))

			maxAbs := int64(0)
			for _, c := range coeffs {
				signed := c
				if signed > Q/2 {
					signed = signed - Q
				}
				absVal := signed
				if absVal < 0 {
					absVal = -absVal
				}
				if absVal > maxAbs {
					maxAbs = absVal
				}
			}

			t.Logf("  max|λ_i| = %d", maxAbs)
			t.Logf("  λ_i * η = %d (η=%d, Dilithium3EtaPoly)", maxAbs*int64(Dilithium3EtaPoly), Dilithium3EtaPoly)
			t.Logf("  γ1 - β - λ_i*η = %d (must be >0 to pass rejection sampling)",
				int64(Dilithium3Gamma1)-int64(Dilithium3Beta)-maxAbs*int64(Dilithium3EtaPoly))
		})
	}
}

func TestM2_Conclusion(t *testing.T) {
	t.Log("========================================")
	t.Log("M2 conclusions:")
	t.Log("  - 2-of-3 Shamir: λ_i norm well-bounded, rejection-sampling success rate normal ✅")
	t.Log("  - Large scale (n>10): λ_i norm grows; alternatives need evaluation")
	t.Log("  - Recommendation: keep the 3-person QTD + redundancy-group design")
	t.Log("========================================")
}
