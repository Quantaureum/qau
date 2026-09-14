// Quantaureum Node source, version 1.0.0.
package tss

import (
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

func BenchmarkQTD_DKG_2of3(b *testing.B) {
	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		manager, _ := NewTSSManager(config)
		b.StartTimer()
		_, err := manager.GenerateKeyShares()
		if err != nil {
			b.Fatalf("DKG failed: %v", err)
		}
	}
}

func BenchmarkQTD_DKG_3of5(b *testing.B) {
	config := TSSConfig{Threshold: 3, TotalShares: 5, SecurityLevel: 256}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		manager, _ := NewTSSManager(config)
		b.StartTimer()
		_, err := manager.GenerateKeyShares()
		if err != nil {
			b.Fatalf("DKG failed: %v", err)
		}
	}
}

func BenchmarkQTD_Signing_2of3(b *testing.B) {
	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()
	message := []byte("benchmark-2of3-signing-test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.SignWithRetry(message, []int{1, 2, 3})
		if err != nil {
			b.Fatalf("signing failed: %v", err)
		}
	}
}

func BenchmarkQTD_Signing_3of5(b *testing.B) {
	config := TSSConfig{Threshold: 3, TotalShares: 5, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()
	message := []byte("benchmark-3of5-signing-test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.SignWithRetry(message, []int{1, 2, 3, 4, 5})
		if err != nil {
			b.Fatalf("signing failed: %v", err)
		}
	}
}

func BenchmarkQTD_Verification_Standard(b *testing.B) {
	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()
	message := []byte("benchmark-verification-test")
	sig, _ := manager.SignWithRetry(message, []int{1, 2, 3})

	groupPK := manager.GroupPublicKey()
	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		switch len(sig) {
		case 3293:
			mode3.Verify(&pk, message, sig)
		case 4064:
			qtd.CheckGMQTDFullSignature(&pk, message, sig)
		}
	}
}

func BenchmarkQTD_FullProtocol_2of3(b *testing.B) {
	message := []byte("benchmark-full-protocol")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
		manager, _ := NewTSSManager(config)
		manager.GenerateKeyShares()
		b.StartTimer()

		sig, err := manager.SignWithRetry(message, []int{1, 2, 3})
		if err != nil {
			b.Fatalf("signing failed: %v", err)
		}
		if len(sig) != 3293 && len(sig) != 4064 {
			b.Fatalf("unexpected sig size: %d", len(sig))
		}
	}
}

func TestPhase13_SigningLatencyBenchmark(t *testing.T) {
	t.Log("=== Phase 1.3: QTD Signing Latency Benchmark ===")

	latencyTests := []struct {
		name      string
		threshold int
		total     int
		iters     int
	}{
		{"2-of-3 (mainnet config)", 2, 3, 10},
		{"3-of-5", 3, 5, 5},
	}

	for _, lt := range latencyTests {
		t.Run(lt.name, func(t *testing.T) {
			config := TSSConfig{Threshold: lt.threshold, TotalShares: lt.total, SecurityLevel: 256}

			var dkgTotal time.Duration
			var signTotal time.Duration
			var verifyTotal time.Duration

			for i := 0; i < lt.iters; i++ {
				manager, _ := NewTSSManager(config)

				start := time.Now()
				manager.GenerateKeyShares()
				dkgTotal += time.Since(start)

				message := []byte("latency-benchmark-test")

				start = time.Now()
				sig, err := manager.SignWithRetry(message, []int{1, 2})
				if err != nil && lt.threshold == 2 {
					sig, err = manager.SignWithRetry(message, []int{1, 2, 3})
				}
				if lt.threshold == 3 {
					sig, err = manager.SignWithRetry(message, []int{1, 2, 3, 4, 5})
				}
				if err != nil {
					t.Fatalf("signing failed: %v", err)
				}
				signTotal += time.Since(start)

				groupPK := manager.GroupPublicKey()
				var pk mode3.PublicKey
				pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

				start = time.Now()
				switch len(sig) {
				case 3293:
					if !mode3.Verify(&pk, message, sig) {
						t.Fatal("verification failed")
					}
				case 4064:
					if !qtd.CheckGMQTDFullSignature(&pk, message, sig) {
						t.Fatal("verification failed")
					}
				}
				verifyTotal += time.Since(start)
			}

			t.Logf("DKG:        avg=%v  total=%v (%d iters)", dkgTotal/time.Duration(lt.iters), dkgTotal, lt.iters)
			t.Logf("Signing:    avg=%v  total=%v (%d iters)", signTotal/time.Duration(lt.iters), signTotal, lt.iters)
			t.Logf("Verify:     avg=%v  total=%v (%d iters)", verifyTotal/time.Duration(lt.iters), verifyTotal, lt.iters)

			avgSign := signTotal / time.Duration(lt.iters)
			if avgSign > 5*time.Second {
				t.Errorf("signing latency too high: %v (target <5s)", avgSign)
			}
		})
	}
}
