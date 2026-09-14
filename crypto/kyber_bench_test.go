// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"testing"
)

func BenchmarkKyberKeyGeneration(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := GenerateKyberKeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKyberEncapsulate(b *testing.B) {
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	senderKP, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := senderKP.Private.Exchange(kp.Public)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKyberDecapsulate(b *testing.B) {
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	senderKP, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	_, ciphertext, err := senderKP.Private.Exchange(kp.Public)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kp.Private.Decapsulate(ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKyberFullKeyExchange(b *testing.B) {
	recipientKP, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		senderKP, err := GenerateKyberKeyPair()
		if err != nil {
			b.Fatal(err)
		}
		_, ciphertext, err := senderKP.Private.Exchange(recipientKP.Public)
		if err != nil {
			b.Fatal(err)
		}
		_, err = recipientKP.Private.Decapsulate(ciphertext)
		if err != nil {
			b.Fatal(err)
		}
		senderKP.Private.Zeroize()
	}
}

func BenchmarkKyberPublicKeySerialization(b *testing.B) {
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kp.Public.Bytes()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKyberPrivateKeySerialization(b *testing.B) {
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kp.Private.Bytes()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKyberPublicKeyDeserialization(b *testing.B) {
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	pubBytes, err := kp.Public.Bytes()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := KyberPublicKeyFromBytes(pubBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKyberParallelKeyGeneration(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := GenerateKyberKeyPair()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkKyberParallelEncapsulate(b *testing.B) {
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		senderKP, _ := GenerateKyberKeyPair()
		for pb.Next() {
			_, _, err := senderKP.Private.Exchange(kp.Public)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
