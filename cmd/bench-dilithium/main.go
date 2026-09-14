// Quantaureum Node source, version 1.0.0.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
)

func main() {
	fmt.Println("Dilithium3 Key Operations Performance Test on ARM64")
	fmt.Println("====================================================")

	pk, sk, _ := mode3.GenerateKey(rand.Reader)
	_ = sk

	pkBytes, _ := pk.MarshalBinary()
	fmt.Printf("PublicKey bytes: %d\n", len(pkBytes))

	start := time.Now()
	for i := 0; i < 5; i++ {
		t1 := time.Now()
		_, err := crypto.PublicKeyFromBytes(pkBytes)
		t2 := time.Now()
		if err != nil {
			fmt.Printf("PublicKeyFromBytes #%d: ERROR %v\n", i+1, err)
		} else {
			fmt.Printf("PublicKeyFromBytes #%d: %v\n", i+1, t2.Sub(t1))
		}
	}
	totalDuration := time.Since(start)
	fmt.Printf("\nTotal for 5 PublicKeyFromBytes: %v\n", totalDuration)

	skBytes, _ := sk.MarshalBinary()
	fmt.Printf("SecretKey bytes: %d\n", len(skBytes))
	fmt.Printf("SecretKey hex length: %d\n", len(hex.EncodeToString(skBytes)))

	start = time.Now()
	_, err := crypto.PrivateKeyFromBytes(skBytes)
	fmt.Printf("PrivateKeyFromBytes: %v (err=%v)\n", time.Since(start), err)
}
