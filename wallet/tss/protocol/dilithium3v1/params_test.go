// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func TestParametersMatchCIRCLMode3(t *testing.T) {
	parameters := StandardParameters()
	want := Parameters{
		N: 256, Q: 8380417, K: 6, L: 5, Eta: 4, Tau: 49, Beta: 196,
		Gamma1: 1 << 19, Gamma2: 261888, Omega: 55, D: 13,
		CTildeSize: 32, TRSize: 32,
		PublicKeySize: mode3.PublicKeySize, PrivateKeySize: mode3.PrivateKeySize,
		SignatureSize: mode3.SignatureSize, Participants: 6, Threshold: 4, MaxCorrupt: 2,
	}
	if parameters != want {
		t.Fatalf("StandardParameters() = %+v, want %+v", parameters, want)
	}
	if err := parameters.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}
	parameters.SignatureSize++
	if !errors.Is(parameters.Validate(), ErrInvalidParameters) {
		t.Fatal("modified parameters were accepted")
	}
}

func TestParametersRejectWrongEncodedSizes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		call func([]byte) error
	}{
		{name: "public key", data: make([]byte, mode3.PublicKeySize-1), call: ValidatePublicKeyEncoding},
		{name: "private key", data: make([]byte, mode3.PrivateKeySize+1), call: ValidatePrivateKeyEncoding},
		{name: "signature", data: make([]byte, mode3.SignatureSize-1), call: ValidateSignatureEncoding},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !errors.Is(test.call(test.data), ErrInvalidEncodingSize) {
				t.Fatalf("wrong-sized %s was accepted", test.name)
			}
		})
	}
}
