// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"testing"
)

func TestStandardParameters(t *testing.T) {
	parameters := StandardParameters()
	if err := parameters.Validate(); err != nil {
		t.Fatalf("standard parameters rejected: %v", err)
	}

	if parameters.N != 256 || parameters.Q != 8380417 {
		t.Fatalf("ring parameters = N %d Q %d", parameters.N, parameters.Q)
	}
	if parameters.K != 6 || parameters.L != 5 {
		t.Fatalf("module dimensions = K %d L %d", parameters.K, parameters.L)
	}
	if parameters.Eta != 4 || parameters.Tau != 49 || parameters.Beta != 196 {
		t.Fatalf("secret bounds = eta %d tau %d beta %d", parameters.Eta, parameters.Tau, parameters.Beta)
	}
	if parameters.Gamma1 != 1<<19 || parameters.Gamma2 != 261888 {
		t.Fatalf("rejection bounds = gamma1 %d gamma2 %d", parameters.Gamma1, parameters.Gamma2)
	}
	if parameters.Omega != 55 || parameters.D != 13 {
		t.Fatalf("encoding bounds = omega %d d %d", parameters.Omega, parameters.D)
	}
	if parameters.PublicKeySize != 1952 || parameters.PrivateKeySize != 4032 || parameters.SignatureSize != 3309 {
		t.Fatalf(
			"encoded sizes = public %d private %d signature %d",
			parameters.PublicKeySize,
			parameters.PrivateKeySize,
			parameters.SignatureSize,
		)
	}
}

func TestStandardParametersRejectMutation(t *testing.T) {
	parameters := StandardParameters()
	parameters.Threshold = 3
	if err := parameters.Validate(); !errors.Is(err, ErrInvalidParameters) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidParameters)
	}
}

func TestValidateEncodedSizes(t *testing.T) {
	parameters := StandardParameters()
	if err := ValidatePublicKeyEncoding(make([]byte, parameters.PublicKeySize)); err != nil {
		t.Fatalf("valid public key length rejected: %v", err)
	}
	if err := ValidateSignatureEncoding(make([]byte, parameters.SignatureSize)); err != nil {
		t.Fatalf("valid signature length rejected: %v", err)
	}
	if err := ValidatePublicKeyEncoding(make([]byte, parameters.PublicKeySize-1)); !errors.Is(err, ErrInvalidEncodingSize) {
		t.Fatalf("public key length error = %v, want %v", err, ErrInvalidEncodingSize)
	}
	if err := ValidateSignatureEncoding(make([]byte, parameters.SignatureSize+1)); !errors.Is(err, ErrInvalidEncodingSize) {
		t.Fatalf("signature length error = %v, want %v", err, ErrInvalidEncodingSize)
	}
}
