// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// R5-07 (2026-10-21 fifth-round audit): every other variable-length field of a
// UserOperation is size-capped while it is decoded, but the signature was only
// capped afterwards by Validate(). A caller that decodes a peer- or RPC-supplied
// operation therefore retains an oversized payload (up to the 16MB per-field
// wire limit) before any policy check runs — and any code path that handles the
// decoded operation without calling Validate() keeps it indefinitely. The
// decoder now enforces MaxUserOpSignatureSize at the boundary, the same rule the
// bundle-count cap follows in UnmarshalUserOpBundle.

func r5UserOpWithSignature(sig []byte) *UserOperation {
	return &UserOperation{
		Sender:               types.Address{0x11},
		Nonce:                1,
		CallGasLimit:         21000,
		VerificationGasLimit: 100000,
		PreVerificationGas:   21000,
		MaxFeePerGas:         big.NewInt(2_000_000_000),
		MaxPriorityFeePerGas: big.NewInt(1_500_000_000),
		Signature:            sig,
	}
}

func TestR5_07_UnmarshalCapsSignatureAtDecodeTime(t *testing.T) {
	oversized := make([]byte, MaxUserOpSignatureSize+1)
	for i := range oversized {
		oversized[i] = byte(i)
	}

	data, err := MarshalUserOperation(r5UserOpWithSignature(oversized))
	if err != nil {
		t.Fatalf("MarshalUserOperation: %v", err)
	}

	uo, err := UnmarshalUserOperation(data)
	if err == nil {
		t.Fatalf("decoder accepted a %d byte signature (limit %d) and returned it for processing",
			len(uo.Signature), MaxUserOpSignatureSize)
	}
	if uo != nil {
		t.Fatalf("decoder returned an operation alongside the error: %v", uo)
	}

	// The cap must not clip legitimate signatures.
	exact := make([]byte, MaxUserOpSignatureSize)
	data, err = MarshalUserOperation(r5UserOpWithSignature(exact))
	if err != nil {
		t.Fatalf("MarshalUserOperation(exact): %v", err)
	}
	uo, err = UnmarshalUserOperation(data)
	if err != nil {
		t.Fatalf("signature of exactly the limit must decode: %v", err)
	}
	if len(uo.Signature) != MaxUserOpSignatureSize {
		t.Fatalf("signature round-trip = %d bytes, want %d", len(uo.Signature), MaxUserOpSignatureSize)
	}
	if err := uo.Validate(); err != nil {
		t.Fatalf("decoded operation should validate: %v", err)
	}
}
