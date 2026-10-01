// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// TestMPCExecutorBoundaryUsesOpaqueHandles pins the Task 8 Step 2 contract:
// the executor is satisfied through opaque handles, and no shared result type
// carries a secret polynomial, share container, or local handle.
func TestMPCExecutorBoundaryUsesOpaqueHandles(t *testing.T) {
	var _ MPCExecutor = (*testMPCExecutor)(nil)

	secretTypes := []reflect.Type{
		reflect.TypeOf(LocalShare{}),
		reflect.TypeOf(RSSComponent{}),
		reflect.TypeOf(Poly{}),
		reflect.TypeOf(VectorL{}),
		reflect.TypeOf(VectorK{}),
		reflect.TypeOf(SecretHandle{}),
	}
	assertNoSecretFields(t, MPCSession{}, secretTypes...)
	assertNoSecretFields(t, PublicHighBits{}, secretTypes...)
	assertNoSecretFields(t, Evidence{}, secretTypes...)
	assertNoSecretFields(t, CoordinatorPreprocessingView{}, secretTypes...)
}

func assertNoSecretFields(t *testing.T, value any, forbidden ...reflect.Type) {
	t.Helper()
	valueType := reflect.TypeOf(value)
	for index := 0; index < valueType.NumField(); index++ {
		field := valueType.Field(index)
		for _, forbiddenType := range forbidden {
			if field.Type == forbiddenType {
				t.Fatalf("%s exposes secret field %s of type %s", valueType.Name(), field.Name, field.Type)
			}
		}
	}
}

// TestMPCEncodePublicHighBitsMatchesReference requires the public w1 encoding
// to reproduce the local mode3 reference bit-exactly, including zero and Q-1
// boundary coefficients.
func TestMPCEncodePublicHighBitsMatchesReference(t *testing.T) {
	var high VectorK
	for row := 0; row < K; row++ {
		var polynomial Poly
		for index := 0; index < N; index++ {
			switch index % 4 {
			case 0:
				polynomial[index] = Coefficient((index * 32749) % Q)
			case 1:
				polynomial[index] = 0
			case 2:
				polynomial[index] = Q - 1
			case 3:
				polynomial[index] = Coefficient((index * 523776) % Q)
			}
		}
		high[row] = HighBits(polynomial)
	}

	encoded, err := EncodePublicHighBits(high)
	if err != nil {
		t.Fatalf("EncodePublicHighBits(): %v", err)
	}
	for row := 0; row < K; row++ {
		decoded, err := DecodeHighBits(encoded.Encoded[row][:])
		if err != nil {
			t.Fatalf("DecodeHighBits(row %d): %v", row, err)
		}
		for index := 0; index < N; index++ {
			if Coefficient(decoded[index]) != high[row][index] {
				t.Fatalf("row %d coefficient %d = %d, want %d", row, index, decoded[index], high[row][index])
			}
		}
	}

	var outOfRange VectorK
	outOfRange[0][0] = Coefficient(highBitsMask + 1)
	if _, err := EncodePublicHighBits(outOfRange); !errors.Is(err, ErrInvalidHighBits) {
		t.Fatalf("out-of-range error = %v, want %v", err, ErrInvalidHighBits)
	}

	var negative VectorK
	negative[1][5] = -1
	if _, err := EncodePublicHighBits(negative); !errors.Is(err, ErrInvalidHighBits) {
		t.Fatalf("negative error = %v, want %v", err, ErrInvalidHighBits)
	}
}

type testMPCExecutor struct{}

func (*testMPCExecutor) OpenHighBits(
	context.Context,
	MPCSession,
	SecretHandle,
) (PublicHighBits, Evidence, error) {
	return PublicHighBits{}, Evidence{}, nil
}

func (*testMPCExecutor) MultiplyPublicChallenge(
	context.Context,
	MPCSession,
	SecretHandle,
	Challenge,
) (SecretHandle, Evidence, error) {
	return SecretHandle{}, Evidence{}, nil
}

func (*testMPCExecutor) CheckNorm(
	context.Context,
	MPCSession,
	SecretHandle,
	int32,
) (bool, Evidence, error) {
	return false, Evidence{}, nil
}

func (*testMPCExecutor) MakeHints(
	context.Context,
	MPCSession,
	SecretHandle,
) (HintVector, Evidence, error) {
	return HintVector{}, Evidence{}, nil
}

func (*testMPCExecutor) Burn(MPCSession, SecretHandle) error {
	return nil
}
