// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"context"
	"testing"
)

func TestMPCExecutorBoundaryUsesOpaqueHandles(t *testing.T) {
	var _ MPCExecutor = (*testMPCExecutor)(nil)
}

type testMPCExecutor struct{}

func (*testMPCExecutor) OpenHighBits(
	context.Context,
	MPCSession,
	PreprocessingSecretHandle,
) (MPCPublicHighBits, MPCEvidence, error) {
	return MPCPublicHighBits{}, MPCEvidence{}, nil
}

func (*testMPCExecutor) CheckNorm(
	context.Context,
	MPCSession,
	PreprocessingSecretHandle,
	int32,
) (bool, MPCEvidence, error) {
	return true, MPCEvidence{}, nil
}

func (*testMPCExecutor) MakeHints(
	context.Context,
	MPCSession,
	PreprocessingSecretHandle,
) (HintVector, MPCEvidence, error) {
	return HintVector{}, MPCEvidence{}, nil
}
