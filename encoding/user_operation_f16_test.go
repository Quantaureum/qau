// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func f16TestUserOp() *UserOperation {
	return &UserOperation{
		Sender:               types.Address{0x11},
		Nonce:                7,
		CallData:             []byte{0x01, 0x02},
		CallGasLimit:         21000,
		VerificationGasLimit: 100000,
		PreVerificationGas:   21000,
		MaxFeePerGas:         big.NewInt(2_000_000_000),
		MaxPriorityFeePerGas: big.NewInt(1_500_000_000),
		Signature:            []byte{0xde, 0xad},
	}
}

// F-16: the user operation hash must cover the whole operation. Previously it
// was the trailing 32 bytes of the protobuf stream, so operations differing
// only in sender/nonce/calldata hashed identically.
func TestUserOperation_Hash_F16_CoversOperation(t *testing.T) {
	entryPoint := types.Address{0xee}
	const chainID = 1668

	base := f16TestUserOp()
	baseHash := base.Hash(entryPoint, chainID)
	if baseHash == (types.Hash{}) {
		t.Fatal("user operation hash must not be zero")
	}
	if again := base.Hash(entryPoint, chainID); again != baseHash {
		t.Fatal("user operation hash must be deterministic")
	}

	mutations := []struct {
		name   string
		mutate func(*UserOperation)
	}{
		{name: "sender", mutate: func(u *UserOperation) { u.Sender = types.Address{0x22} }},
		{name: "nonce", mutate: func(u *UserOperation) { u.Nonce++ }},
		{name: "callData", mutate: func(u *UserOperation) { u.CallData = []byte{0x01, 0x03} }},
		{name: "initCode", mutate: func(u *UserOperation) { u.InitCode = []byte{0x63} }},
		{name: "callGasLimit", mutate: func(u *UserOperation) { u.CallGasLimit++ }},
		{name: "verificationGasLimit", mutate: func(u *UserOperation) { u.VerificationGasLimit++ }},
		{name: "preVerificationGas", mutate: func(u *UserOperation) { u.PreVerificationGas++ }},
		{name: "maxFeePerGas", mutate: func(u *UserOperation) { u.MaxFeePerGas = big.NewInt(3_000_000_000) }},
		{name: "maxPriorityFeePerGas", mutate: func(u *UserOperation) { u.MaxPriorityFeePerGas = big.NewInt(1_600_000_000) }},
		{name: "paymaster", mutate: func(u *UserOperation) {
			pm := types.Address{0x33}
			u.Paymaster = &pm
		}},
		{name: "paymasterData", mutate: func(u *UserOperation) {
			pm := types.Address{0x33}
			u.Paymaster = &pm
			u.PaymasterData = []byte{0x99}
		}},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			op := f16TestUserOp()
			// Paymaster-dependent mutations must start from a paymaster op so
			// the mutation itself is the only difference.
			if m.name == "paymasterData" {
				pm := types.Address{0x33}
				op.Paymaster = &pm
			}
			before := op.Hash(entryPoint, chainID)
			m.mutate(op)
			if got := op.Hash(entryPoint, chainID); got == before {
				t.Fatalf("hash did not change when %s changed", m.name)
			}
		})
	}

	if base.Hash(types.Address{0xff}, chainID) == baseHash {
		t.Fatal("hash did not change when entry point changed")
	}
	if base.Hash(entryPoint, chainID+1) == baseHash {
		t.Fatal("hash did not change when chain ID changed")
	}
}
