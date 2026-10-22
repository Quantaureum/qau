// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"encoding/json"
	"testing"
)

// R5-05 (2026-10-21 fifth-round audit): account abstraction is registered on
// the RPC surface but no component consumes Bundler.BundleChannel(), so an
// accepted user operation was never bundled and never produced a receipt —
// the node returned a success hash for work it could not do. eth_sendUserOperation
// and qau_sendUserOperation now refuse with an explicit "not live" error.
// These tests pin that behaviour for BOTH registered names, because the two
// names are what makes the handler reachable by standard ERC-4337 clients.

// A complete ERC-4337 shaped operation: every field parseUserOperation reads,
// so nothing in the payload itself would have made the old path reject it.
const r5SendUserOpParams = `[{
	"sender": "0x0000000000000000000000000000000000000111",
	"nonce": "0x0",
	"initCode": "0x",
	"callData": "0xdeadbeef",
	"callGasLimit": "0x5208",
	"verificationGasLimit": "0xc350",
	"preVerificationGas": "0x5208",
	"maxFeePerGas": "0x77359400",
	"maxPriorityFeePerGas": "0x59682f00",
	"paymasterAndData": "0x",
	"signature": "0xdeadbeef"
}]`

// The mock pool used by newTestAPI accepts every submission (its
// AddUserOperation returns nil), so a refusal here can only come from the
// handler's own gate — the test would fail if the gate were removed.
func TestR5_05_SendUserOperationRefusedUnderBothNames(t *testing.T) {
	api := newTestAPI()
	srv := NewServer(nil)
	api.RegisterHandlers(srv)

	for _, method := range []string{"eth_sendUserOperation", "qau_sendUserOperation"} {
		resp := srv.handleRequest(ctx(), &Request{
			JSONRPC: JSONRPCVersion,
			Method:  method,
			Params:  json.RawMessage(r5SendUserOpParams),
			ID:      1,
		})
		if resp.Error == nil {
			t.Fatalf("%s: submission accepted while AA is not live (result=%v)", method, resp.Result)
		}
		if resp.Error.Code != ErrCodeInternal {
			t.Errorf("%s: got code %d, want %d (ErrCodeInternal)", method, resp.Error.Code, ErrCodeInternal)
		}
		if resp.Error.Message != ErrUserOpsNotLiveRPC {
			t.Errorf("%s: got message %q, want %q", method, resp.Error.Message, ErrUserOpsNotLiveRPC)
		}
		if resp.Result != nil {
			t.Errorf("%s: a refusal must not also return an operation hash, got %v", method, resp.Result)
		}
	}
}

// The refusal is unconditional, so it does not depend on the payload being
// well-formed or on a transaction pool being wired. Malformed and absent
// parameters get the same "not live" answer rather than a parse error that
// implies the node would have accepted a better-formed operation.
func TestR5_05_SendUserOperationRefusesBeforeParsing(t *testing.T) {
	api := newTestAPI()

	for name, params := range map[string]json.RawMessage{
		"nil params":    nil,
		"empty array":   json.RawMessage(`[]`),
		"garbage":       json.RawMessage(`"not an operation"`),
		"incomplete op": json.RawMessage(`[{"sender":"0xdeadbeef"}]`),
		"complete op":   json.RawMessage(r5SendUserOpParams),
	} {
		result, rpcErr := api.SendUserOperation(ctx(), params)
		if rpcErr == nil {
			t.Fatalf("%s: accepted (result=%v)", name, result)
		}
		if rpcErr.Message != ErrUserOpsNotLiveRPC {
			t.Errorf("%s: got message %q, want %q", name, rpcErr.Message, ErrUserOpsNotLiveRPC)
		}
		if result != nil {
			t.Errorf("%s: got result %v, want nil", name, result)
		}
	}
}

// A node started without a transaction pool must still give the same answer,
// not "transaction pool not available" — the reason the operation is refused
// is that AA is not live, and that has nothing to do with pool wiring.
func TestR5_05_SendUserOperationRefusesWithoutTxPool(t *testing.T) {
	api := newTestAPI()
	api.txPool = nil

	result, rpcErr := api.SendUserOperation(ctx(), json.RawMessage(r5SendUserOpParams))
	if rpcErr == nil {
		t.Fatalf("accepted without a transaction pool (result=%v)", result)
	}
	if rpcErr.Message != ErrUserOpsNotLiveRPC {
		t.Errorf("got message %q, want %q", rpcErr.Message, ErrUserOpsNotLiveRPC)
	}
}
