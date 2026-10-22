// Quantaureum Node source, version 1.0.0.
package lightclient

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/quantaureum/qau/rpc"
	"github.com/quantaureum/qau/types"
)

// R6-02/R6-05 RPC-surface contract for the qau_light_* state-proof methods:
//
//   - a prover failure is reported as "this node could not produce a proof",
//     never as "state not found" (which is a claim about chain state that only a
//     verified exclusion proof may make);
//   - the response carries the proof material so the caller can re-verify it
//     offline (the AccountProof/Proof fields used to be declared and left empty);
//   - a malformed storage key is rejected rather than skipped, because a skipped
//     key would come back as a proof over a set the caller never asked about.

func hashHex(h types.Hash) string { return "0x" + hex.EncodeToString(h[:]) }

func TestR6_02_LightAPIReportsProofFailuresAsProofFailures(t *testing.T) {
	addr := types.Address{0xa1, 0xb2}
	params, err := json.Marshal(map[string]any{"address": formatHexAddress(addr)})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	// No state backend at all.
	api := NewLightClientAPI(nil, NewSPVProver(nil, nil))
	result, rpcErr := api.GetStateProof(context.Background(), params)
	if result != nil {
		t.Fatalf("result = %v, want nil on a prover failure", result)
	}
	if rpcErr == nil {
		t.Fatal("the handler swallowed the prover failure")
	}
	if rpcErr.Code == rpc.ErrCodeNotFound {
		t.Fatalf("code = %d (not found): a light client reading this concludes the account is absent from the chain, which only a verified exclusion proof may claim", rpcErr.Code)
	}
	if rpcErr.Code != rpc.ErrCodeInternal || rpcErr.Message != "state proof unavailable" {
		t.Fatalf("error = (%d, %q), want (-32603, \"state proof unavailable\")", rpcErr.Code, rpcErr.Message)
	}
	if data, ok := rpcErr.Data.(string); !ok || data == "" {
		t.Fatalf("data = %#v, want the prover's explanation", rpcErr.Data)
	}
}

func TestR6_05_LightAPIRefusesStorageKeysExplicitly(t *testing.T) {
	sdb, _ := newProvedStateDB(t)
	addr := types.Address{0xa1, 0xb2}
	slot := types.Hash{0x10, 0x20}
	api := NewLightClientAPI(nil, NewSPVProver(nil, sdb))

	params, err := json.Marshal(map[string]any{
		"address":     formatHexAddress(addr),
		"storageKeys": []string{hashHex(slot)},
	})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	result, rpcErr := api.GetStateProof(context.Background(), params)
	if result != nil {
		t.Fatalf("result = %v, want nil: no state-root-bound storage proof exists", result)
	}
	if rpcErr == nil || rpcErr.Code != rpc.ErrCodeInternal {
		t.Fatalf("error = %+v, want an internal proof-unavailable failure", rpcErr)
	}
	data, _ := rpcErr.Data.(string)
	if !strings.Contains(data, "storage") || !strings.Contains(data, "Verkle state trie") {
		t.Fatalf("data = %q, want it to name the storage slot gap and its cause", data)
	}

	// The batch method must not degrade to "states not found" either.
	batch, err := json.Marshal(map[string]any{
		"addresses":   []string{formatHexAddress(addr)},
		"storageKeys": map[string][]string{formatHexAddress(addr): {hashHex(slot)}},
	})
	if err != nil {
		t.Fatalf("marshal batch params: %v", err)
	}
	result, rpcErr = api.GetMultiStateProof(context.Background(), batch)
	if result != nil {
		t.Fatalf("GetMultiStateProof result = %v, want nil", result)
	}
	if rpcErr == nil || rpcErr.Code == rpc.ErrCodeNotFound {
		t.Fatalf("GetMultiStateProof error = %+v, want a proof failure instead of \"states not found\"", rpcErr)
	}

	// A malformed storage key is rejected, not silently dropped from the set.
	bad, err := json.Marshal(map[string]any{
		"type":   "state",
		"target": formatHexAddress(addr),
		"keys":   []string{"0xnothex"},
	})
	if err != nil {
		t.Fatalf("marshal compact params: %v", err)
	}
	result, rpcErr = api.GetCompactProof(context.Background(), bad)
	if result != nil {
		t.Fatalf("GetCompactProof result = %v, want nil on an unparsable key", result)
	}
	if rpcErr == nil || rpcErr.Code != rpc.ErrCodeInvalidParams {
		t.Fatalf("GetCompactProof error = %+v, want invalid params", rpcErr)
	}
}

func TestR6_02_LightAPICarriesVerifiableProofMaterial(t *testing.T) {
	sdb, root := newProvedStateDB(t)
	addr := types.Address{0xa1, 0xb2}
	api := NewLightClientAPI(nil, NewSPVProver(nil, sdb))

	params, err := json.Marshal(map[string]any{"address": formatHexAddress(addr)})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	out, rpcErr := api.GetStateProof(context.Background(), params)
	if rpcErr != nil {
		t.Fatalf("GetStateProof: %+v", rpcErr)
	}
	resp, ok := out.(*StateProofResponse)
	if !ok {
		t.Fatalf("response type = %T, want *StateProofResponse", out)
	}
	if resp.AccountProof == "" {
		t.Fatal("AccountProof is empty: the caller received no material it could re-verify offline")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(resp.AccountProof, "0x"))
	if err != nil {
		t.Fatalf("AccountProof is not hex: %v", err)
	}
	restored := unmarshalVerkleProof(raw)
	if restored == nil {
		t.Fatal("the AccountProof handed to the caller does not decode")
	}
	offline := &StateProof{Address: addr, AccountProof: restored, StorageProofs: map[types.Hash]*StorageProofEntry{}}
	if !VerifyStateProof(root, offline) {
		t.Fatal("the proof material in the RPC response does not verify against the state root")
	}
}
