// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// R6-01 (2026-10-21 sixth-round audit): evm_snapshot and evm_revert were served
// by a SnapshotManager seam that no backend could honour. The node adapter
// recorded a state root keyed by BLOCK HEIGHT in StateDB.stateSnapshots -- a map
// that is written, pruned and counted but never read back -- and "restore"
// passed that same height to StateDB.RevertToSnapshot(id), whose argument is a
// position in the live dirty-state journal. So the pair either poisoned the next
// authoritative Commit (no journal entry at that position) or rewound and
// truncated the journal of a block transition already in flight, and neither
// outcome ever restored committed state at a height.
//
// Both methods now refuse unconditionally and the injection point is gone, so
// these tests pin: the refusal for every parameter shape, the explanation the
// caller gets, the absence of the seam, and the fact that the methods stay
// registered and admin-gated (a caller must see "not supported", not "method not
// found", and a non-admin must not reach the refusal path at all).

func snapshotRefusalParams() map[string]json.RawMessage {
	return map[string]json.RawMessage{
		"nil params":      nil,
		"null":            json.RawMessage("null"),
		"empty array":     json.RawMessage("[]"),
		"hex height":      json.RawMessage(`["0x1"]`),
		"decimal height":  json.RawMessage(`["12345"]`),
		"non numeric":     json.RawMessage(`["latest"]`),
		"object instead":  json.RawMessage(`{"height":"0x1"}`),
		"negative height": json.RawMessage(`["-1"]`),
		"beyond uint64":   json.RawMessage(`["18446744073709551616"]`),
		"truncated json":  json.RawMessage(`["0x1`),
	}
}

func TestR6_01_SnapshotMethodsRefuseEveryParamShape(t *testing.T) {
	api := newTestAPIFull()

	for name, params := range snapshotRefusalParams() {
		for _, method := range []struct {
			label string
			call  func(json.RawMessage) (any, *Error)
		}{
			{"evm_snapshot", func(p json.RawMessage) (any, *Error) { return api.CreateSnapshot(ctx(), p) }},
			{"evm_revert", func(p json.RawMessage) (any, *Error) { return api.RestoreSnapshot(ctx(), p) }},
		} {
			t.Run(method.label+"/"+name, func(t *testing.T) {
				result, rpcErr := method.call(params)
				if result != nil {
					t.Fatalf("result = %v, want nil", result)
				}
				if rpcErr == nil {
					t.Fatal("expected refusal, got nil error")
				}
				if rpcErr.Code != ErrCodeInternal {
					t.Errorf("code = %d, want %d (ErrCodeInternal)", rpcErr.Code, ErrCodeInternal)
				}
				if rpcErr.Message != ErrStateSnapshotNotSupportedRPC {
					t.Errorf("message = %q, want %q", rpcErr.Message, ErrStateSnapshotNotSupportedRPC)
				}
				data, ok := rpcErr.Data.(string)
				if !ok || data == "" {
					t.Errorf("data = %#v, want a non-empty explanation", rpcErr.Data)
				}
			})
		}
	}
}

func TestR6_01_RefusalExplainsWhyAndWhatInstead(t *testing.T) {
	api := newTestAPI()

	_, createErr := api.CreateSnapshot(ctx(), json.RawMessage(`["0x64"]`))
	if createErr == nil {
		t.Fatal("evm_snapshot was accepted")
	}
	// A caller that wants a checkpoint needs the admin-gated fork recovery
	// route, so the refusal has to name it rather than leave the operator
	// hunting.
	if !strings.Contains(createErr.Data.(string), "debug_rollbackChainToHeight") {
		t.Errorf("evm_snapshot refusal does not point at the supported alternative: %v", createErr.Data)
	}

	_, revertErr := api.RestoreSnapshot(ctx(), json.RawMessage(`["0x64"]`))
	if revertErr == nil {
		t.Fatal("evm_revert was accepted")
	}
	// The reason matters: the argument is a journal position, not a height.
	if !strings.Contains(revertErr.Data.(string), "journal") {
		t.Errorf("evm_revert refusal does not explain the journal-position hazard: %v", revertErr.Data)
	}
}

func TestR6_01_SnapshotManagerSeamIsGone(t *testing.T) {
	apiType := reflect.TypeOf((*API)(nil))
	if _, ok := apiType.MethodByName("SetSnapshotManager"); ok {
		t.Error("API.SetSnapshotManager still exists: the injection point for a half-wired snapshot backend must stay removed")
	}

	structType := apiType.Elem()
	for i := 0; i < structType.NumField(); i++ {
		if name := structType.Field(i).Name; strings.Contains(strings.ToLower(name), "snapshotmanager") {
			t.Errorf("API has field %s: a snapshot manager that nothing reads back is a dead seam, not a capability", name)
		}
	}
}

func TestR6_01_SnapshotMethodsStayRegisteredAndAdminGated(t *testing.T) {
	api := newTestAPI()
	server := NewServer(nil)
	api.RegisterHandlers(server)

	server.mu.RLock()
	defer server.mu.RUnlock()

	for _, method := range []string{"evm_snapshot", "evm_revert"} {
		if _, ok := server.handlers[method]; !ok {
			t.Errorf("%s is no longer registered: callers must get an explicit refusal, not method-not-found", method)
		}
		if !server.adminMethods[method] {
			t.Errorf("%s lost its admin gate", method)
		}
	}
}
