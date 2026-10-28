// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"testing"
)

// TestR19_F03_VerifyFinalityRejectsEmptyVerification pins the R19-F03 fix:
// the public qau_stardust_verifyFinality endpoint used to return
// {"valid": true} for ANY (slot, blockHash) when finalityType was omitted
// (defaults to 0, which VerifyStardustFinality treats as "no QTD finality
// claimed" and passes) and no signature was presented.
func TestR19_F03_VerifyFinalityRejectsEmptyVerification(t *testing.T) {
	api := &StardustAPI{qpos: nil} // handler must reject before qpos is used

	// finalityType omitted → 0 → rejected.
	params, _ := json.Marshal(map[string]any{
		"slot":      1,
		"blockHash": "0x0000000000000000000000000000000000000000000000000000000000000001",
	})
	_, rerr := api.VerifyFinality(context.Background(), params)
	if rerr == nil {
		t.Fatal("finalityType=0 must be rejected (R19-F03)")
	}

	// finalityType set but no signature → rejected.
	params2, _ := json.Marshal(map[string]any{
		"slot":         1,
		"blockHash":    "0x0000000000000000000000000000000000000000000000000000000000000001",
		"finalityType": 1,
	})
	_, rerr2 := api.VerifyFinality(context.Background(), params2)
	if rerr2 == nil {
		t.Fatal("missing qtdSignature must be rejected (R19-F03)")
	}
}

// TestR19_F11_ParseUint64HexOverflow pins the R19-F11 overflow check: a hex
// string wider than uint64 must error instead of silently wrapping to an
// unintended slot.
func TestR19_F11_ParseUint64HexOverflow(t *testing.T) {
	if v, err := parseUint64Hex("ffffffffffffffff"); err != nil || v != ^uint64(0) {
		t.Fatalf("max uint64 must parse exactly, got %d err %v", v, err)
	}
	if _, err := parseUint64Hex("1ffffffffffffffff"); err == nil {
		t.Fatal("17-hex-digit value must overflow-error, not wrap (R19-F11)")
	}
	if v, err := parseUint64Hex("0x1a"); err != nil || v != 0x1a {
		t.Fatalf("plain hex must parse, got %d err %v", v, err)
	}
}
