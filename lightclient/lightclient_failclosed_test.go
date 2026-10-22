// Quantaureum Node source, version 1.0.0.
package lightclient

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
)

// R3-01: VerifyHeaderChain used to `continue` on ErrSyncCommitteeNotAvailable,
// accepting headers that carry sync committee data while no committee is
// loaded. The chain check must fail closed instead.

func chainHeaderPair(t *testing.T, withSyncData bool) []*encoding.BlockHeader {
	t.Helper()
	prev := testHeader()
	curr := &encoding.BlockHeader{}
	curr.Height = prev.Height + 1
	curr.ParentHash = block.ComputeBlockHash(prev)
	curr.Timestamp = prev.Timestamp + 1
	if withSyncData {
		curr.SyncCommitteeBits = []byte{0x01}
		curr.SyncCommitteeSig = []byte{0x01}
	}
	return []*encoding.BlockHeader{prev, curr}
}

func TestVerifyHeaderChainFailsClosedWithoutCommittee(t *testing.T) {
	syncer := NewHeaderSyncer(nil, nil)

	// Headers without sync committee data remain valid pre-committee blocks.
	if err := syncer.VerifyHeaderChain(chainHeaderPair(t, false)); err != nil {
		t.Fatalf("pre-committee chain rejected: %v", err)
	}

	err := syncer.VerifyHeaderChain(chainHeaderPair(t, true))
	if err == nil {
		t.Fatal("chain with sync committee data and no committee was accepted")
	}
	if !errors.Is(err, ErrSyncCommitteeNotAvailable) {
		t.Fatalf("expected ErrSyncCommitteeNotAvailable, got %v", err)
	}
}

func TestVerifyHeaderChainAcceptsHonestCommitteeSignatures(t *testing.T) {
	verifier, members := newTestCommittee(t, 3)
	syncer := NewHeaderSyncer(nil, nil)
	syncer.syncCommitteeVerifier = verifier

	headers := chainHeaderPair(t, false)
	signedHeader(t, headers[1], []int{0, 1, 2}, members)

	if err := syncer.VerifyHeaderChain(headers); err != nil {
		t.Fatalf("honest committee-signed chain rejected: %v", err)
	}
}

func callVerifySyncCommitteeSig(t *testing.T, api *LightClientAPI, header *encoding.BlockHeader) map[string]any {
	t.Helper()
	raw, err := encoding.MarshalBlockHeader(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	params, err := json.Marshal([]any{hex.EncodeToString(raw)})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	res, rpcErr := api.VerifySyncCommitteeSig(context.Background(), params)
	if rpcErr != nil {
		t.Fatalf("VerifySyncCommitteeSig RPC error: %v", rpcErr)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type %T", res)
	}
	return m
}

// R3-01: the RPC result distinguishes "signature verified" from "no committee,
// verification skipped". Neither may report valid=true.
func TestVerifySyncCommitteeSigTriState(t *testing.T) {
	syncer := NewHeaderSyncer(nil, nil)
	api := NewLightClientAPI(syncer, nil)

	// Empty committee, header carries no sync data: skipped, not verified.
	res := callVerifySyncCommitteeSig(t, api, testHeader())
	if res["valid"] != false || res["verified"] != false {
		t.Fatalf("skipped header reported as valid/verified: %v", res)
	}
	if res["reason"] != "no_committee" {
		t.Fatalf("reason = %v, want no_committee", res["reason"])
	}

	// Empty committee, header carries sync data: fail-closed.
	withData := testHeader()
	withData.SyncCommitteeBits = []byte{0x01}
	withData.SyncCommitteeSig = []byte{0x01}
	res = callVerifySyncCommitteeSig(t, api, withData)
	if res["valid"] != false || res["verified"] != false {
		t.Fatalf("unverifiable header reported as valid/verified: %v", res)
	}
	if res["reason"] != "no_committee" {
		t.Fatalf("reason = %v, want no_committee", res["reason"])
	}
	if res["error"] == "" || res["error"] == nil {
		t.Fatalf("expected error detail, got %v", res["error"])
	}

	// Configured committee with an honest signature: verified.
	verifier, members := newTestCommittee(t, 3)
	syncer.syncCommitteeVerifier = verifier
	h := testHeader()
	h.ChainID = 1668
	h.Slot = 42
	signedHeader(t, h, []int{0, 1, 2}, members)
	res = callVerifySyncCommitteeSig(t, api, h)
	if res["valid"] != true || res["verified"] != true {
		t.Fatalf("honest header not reported as verified: %v", res)
	}

	// Configured committee but tampered header: verification failed.
	h.Height++
	res = callVerifySyncCommitteeSig(t, api, h)
	if res["valid"] != false || res["verified"] != false {
		t.Fatalf("tampered header reported as valid/verified: %v", res)
	}
	if res["reason"] != "verification_failed" {
		t.Fatalf("reason = %v, want verification_failed", res["reason"])
	}
}
