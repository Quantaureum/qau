// Quantaureum Go SDK source, version 1.0.0.
package client

// Unit tests for the randomness client methods against a mock JSON-RPC
// server (httptest), covering wire-format parsing and error propagation.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const sampleRandomnessJSON = `{
	"epoch": 18420,
	"randomness": "0xa3f9c10000000000000000000000000000000000000000000000000000000000",
	"boundaryBlock": "0x8f8bf",
	"blockHash": "0x77e5000000000000000000000000000000000000000000000000000000000000",
	"finalized": true,
	"source": "vrf-accumulator"
}`

func newRandomnessMockServer(t *testing.T, wantMethod string, respond string, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if wantMethod != "" && req.Method != wantMethod {
			t.Errorf("got method %q, want %q", req.Method, wantMethod)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":` + respond + `}`))
	}))
}

func TestEpochRandomnessParsesWireFormat(t *testing.T) {
	srv := newRandomnessMockServer(t, "qau_randomnessGet", sampleRandomnessJSON, http.StatusOK)
	defer srv.Close()

	c, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := c.EpochRandomness(context.Background(), 18420)
	if err != nil {
		t.Fatalf("EpochRandomness: %v", err)
	}
	if rec.Epoch != 18420 {
		t.Errorf("Epoch = %d", rec.Epoch)
	}
	if rec.BoundaryBlock != 0x8f8bf {
		t.Errorf("BoundaryBlock = %d", rec.BoundaryBlock)
	}
	if !rec.Finalized {
		t.Error("Finalized = false, want true")
	}
	if rec.Source != "vrf-accumulator" {
		t.Errorf("Source = %q", rec.Source)
	}
	if rec.Randomness[0] != 0xa3 || rec.Randomness[1] != 0xf9 || rec.Randomness[2] != 0xc1 {
		t.Errorf("Randomness prefix = %x", rec.Randomness[:3])
	}
	if rec.BlockHash[0] != 0x77 || rec.BlockHash[1] != 0xe5 {
		t.Errorf("BlockHash prefix = %x", rec.BlockHash[:2])
	}
}

func TestLatestRandomnessRoundtrip(t *testing.T) {
	srv := newRandomnessMockServer(t, "qau_randomnessLatest", sampleRandomnessJSON, http.StatusOK)
	defer srv.Close()

	c, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := c.LatestRandomness(context.Background())
	if err != nil {
		t.Fatalf("LatestRandomness: %v", err)
	}
	if rec.Epoch != 18420 || rec.BoundaryBlock != 0x8f8bf {
		t.Errorf("unexpected record: %+v", rec)
	}
}

func TestRandomnessErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"no finalized epoch yet"}}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LatestRandomness(context.Background()); err == nil {
		t.Fatal("expected error for pre-finality call")
	}
}

func TestParseHexUint64(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
		fail bool
	}{
		{"0x8f8bf", 0x8f8bf, false},
		{"8f8bf", 0x8f8bf, false},
		{"0x0", 0, false},
		{"", 0, true},
		{"0xzz", 0, true},
	}
	for _, tc := range cases {
		got, err := parseHexUint64(tc.in)
		if tc.fail && err == nil {
			t.Errorf("parseHexUint64(%q): expected error", tc.in)
		}
		if !tc.fail && (err != nil || got != tc.want) {
			t.Errorf("parseHexUint64(%q) = %d, %v; want %d", tc.in, got, err, tc.want)
		}
	}
}
