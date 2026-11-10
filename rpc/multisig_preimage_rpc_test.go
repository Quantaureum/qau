// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/multisig"
)

// preimageFromRPC calls GetMultisigProposalPreimage and round-trips the
// response through JSON so the test consumes exactly what a wallet sees on
// the wire (all numbers become float64, all strings stay strings). A field
// that only survives the Go-native path but not the JSON round trip — e.g.
// a nonce JSON number beyond the 2^53 JS safe-integer range — fails here.
func preimageFromRPC(t *testing.T, api *MultisigAPI, hashHex string) map[string]any {
	t.Helper()
	params, err := json.Marshal([]string{hashHex})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	resp, apiErr := api.GetMultisigProposalPreimage(context.Background(), params)
	if apiErr != nil {
		t.Fatalf("GetMultisigProposalPreimage RPC error: %v", apiErr)
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return out
}

// registerSingleSignerWallet registers caller as a 1-of-1 multisig wallet
// through the RPC path (mirrors the R38-P0-01 step4 fixtures) and returns
// the caller address hex and public key hex.
func registerSingleSignerWallet(t *testing.T, api *MultisigAPI) (callerHex, pubKeyHex string) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	callerAddr := crypto.PublicKeyAddressFromBytes(kp.Public.Bytes())
	callerHex = "0x" + hex.EncodeToString(callerAddr[:])
	pubKeyHex = "0x" + hex.EncodeToString(kp.Public.Bytes())

	var salt [types.MultisigV2SaltSize]byte
	for i := range salt {
		salt[i] = byte(0xff - i)
	}
	regReq := map[string]any{
		"address":          callerHex,
		"threshold":        1,
		"signers":          []string{callerHex},
		"signerPublicKeys": map[string]string{callerHex: pubKeyHex},
		"salt":             "0x" + hex.EncodeToString(salt[:]),
	}
	regParams, _ := json.Marshal(regReq)
	if _, apiErr := api.RegisterWallet(context.Background(), regParams); apiErr != nil {
		t.Fatalf("RegisterWallet RPC error: %v", apiErr)
	}
	return callerHex, pubKeyHex
}

// parseRespAddr decodes an address field from the preimage response.
// Response address fields use types.Address.String() (QAU base32) matching
// every other multisig RPC response; parseAddress also accepts 0x-hex.
func parseRespAddr(t *testing.T, s string) types.Address {
	t.Helper()
	a, err := parseAddress(s)
	if err != nil {
		t.Fatalf("parse address %q: %v", s, err)
	}
	return a
}

// TestMultisigAPI_GetMultisigProposalPreimage_RebuildsCanonicalHash is the
// field-drift guard for the whole preimage RPC: it drives the real
// RegisterWallet → CreateProposal RPC path, fetches the preimage, and
// rebuilds the canonical digest from the response fields ONLY (the exact
// reconstruction a wallet performs before un-blinding
// qau_approveMultisigProposal). The rebuilt digest must equal the stored
// proposal hash (what approve signs), the node-side recomputedHash, and
// response.hash. If any response field drifts from
// types.ComputeMultisigV2ProposalHash inputs, the rebuild mismatches and
// this test fails.
func TestMultisigAPI_GetMultisigProposalPreimage_RebuildsCanonicalHash(t *testing.T) {
	store := multisig.NewMultisigStateStore()
	api := NewMultisigAPI(store, newMockStateReader(), &mockChainStateDBHC{})
	api.SetChainInfo(newMockChainInfo())

	callerHex, _ := registerSingleSignerWallet(t, api)

	toAddr := types.Address{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
		0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34}
	toHex := "0x" + hex.EncodeToString(toAddr[:])
	value := big.NewInt(987_654_321)

	createReq := fmt.Sprintf(`{"from":"%s","to":"%s","value":"%d"}`, callerHex, toHex, value.Int64())
	resp, apiErr := api.CreateProposal(context.Background(), json.RawMessage(createReq))
	if apiErr != nil {
		t.Fatalf("CreateProposal RPC error: %v", apiErr)
	}
	created := resp.(map[string]any)

	proposals := store.GetAllProposals(parseRespAddr(t, callerHex))
	if len(proposals) != 1 {
		t.Fatalf("expected 1 proposal persisted, got %d", len(proposals))
	}
	stored := proposals[0]

	pre := preimageFromRPC(t, api, "0x"+hex.EncodeToString(stored.Hash[:]))

	// Rebuild the digest from response fields only.
	chainID := uint64(pre["chainId"].(float64))
	hashWallet := parseRespAddr(t, pre["hashWalletAddr"].(string))
	to := parseRespAddr(t, pre["to"].(string))
	valueBig, ok := new(big.Int).SetString(pre["value"].(string), 10)
	if !ok {
		t.Fatalf("response value %q does not parse as a decimal integer", pre["value"])
	}
	nonce, err := strconv.ParseUint(pre["nonce"].(string), 10, 64)
	if err != nil {
		t.Fatalf("response nonce %q does not parse as uint64: %v", pre["nonce"], err)
	}
	expiresAt := uint64(pre["expiresAt"].(float64))
	callData, err := hex.DecodeString(strings.TrimPrefix(pre["callData"].(string), "0x"))
	if err != nil {
		t.Fatalf("response callData does not parse as hex: %v", err)
	}
	if got := pre["domain"].(string); got != types.MultisigV2ProposalDomain {
		t.Fatalf("response domain = %q, want %q", got, types.MultisigV2ProposalDomain)
	}

	rebuilt, rerr := types.ComputeMultisigV2ProposalHash(chainID, hashWallet, to, valueBig, callData, nonce, expiresAt)
	if rerr != nil {
		t.Fatalf("rebuild canonical hash from preimage fields: %v", rerr)
	}

	if rebuilt != stored.Hash {
		t.Fatalf("hash rebuilt from preimage fields %s != stored proposal hash %s — field drift between the preimage RPC response and ComputeMultisigV2ProposalHash inputs",
			"0x"+hex.EncodeToString(rebuilt[:]), "0x"+hex.EncodeToString(stored.Hash[:]))
	}

	if gotHash := pre["hash"].(string); gotHash != "0x"+hex.EncodeToString(stored.Hash[:]) {
		t.Fatalf("response hash = %s, want stored %s", gotHash, "0x"+hex.EncodeToString(stored.Hash[:]))
	}
	if gotRecomputed := pre["recomputedHash"].(string); gotRecomputed != "0x"+hex.EncodeToString(rebuilt[:]) {
		t.Fatalf("response recomputedHash = %s, want rebuilt %s", gotRecomputed, "0x"+hex.EncodeToString(rebuilt[:]))
	}
	if match, ok := pre["hashMatch"].(bool); !ok || !match {
		t.Fatalf("response hashMatch = %#v, want true", pre["hashMatch"])
	}
	if gotCreated := created["hash"].(string); gotCreated != pre["hash"].(string) {
		t.Fatalf("CreateProposal hash %s != preimage hash %s", gotCreated, pre["hash"])
	}

	// walletAddr is the store cache key (the caller EOA here); the digest
	// binds hashWalletAddr (the V2-derived wallet). Both must be exposed
	// and must differ on the V2 path.
	v2Wallet, okV2 := api.callerToWallet[parseRespAddr(t, callerHex)]
	if !okV2 {
		t.Fatal("callerToWallet has no V2 mapping — RegisterWallet did not record it")
	}
	if got := parseRespAddr(t, pre["walletAddr"].(string)); got != parseRespAddr(t, callerHex) {
		t.Fatalf("response walletAddr = %s, want caller EOA %s", got, callerHex)
	}
	if got := parseRespAddr(t, pre["hashWalletAddr"].(string)); got != v2Wallet {
		t.Fatalf("response hashWalletAddr = %s, want V2 wallet %s", got, v2Wallet)
	}
	if v2Wallet == parseRespAddr(t, callerHex) {
		t.Fatal("V2 wallet equals the caller EOA — expected a distinct derived address on the V2 path")
	}
}

// TestMultisigAPI_GetMultisigProposalPreimage_WithCallData covers the
// Keccak256(callData) term with non-empty callData. The RPC create path
// carries no callData today, so the proposal is inserted through the store
// directly; the store's R39-P1-02 invariant gate forces the canonical hash,
// and the rebuild from the response fields must still match.
func TestMultisigAPI_GetMultisigProposalPreimage_WithCallData(t *testing.T) {
	store := multisig.NewMultisigStateStore()
	api := NewMultisigAPI(store, newMockStateReader(), &mockChainStateDBHC{})
	api.SetChainInfo(newMockChainInfo())

	callerHex, _ := registerSingleSignerWallet(t, api)
	callerAddr := parseRespAddr(t, callerHex)

	toAddr := types.Address{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	// Deliberately not the mock chain ID: the preimage must carry the
	// chainID stored on the proposal, not read it from chainInfo.
	const chainID = uint64(1669)
	const nonce = uint64(12345)
	callData := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x42}
	value := big.NewInt(42)
	expiresAt := time.Now().Add(time.Hour).Unix()

	propHash, err := types.ComputeMultisigV2ProposalHash(chainID, callerAddr, toAddr, value, callData, nonce, uint64(expiresAt))
	if err != nil {
		t.Fatalf("compute proposal hash: %v", err)
	}
	prop := &multisig.Proposal{
		Hash:           propHash,
		WalletAddr:     callerAddr,
		HashWalletAddr: callerAddr,
		To:             toAddr,
		Value:          value,
		Data:           callData,
		GasLimit:       21000,
		SignerBitmap:   make([]byte, 1),
		Signatures:     make([][]byte, 1),
		Status:         multisig.ProposalStatusPending,
		CreatedAt:      time.Now().Unix(),
		ExpiresAt:      expiresAt,
		ChainID:        chainID,
		Nonce:          nonce,
	}
	if err := store.CreateProposal(prop, store.GetWallet(callerAddr)); err != nil {
		t.Fatalf("store.CreateProposal: %v", err)
	}

	pre := preimageFromRPC(t, api, "0x"+hex.EncodeToString(propHash[:]))

	nonceGot, err := strconv.ParseUint(pre["nonce"].(string), 10, 64)
	if err != nil {
		t.Fatalf("response nonce %q does not parse: %v", pre["nonce"], err)
	}
	callDataGot, err := hex.DecodeString(strings.TrimPrefix(pre["callData"].(string), "0x"))
	if err != nil {
		t.Fatalf("response callData does not parse: %v", err)
	}
	if string(callDataGot) != string(callData) {
		t.Fatalf("response callData = %#x, want %#x", callDataGot, callData)
	}
	rebuilt, rerr := types.ComputeMultisigV2ProposalHash(
		uint64(pre["chainId"].(float64)),
		parseRespAddr(t, pre["hashWalletAddr"].(string)),
		parseRespAddr(t, pre["to"].(string)),
		func() *big.Int {
			v, ok := new(big.Int).SetString(pre["value"].(string), 10)
			if !ok {
				t.Fatalf("response value %q does not parse", pre["value"])
			}
			return v
		}(),
		callDataGot,
		nonceGot,
		uint64(pre["expiresAt"].(float64)),
	)
	if rerr != nil {
		t.Fatalf("rebuild canonical hash: %v", rerr)
	}
	if rebuilt != propHash {
		t.Fatalf("hash rebuilt from preimage fields %s != stored hash %s (callData term drifted)",
			"0x"+hex.EncodeToString(rebuilt[:]), "0x"+hex.EncodeToString(propHash[:]))
	}
	if match := pre["hashMatch"].(bool); !match {
		t.Fatal("response hashMatch = false, want true")
	}
	if got := pre["nonce"].(string); got != "12345" {
		t.Fatalf("response nonce = %q, want \"12345\"", got)
	}
}

// TestMultisigAPI_GetMultisigProposalPreimage_HashDriftReported proves the
// drift-reporting path: a stored proposal whose fields no longer hash to
// its stored digest (the R39-P1-02 attack shape) must NOT be served with a
// silently matching preimage. The wallet-side rebuild would refuse to sign
// such a digest anyway; the RPC surfaces the mismatch as hashMatch=false.
func TestMultisigAPI_GetMultisigProposalPreimage_HashDriftReported(t *testing.T) {
	store := multisig.NewMultisigStateStore()
	api := NewMultisigAPI(store, newMockStateReader(), &mockChainStateDBHC{})
	api.SetChainInfo(newMockChainInfo())

	callerHex, _ := registerSingleSignerWallet(t, api)
	toAddr := types.Address{0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
		0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64}
	toHex := "0x" + hex.EncodeToString(toAddr[:])

	createReq := fmt.Sprintf(`{"from":"%s","to":"%s","value":"777"}`, callerHex, toHex)
	if _, apiErr := api.CreateProposal(context.Background(), json.RawMessage(createReq)); apiErr != nil {
		t.Fatalf("CreateProposal RPC error: %v", apiErr)
	}
	proposals := store.GetAllProposals(parseRespAddr(t, callerHex))
	if len(proposals) != 1 {
		t.Fatalf("expected 1 proposal persisted, got %d", len(proposals))
	}

	// Simulate field drift after storage: GetProposal returns the live
	// pointer, so mutating the value breaks the stored-hash invariant the
	// same way an unchecked store caller would.
	drifted := store.GetProposal(proposals[0].Hash)
	drifted.Value = big.NewInt(1)

	pre := preimageFromRPC(t, api, "0x"+hex.EncodeToString(drifted.Hash[:]))

	if match := pre["hashMatch"].(bool); match {
		t.Fatal("response hashMatch = true after field drift, want false")
	}
	if pre["hash"].(string) == pre["recomputedHash"].(string) {
		t.Fatal("stored hash equals recomputed hash after field drift — drift not detected")
	}
}

// TestMultisigAPI_GetMultisigProposalPreimage_NotFoundAndInvalidParams
// covers the parameter-validation edges: unknown hash, nil params, bad hex,
// and wrong hash length.
func TestMultisigAPI_GetMultisigProposalPreimage_NotFoundAndInvalidParams(t *testing.T) {
	store := multisig.NewMultisigStateStore()
	api := NewMultisigAPI(store, newMockStateReader(), &mockChainStateDBHC{})
	api.SetChainInfo(newMockChainInfo())

	// Unknown but well-formed hash → not found.
	unknown := types.Hash{0x01, 0x02, 0x03}
	params, _ := json.Marshal([]string{"0x" + hex.EncodeToString(unknown[:])})
	if _, apiErr := api.GetMultisigProposalPreimage(context.Background(), params); apiErr == nil || apiErr.Code != ErrCodeNotFound {
		t.Fatalf("unknown hash: want ErrCodeNotFound (%d), got %#v", ErrCodeNotFound, apiErr)
	}

	// Nil params → invalid params.
	if _, apiErr := api.GetMultisigProposalPreimage(context.Background(), nil); apiErr == nil {
		t.Fatal("nil params: want an error, got nil")
	}

	// Bad hex → invalid params.
	params, _ = json.Marshal([]string{"not-hex"})
	if _, apiErr := api.GetMultisigProposalPreimage(context.Background(), params); apiErr == nil || apiErr.Code != ErrCodeInvalidParams {
		t.Fatalf("bad hex: want ErrCodeInvalidParams (%d), got %#v", ErrCodeInvalidParams, apiErr)
	}

	// Wrong hash length → invalid params.
	params, _ = json.Marshal([]string{"0x1234"})
	if _, apiErr := api.GetMultisigProposalPreimage(context.Background(), params); apiErr == nil || apiErr.Code != ErrCodeInvalidParams {
		t.Fatalf("short hash: want ErrCodeInvalidParams (%d), got %#v", ErrCodeInvalidParams, apiErr)
	}
}

// TestMultisigAPI_GetMultisigProposalPreimage_NoStore pins the fail-closed
// behavior when the multisig store is not wired.
func TestMultisigAPI_GetMultisigProposalPreimage_NoStore(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	someHash := types.Hash{0x01}
	params, _ := json.Marshal([]string{"0x" + hex.EncodeToString(someHash[:])})
	if _, apiErr := api.GetMultisigProposalPreimage(context.Background(), params); apiErr == nil || apiErr.Code != ErrCodeInternal {
		t.Fatalf("nil store: want ErrCodeInternal (%d), got %#v", ErrCodeInternal, apiErr)
	}
}
