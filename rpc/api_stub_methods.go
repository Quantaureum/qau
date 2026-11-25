// Quantaureum Node source, version 1.0.0.
//go:build !no_rpc_sign_tx

// Stub methods for API handlers referenced in api.go RegisterHandlers.
// SignQuantumTransaction is disabled in production (use client-side signing);
// in dev mode it performs Dilithium3 signing for testing.
// The remaining methods are intentionally NOT IMPLEMENTED and fail closed
// with ErrCodeNotImplemented (audit M-07): each carries a per-method comment
// documenting the evaluated gap that blocks a safe wiring. They stay
// registered so callers get a precise refusal instead of method-not-found.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// SignQuantumTransaction signs a transaction using Dilithium3.
// In production: always returns disabled error (use client-side signing).
// In dev mode (DEV_MODE_ENABLED=true + SetDevMode(true)): performs signing.
func (api *API) SignQuantumTransaction(ctx context.Context, params json.RawMessage) (any, *Error) {
	if !api.devMode {
		return nil, NewError(ErrCodeUnauthorized, "qau_signQuantumTransaction is disabled; use client-side signing")
	}

	// Dev mode: parse params and sign
	var rawParams []json.RawMessage
	if err := json.Unmarshal(params, &rawParams); err != nil || len(rawParams) < 2 {
		return nil, NewError(ErrCodeInvalidParams, "expected [txObject, privateKeyHex]")
	}

	var txReq struct {
		Type     int             `json:"type"`
		Nonce    uint64          `json:"nonce"`
		ChainID  uint64          `json:"chainId"`
		To       string          `json:"to"`
		Value    json.RawMessage `json:"value"`
		GasLimit uint64          `json:"gasLimit"`
		GasPrice json.RawMessage `json:"gasPrice"`
		Data     string          `json:"data"`
	}
	if err := json.Unmarshal(rawParams[0], &txReq); err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid tx object: "+err.Error())
	}

	var privKeyHex string
	if err := json.Unmarshal(rawParams[1], &privKeyHex); err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid private key hex: "+err.Error())
	}

	// Parse value (decimal string, hex string, or number)
	value := new(big.Int)
	if len(txReq.Value) > 0 {
		switch txReq.Value[0] {
		case '"':
			var valStr string
			if err := json.Unmarshal(txReq.Value, &valStr); err != nil {
				return nil, NewError(ErrCodeInvalidParams, "invalid value")
			}
			valStr = strings.TrimSpace(valStr)
			if strings.HasPrefix(valStr, "0x") || strings.HasPrefix(valStr, "0X") {
				if _, ok := value.SetString(valStr[2:], 16); !ok {
					return nil, NewError(ErrCodeInvalidParams, "invalid hex value")
				}
			} else {
				if _, ok := value.SetString(valStr, 10); !ok {
					return nil, NewError(ErrCodeInvalidParams, "invalid decimal value")
				}
			}
			if value.Sign() < 0 {
				return nil, NewError(ErrCodeInvalidParams, "value cannot be negative")
			}
		default:
			if err := json.Unmarshal(txReq.Value, value); err != nil {
				return nil, NewError(ErrCodeInvalidParams, "invalid value type")
			}
			if value.Sign() < 0 {
				return nil, NewError(ErrCodeInvalidParams, "value cannot be negative")
			}
		}
	}

	// Parse gas price
	gasPrice := new(big.Int)
	if len(txReq.GasPrice) > 0 {
		switch txReq.GasPrice[0] {
		case '"':
			var gpStr string
			if err := json.Unmarshal(txReq.GasPrice, &gpStr); err == nil {
				gpStr = strings.TrimSpace(gpStr)
				if strings.HasPrefix(gpStr, "0x") || strings.HasPrefix(gpStr, "0X") {
					gasPrice.SetString(gpStr[2:], 16)
				} else {
					gasPrice.SetString(gpStr, 10)
				}
			}
		default:
			// Malformed input falls back to the default gas price below.
			_ = json.Unmarshal(txReq.GasPrice, gasPrice)
		}
	}
	if gasPrice.Sign() <= 0 {
		gasPrice = big.NewInt(1)
	}

	// Parse private key
	privKeyHex = strings.TrimPrefix(privKeyHex, "dilithium3:")
	if idx := strings.Index(privKeyHex, ":"); idx >= 0 {
		privKeyHex = privKeyHex[:idx]
	}
	keyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid private key hex: "+err.Error())
	}
	if len(keyBytes) != crypto.Dilithium3PrivateKeySize {
		return nil, NewError(ErrCodeInvalidParams, fmt.Sprintf("invalid private key size: %d", len(keyBytes)))
	}

	privKey, err := crypto.PrivateKeyFromBytes(keyBytes)
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid private key: "+err.Error())
	}
	pubKeyBytes := privKey.PublicKey().Bytes()
	fromAddr := crypto.PublicKeyAddressFromBytes(pubKeyBytes)

	// Parse 'to' address
	var toAddr *types.Address
	if txReq.To != "" && txReq.To != "none" {
		h := strings.TrimPrefix(strings.ToLower(txReq.To), "0x")
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != types.AddressLength {
			return nil, NewError(ErrCodeInvalidParams, "invalid to address")
		}
		var a types.Address
		copy(a[:], b)
		toAddr = &a
	}

	// Parse data
	var dataBytes []byte
	if txReq.Data != "" {
		dh := strings.TrimPrefix(txReq.Data, "0x")
		// R32-P2-02 FIX (2026-07-28): Cap data size to prevent memory DoS.
		// Mirrors parseHexBytes' maxParseHexBytesLen (1 MiB decoded).
		if len(dh) > maxParseHexBytesLen {
			return nil, NewError(ErrCodeInvalidParams,
				fmt.Sprintf("data too large: %d chars exceeds limit %d", len(dh), maxParseHexBytesLen))
		}
		dataBytes, err = hex.DecodeString(dh)
		if err != nil {
			return nil, NewError(ErrCodeInvalidParams, "invalid data hex: "+err.Error())
		}
	}

	// Validate chain ID
	if txReq.ChainID == 0 {
		return nil, NewError(ErrCodeInvalidParams, "chainId is required")
	}
	if api.chainInfo != nil && txReq.ChainID != api.chainInfo.ChainID() {
		return nil, NewError(ErrCodeInvalidParams, fmt.Sprintf("chainId mismatch: expected %d, got %d", api.chainInfo.ChainID(), txReq.ChainID))
	}

	// Build transaction
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxType(txReq.Type),
		Nonce:    txReq.Nonce,
		From:     fromAddr,
		To:       toAddr,
		Value:    value,
		GasLimit: txReq.GasLimit,
		GasPrice: gasPrice,
		Data:     dataBytes,
		ChainID:  txReq.ChainID,
	}

	// Sign
	signingHash, err := tx.SigningHash()
	if err != nil {
		return nil, NewError(ErrCodeInternal, "compute signing hash: "+err.Error())
	}
	signature, err := crypto.Sign(privKey, signingHash[:])
	if err != nil {
		return nil, NewError(ErrCodeInternal, "signing failed: "+err.Error())
	}

	tx.PublicKey = pubKeyBytes
	tx.Signature = signature

	rawBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		return nil, NewError(ErrCodeInternal, "marshal failed: "+err.Error())
	}

	return "0x" + hex.EncodeToString(rawBytes), nil
}

// errNotImplemented builds the fail-closed error for a registered RPC method
// whose backing capability is intentionally not wired on this node (audit
// M-07). The message names the method and the concrete gap so callers get an
// actionable refusal instead of a generic internal error.
func errNotImplemented(method, reason string) *Error {
	return NewError(ErrCodeNotImplemented, method+" is not implemented on this node: "+reason)
}

// VerifyQuantumTransaction is NOT IMPLEMENTED (audit M-07, fail-closed).
//
// Evaluation: the raw crypto exists (crypto.Verify over Dilithium3), but there
// is no agreed contract for WHICH bytes a submitted transaction signs — the
// wallet signs the |QUANTUM|-envelope payload client-side (see
// quantum_signature_parser.go) and no canonical server-side signing-hash
// convention exists for arbitrary submitted transactions. Wiring a guess would
// expose a verification oracle that disagrees with the wallet. Wiring this
// requires a documented (tx, publicKey, signature) verification contract
// synced with the wallet plus round-trip tests; until then the method stays
// registered and refuses.
func (api *API) VerifyQuantumTransaction(ctx context.Context, params json.RawMessage) (any, *Error) {
	return nil, errNotImplemented("qau_verifyQuantumTransaction",
		"no wallet-synced contract for which bytes a submitted transaction signs; use client-side Dilithium3 verification")
}

// SendPrivacyTransaction is NOT IMPLEMENTED (audit M-07, fail-closed).
//
// Evaluation: the privacy package can BUILD a privacy transaction
// (privacy.PrivacyManager.SendPrivacyTransaction), but nothing broadcasts or
// includes privacy transactions in blocks: the API-local manager is
// disconnected from chain state and no privacy-tx mempool/gossip/execution
// path exists. A wired handler would report success for a transaction that can
// never land on-chain. Wiring this requires end-to-end privacy-transaction
// inclusion (mempool, block execution, persistence) first.
func (api *API) SendPrivacyTransaction(ctx context.Context, params json.RawMessage) (any, *Error) {
	return nil, errNotImplemented("qau_sendPrivacyTransaction",
		"privacy transactions are not accepted into the mempool or included in blocks; a node-side build-only path would silently lose funds' visibility")
}

// ScanPrivacy is NOT IMPLEMENTED (audit M-07, fail-closed).
//
// Evaluation: privacy.PrivacyManager.ScanPrivacyTransactions exists, but it
// only sees announcements cached in the API-local in-memory manager, which
// receives no chain traffic; results would be misleadingly empty or
// incomplete. Wiring this requires chain-integrated stealth-announcement
// indexing addressable by the caller's (kemPrivKey, spendPubKey).
func (api *API) ScanPrivacy(ctx context.Context, params json.RawMessage) (any, *Error) {
	return nil, errNotImplemented("qau_scanPrivacy",
		"no chain-integrated stealth-announcement index exists; scanning would only see this node's in-memory cache and miss on-chain outputs")
}

// GetPrivacyBalance is NOT IMPLEMENTED (audit M-07, fail-closed).
//
// Evaluation: the underlying privacy.PrivacyManager.GetPrivacyBalance returns
// a COUNT of unspent notes, NOT a QAU amount — output amounts are
// KEM-encrypted to the receiver and cannot be summed server-side (see the
// deprecation comment on privacy.PrivacyManager.GetPrivacyBalance). Wiring it
// as a "balance" would be a resource-accounting error. A real balance RPC
// needs a receiver-side decryption protocol that never transmits private keys.
func (api *API) GetPrivacyBalance(ctx context.Context, params json.RawMessage) (any, *Error) {
	return nil, errNotImplemented("qau_getPrivacyBalance",
		"privacy output amounts are receiver-encrypted and cannot be summed server-side; a count of unspent notes would be misleading as a balance")
}

// GenerateStealthAddress is NOT IMPLEMENTED (audit M-07, fail-closed).
//
// Evaluation: privacy/stealth can derive a one-time stealth address, but only
// with the SENDER's Dilithium3 private key passed in, because the announcement
// must carry the sender signature to be valid downstream. Accepting raw
// signing keys over a public RPC for a capability with no chain integration is
// not a safe wiring. Wiring this requires an agreed key-handling contract
// (client-side generation, or an authenticated session-bound key source).
func (api *API) GenerateStealthAddress(ctx context.Context, params json.RawMessage) (any, *Error) {
	return nil, errNotImplemented("qau_generateStealthAddress",
		"valid stealth announcements require the sender's private signing key, which this RPC must not solicit; generate stealth addresses client-side")
}
