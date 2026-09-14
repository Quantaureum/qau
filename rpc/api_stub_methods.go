// Quantaureum Node source, version 1.0.0.
//go:build !no_rpc_sign_tx

// Stub methods for API handlers referenced in api.go RegisterHandlers.
// SignQuantumTransaction is disabled in production (use client-side signing);
// in dev mode it performs Dilithium3 signing for testing.
// The remaining methods return "not implemented" until full implementations
// are provided.
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
		switch {
		case txReq.Value[0] == '"':
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
		switch {
		case txReq.GasPrice[0] == '"':
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
			json.Unmarshal(txReq.GasPrice, gasPrice)
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

// VerifyQuantumTransaction verifies a quantum signature.
func (api *API) VerifyQuantumTransaction(ctx context.Context, params json.RawMessage) (any, *Error) {
	return nil, NewError(ErrCodeInternal, "not implemented")
}

// SendPrivacyTransaction sends a privacy transaction.
func (api *API) SendPrivacyTransaction(ctx context.Context, params json.RawMessage) (any, *Error) {
	return nil, NewError(ErrCodeInternal, "not implemented")
}

// ScanPrivacy scans for privacy transactions.
func (api *API) ScanPrivacy(ctx context.Context, params json.RawMessage) (any, *Error) {
	return nil, NewError(ErrCodeInternal, "not implemented")
}

// GetPrivacyBalance returns the privacy balance for an address.
func (api *API) GetPrivacyBalance(ctx context.Context, params json.RawMessage) (any, *Error) {
	return nil, NewError(ErrCodeInternal, "not implemented")
}

// GenerateStealthAddress generates a stealth address.
func (api *API) GenerateStealthAddress(ctx context.Context, params json.RawMessage) (any, *Error) {
	return nil, NewError(ErrCodeInternal, "not implemented")
}
