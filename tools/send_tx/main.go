// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

var qauDecimals = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
var rpcURL string

func main() {
	log.SetFlags(0)

	// Configurable via env vars or defaults
	keyFile := os.Getenv("KEY_FILE")
	if keyFile == "" {
		keyFile = "/tmp/account5_key.txt"
	}
	rpcURL = os.Getenv("RPC_URL")
	if rpcURL == "" {
		rpcURL = "http://127.0.0.1:8545"
	}
	targetAddrStr := os.Getenv("TO_ADDR")
	if targetAddrStr == "" {
		targetAddrStr = "0x3de59b8b7aabc7a188375bcb6584393afec83476"
	}
	amountStr := os.Getenv("AMOUNT")
	if amountStr == "" {
		amountStr = "3200"
	}
	dataHex := os.Getenv("DATA")

	// Read key file
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("Failed to read key file: %v", err)
	}

	// Parse dilithium3 key
	// Format 1: dilithium3:SK_HEX:PK_HEX (colon-separated, with prefix)
	// Format 2: SK_HEX only (8000 hex chars = 4000 bytes, no prefix)
	content := strings.TrimSpace(string(keyData))
	var skHex, pkHex string

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "dilithium3:") {
			// Format 1: dilithium3:SK:PK or dilithium3:SK
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 {
				skHex = parts[1]
				pkHex = parts[2]
			} else if len(parts) == 2 {
				skHex = parts[1]
			} else {
				//nolint:gosec // G706: len(parts) is an integer count, not attacker input.
				log.Fatalf("Invalid key format: expected dilithium3:SK[:PK], got %d parts", len(parts))
			}
			break
		}
		// Try as raw hex (format 2)
		if _, err := hex.DecodeString(line); err == nil && len(line) == 8000 {
			skHex = line
			break
		}
	}

	if skHex == "" {
		log.Fatal("No valid key found in file (expected dilithium3:SK:PK or raw 8000-char SK hex)")
	}

	skBytes, err := hex.DecodeString(skHex)
	if err != nil {
		log.Fatalf("Invalid SK hex: %v", err)
	}

	priv, err := crypto.PrivateKeyFromBytes(skBytes)
	if err != nil {
		log.Fatalf("Invalid private key: %v", err)
	}

	// Derive public key from private key if not provided
	var pkBytes []byte
	if pkHex != "" {
		pkBytes, err = hex.DecodeString(pkHex)
		if err != nil {
			log.Fatalf("Invalid PK hex: %v", err)
		}
	} else {
		pubKey := priv.PublicKey()
		if pubKey == nil {
			log.Fatal("Failed to derive public key from private key")
		}
		pkBytes = pubKey.Bytes()
		fmt.Printf("Derived public key from private key: %d bytes\n", len(pkBytes))
	}

	addr := types.AddressFromPublicKey(pkBytes)
	fmt.Printf("From: 0x%s\n", hex.EncodeToString(addr[:]))

	// Get nonce
	nonce, err := rpcGetNonce(addr)
	if err != nil {
		log.Fatalf("Get nonce: %v", err)
	}
	fmt.Printf("Nonce: %d\n", nonce)

	// Get chain ID
	chainID, err := rpcGetChainID()
	if err != nil {
		log.Fatalf("Get chain ID: %v", err)
	}
	fmt.Printf("ChainID: %d\n", chainID)

	// Parse target address
	targetAddr, err := types.ParseHexAddress(targetAddrStr)
	if err != nil {
		log.Fatalf("Invalid target address: %v", err)
	}

	// Parse amount
	amountInt := new(big.Int)
	_, ok := amountInt.SetString(amountStr, 10)
	if !ok {
		//nolint:gosec // G706: local CLI tool — echoing the operator's own
		// malformed amount string back to them is intended UX, not a log-injection
		// attack surface (single-user tool, logs never shipped to a SIEM).
		log.Fatalf("Invalid amount: %s", amountStr)
	}
	value := new(big.Int).Mul(amountInt, qauDecimals)
	var data []byte
	if dataHex != "" {
		data, err = hex.DecodeString(strings.TrimPrefix(dataHex, "0x"))
		if err != nil {
			log.Fatalf("Invalid DATA hex: %v", err)
		}
	}
	gasLimit := uint64(21000)
	if dataHex != "" {
		gasLimit = 300000
	}
	tx := &encoding.Transaction{
		Version:   1,
		Type:      encoding.TxTypeTransfer,
		Nonce:     nonce,
		From:      addr,
		To:        &targetAddr,
		Value:     value,
		GasLimit:  gasLimit,
		GasPrice:  big.NewInt(1000000000), // 1 Gwei
		Data:      data,
		ChainID:   chainID,
		PublicKey: pkBytes,
	}

	// Sign
	signingHash, err := tx.SigningHash()
	if err != nil {
		log.Fatalf("failed to compute signing hash: %v", err)
	}
	fmt.Printf("SigningHash: 0x%s\n", hex.EncodeToString(signingHash[:]))
	sig, err := crypto.Sign(priv, signingHash[:])
	if err != nil {
		log.Fatalf("Sign failed: %v", err)
	}
	tx.Signature = sig
	fmt.Printf("Signature: %d bytes\n", len(sig))

	// Local verification
	pubKey, err := crypto.PublicKeyFromBytes(pkBytes)
	if err != nil {
		log.Fatalf("PublicKeyFromBytes failed: %v", err)
	}
	verified := crypto.Verify(pubKey, signingHash[:], sig)
	fmt.Printf("Local signature verify: %v\n", verified)
	if !verified {
		log.Fatal("Local signature verification FAILED!")
	}

	// Address derivation check
	derivedAddr := crypto.PublicKeyAddressFromBytes(pkBytes)
	fmt.Printf("Derived addr: 0x%s\n", hex.EncodeToString(derivedAddr[:]))
	fmt.Printf("TX From:      0x%s\n", hex.EncodeToString(tx.From[:]))
	if derivedAddr != tx.From {
		log.Fatal("Address mismatch!")
	}

	// Marshal
	rawBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		log.Fatalf("Marshal failed: %v", err)
	}
	rawHex := "0x" + hex.EncodeToString(rawBytes)
	fmt.Printf("Raw TX: %d bytes\n", len(rawBytes))

	// Round-trip: unmarshal and verify
	rtTx, err := encoding.UnmarshalTransaction(rawBytes)
	if err != nil {
		log.Fatalf("Round-trip unmarshal failed: %v", err)
	}
	rtSigHash, err := rtTx.SigningHash()
	if err != nil {
		log.Fatalf("failed to compute RT signing hash: %v", err)
	}
	fmt.Printf("RT SigningHash: 0x%s\n", hex.EncodeToString(rtSigHash[:]))
	if rtSigHash != signingHash {
		log.Fatal("Round-trip signing hash MISMATCH!")
	}
	rtVerified := crypto.Verify(pubKey, rtSigHash[:], rtTx.Signature)
	fmt.Printf("Round-trip signature verify: %v\n", rtVerified)

	// Send
	txHash, err := rpcSendRaw(rawHex)
	if err != nil {
		log.Fatalf("Send failed: %v", err)
	}
	fmt.Printf("TX hash: %s\n", txHash)
	fmt.Printf("DONE: %s QAU sent to %s\n", amountStr, targetAddrStr)
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func rpcCall(method string, params []interface{}) (json.RawMessage, error) {
	reqBody, _ := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})

	resp, err := http.Post(rpcURL, "application/json", strings.NewReader(string(reqBody))) //nolint:gosec // G107: rpcURL is the CLI's own --rpc argument (user-supplied by design)
	if err != nil {
		return nil, fmt.Errorf("rpc call: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var rpcResp rpcResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("rpc: %s", rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

func rpcGetNonce(addr types.Address) (uint64, error) {
	addrHex := "0x" + hex.EncodeToString(addr[:])
	result, err := rpcCall("eth_getTransactionCount", []interface{}{addrHex, "latest"})
	if err != nil {
		return 0, err
	}
	var hexStr string
	if err := json.Unmarshal(result, &hexStr); err != nil {
		return 0, fmt.Errorf("nonce parse: %w", err)
	}
	nonce, ok := new(big.Int).SetString(strings.TrimPrefix(hexStr, "0x"), 16)
	if !ok {
		return 0, fmt.Errorf("invalid nonce: %s", hexStr)
	}
	return nonce.Uint64(), nil
}

func rpcGetChainID() (uint64, error) {
	result, err := rpcCall("eth_chainId", []interface{}{})
	if err != nil {
		return 0, err
	}
	var hexStr string
	if err := json.Unmarshal(result, &hexStr); err != nil {
		return 0, fmt.Errorf("chainID parse: %w", err)
	}
	chainID, ok := new(big.Int).SetString(strings.TrimPrefix(hexStr, "0x"), 16)
	if !ok {
		return 0, fmt.Errorf("invalid chainID: %s", hexStr)
	}
	return chainID.Uint64(), nil
}

func rpcSendRaw(rawHex string) (string, error) {
	result, err := rpcCall("eth_sendRawTransaction", []interface{}{rawHex})
	if err != nil {
		return "", err
	}
	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return "", fmt.Errorf("txHash parse: %w", err)
	}
	return txHash, nil
}
