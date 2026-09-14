// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"bytes"
	"encoding/json"
	"math/big"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// transfer signs a transfer transaction using a dilithium3 key file and submits via RPC.
//
// Usage: transfer <keyfile> <to_address> <amount_qau> <chain_id> <rpc_url>

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "Usage: transfer <keyfile> <to_address> <amount_qau> <chain_id> [rpc_url]")
		os.Exit(1)
	}

	keyFile := os.Args[1]
	toAddrStr := os.Args[2]
	amountStr := os.Args[3]
	chainIDStr := os.Args[4]
	rpcURL := "http://localhost:8545"
	if len(os.Args) > 5 {
		rpcURL = os.Args[5]
	}

	chainID, err := strconv.ParseUint(chainIDStr, 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid chain ID: %v\n", err)
		os.Exit(1)
	}

	// Read key file
	data, err := ioutil.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read key file: %v\n", err)
		os.Exit(1)
	}

	line := strings.TrimSpace(string(data))
	if strings.HasPrefix(line, "dilithium3:") {
		line = strings.TrimPrefix(line, "dilithium3:")
	}

	parts := strings.Split(line, ":")
	if len(parts) < 1 {
		fmt.Fprintln(os.Stderr, "invalid key format")
		os.Exit(1)
	}

	privHex := parts[0]
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode private key: %v\n", err)
		os.Exit(1)
	}

	privKey, err := crypto.PrivateKeyFromBytes(privBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse private key: %v\n", err)
		os.Exit(1)
	}

	pubKey := privKey.PublicKey()
	fromAddr := pubKey.Address()
	pubKeyBytes := pubKey.Bytes()

	fromHex := fromAddr.ToHexAddress()
	fmt.Printf("From: %s\n", fromHex)

	// Parse to address
	toAddr, err := types.ParseAddressWithFallback(toAddrStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid to address: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("To: %s\n", toAddr.ToHexAddress())

	// Parse amount (QAU decimal -> wei).
	// AUDIT (2026) KEYS-13 FIX: Previously used float64 then int64(amountFloat),
	// which truncated any fractional QAU to 0 wei (e.g. 0.5 QAU → 0 wei) and lost
	// precision beyond ~15 significant digits. Now parse the decimal string
	// directly with pure integer math so 18-decimal QAU values are exact.
	amountWei, err := parseQauAmountToWei(amountStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid amount: %v\n", err)
		os.Exit(1)
	}

	// Fetch nonce
	nonce, err := fetchNonce(rpcURL, fromHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch nonce: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Nonce: %d\n", nonce)

	// Build transaction
	gasLimit := uint64(21000)
	gasPrice := big.NewInt(1) // 1 wei

	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    nonce,
		From:     fromAddr,
		To:       &toAddr,
		Value:    amountWei,
		GasLimit: gasLimit,
		GasPrice: gasPrice,
		Data:     nil,
		ChainID:  chainID,
	}

	// Sign
	signingHash, err := tx.SigningHash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "compute signing hash: %v\n", err)
		os.Exit(1)
	}

	signature, err := crypto.Sign(privKey, signingHash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}

	tx.Signature = signature
	tx.PublicKey = pubKeyBytes

	// Marshal
	txBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal transaction: %v\n", err)
		os.Exit(1)
	}

	txHex := "0x" + hex.EncodeToString(txBytes)
	txHash := tx.Hash()
	fmt.Printf("Tx Hash: %s\n", txHash.String())

	// Submit via RPC
	result, err := sendRawTx(rpcURL, txHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "send raw tx: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Send result: %s\n", result)
}

func fetchNonce(rpcURL, addrHex string) (uint64, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["%s","latest"],"id":1}`, addrHex)
	resp, err := http.Post(rpcURL, "application/json", bytes.NewBufferString(body)) //nolint:gosec // G107: rpcURL is the CLI's own --rpc argument (user-supplied by design)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Result string `json:"result"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}
	if result.Error.Message != "" {
		return 0, fmt.Errorf("RPC error: %s", result.Error.Message)
	}

	hexNonce := strings.TrimPrefix(result.Result, "0x")
	nonce, err := strconv.ParseUint(hexNonce, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parse nonce %s: %v", hexNonce, err)
	}
	return nonce, nil
}

func sendRawTx(rpcURL, txHex string) (string, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["%s"],"id":1}`, txHex)
	resp, err := http.Post(rpcURL, "application/json", bytes.NewBufferString(body)) //nolint:gosec // G107: rpcURL is the CLI's own --rpc argument (user-supplied by design)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return string(result), nil
}

// parseQauAmountToWei converts a decimal QAU string (e.g. "0.5", "10.25",
// "123") to wei using pure integer math.
//
// AUDIT (2026) KEYS-13 FIX: Replaces the previous float64-based parsing
// that truncated fractional QAU and lost precision for 18-decimal values.
// Accepts an optional "0x" prefix to mean raw hex wei (no scaling). Rejects
// negative values, empty strings, and values with more than 18 fractional
// digits (sub-wei precision is not representable on chain).
func parseQauAmountToWei(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return new(big.Int), nil
	}
	if s[0] == '-' {
		return nil, fmt.Errorf("negative amount: %q", s)
	}

	// 0x prefix → raw hex wei, no scaling.
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		hexStr := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
		val := new(big.Int)
		if _, ok := val.SetString(hexStr, 16); !ok {
			return nil, fmt.Errorf("invalid hex amount: %q", s)
		}
		return val, nil
	}

	// Integer QAU (no decimal point): parse and multiply by 10^18.
	if !strings.ContainsRune(s, '.') {
		wei := new(big.Int)
		if _, ok := wei.SetString(s, 10); !ok {
			return nil, fmt.Errorf("invalid integer amount: %q", s)
		}
		return wei.Mul(wei, big.NewInt(1e18)), nil
	}

	// Decimal QAU: split, pad fractional part to 18 digits, concatenate.
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid decimal amount: %q", s)
	}
	intPart, fracPart := parts[0], parts[1]
	if intPart == "" && fracPart == "" {
		return nil, fmt.Errorf("invalid decimal amount: %q", s)
	}
	if len(fracPart) > 18 {
		return nil, fmt.Errorf("too many fractional digits (%d > 18): %q",
			len(fracPart), s)
	}
	paddedFrac := fracPart + strings.Repeat("0", 18-len(fracPart))
	combined := strings.TrimLeft(intPart+paddedFrac, "0")
	if combined == "" {
		return new(big.Int), nil
	}
	wei := new(big.Int)
	if _, ok := wei.SetString(combined, 10); !ok {
		return nil, fmt.Errorf("invalid decimal amount: %q", s)
	}
	return wei, nil
}
