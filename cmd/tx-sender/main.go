// Quantaureum Node source, version 1.0.0.
// Transaction Sender for Quantaureum 24h Stress Test
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

type TestAccount struct {
	Address    string `json:"address"`
	PrivateKey string `json:"private_key"`
	Balance    string `json:"balance"`
}

type DevAccounts struct {
	Accounts []TestAccount `json:"accounts"`
}

type RPCResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *RPCError       `json:"error"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var (
	rpcURL   = flag.String("rpc", "http://localhost:8545", "RPC URL")
	dataDir  = flag.String("data", "./data", "Data directory")
	duration = flag.Int("duration", 24, "Duration in hours")
	tpm      = flag.Int("tpm", 10, "Transactions per minute")
)

func main() {
	flag.Parse()

	accounts, err := loadAccounts(*dataDir)
	if err != nil {
		fmt.Printf("Failed to load accounts: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %d accounts\n", len(accounts))

	// Security fix (Round 4): zeroize all account private keys on exit, preventing keys from lingering in memory.
	defer func() {
		for _, acc := range accounts {
			acc.Zeroize()
		}
	}()

	endTime := time.Now().Add(time.Duration(*duration) * time.Hour)
	delay := time.Minute / time.Duration(*tpm)

	var sent, success, failed int
	txIdx := 0

	fmt.Printf("Starting %dh stress test at %d tx/min\n", *duration, *tpm)

	for time.Now().Before(endTime) {
		fromIdx := txIdx % len(accounts)
		toIdx := (txIdx + 1) % len(accounts)

		txHash, err := sendTransaction(accounts[fromIdx], accounts[toIdx].Address.String())
		sent++

		if err != nil {
			failed++
			// Only log every 10th failure to reduce noise
			if failed%10 == 1 {
				fmt.Printf("[%s] TX #%d FAILED: %v\n", time.Now().Format("15:04:05"), sent, err)
			}
		} else {
			success++
			if sent%10 == 0 {
				fmt.Printf("[%s] TX #%d OK: %s (success rate: %.1f%%)\n",
					time.Now().Format("15:04:05"), sent, txHash[:18], float64(success)/float64(sent)*100)
			}
		}

		txIdx++
		time.Sleep(delay)
	}

	fmt.Printf("\n=== Final Results ===\n")
	fmt.Printf("Sent: %d, Success: %d, Failed: %d\n", sent, success, failed)
	fmt.Printf("Success Rate: %.2f%%\n", float64(success)/float64(sent)*100)
}

type LoadedAccount struct {
	Address    types.Address
	PrivateKey *crypto.PrivateKey
	PublicKey  *crypto.PublicKey
	Nonce      uint64
}

// Zeroize zeroes the account's private-key memory, preventing keys from lingering.
// Security fix (Round 4): previously private keys stayed resident in memory throughout the 24-hour stress test,
// and were not zeroed at exit — a memory-dump attack risk.
func (a *LoadedAccount) Zeroize() {
	if a == nil || a.PrivateKey == nil {
		return
	}
	a.PrivateKey.Zeroize()
	a.PrivateKey = nil
}

func loadAccounts(dataDir string) ([]*LoadedAccount, error) {
	data, err := os.ReadFile(dataDir + "/dev_accounts.json") // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, err
	}

	var devAccounts DevAccounts
	if err := json.Unmarshal(data, &devAccounts); err != nil {
		return nil, err
	}

	var accounts []*LoadedAccount
	for _, acc := range devAccounts.Accounts {
		keyHex := strings.TrimPrefix(acc.PrivateKey, "0x")
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil {
			continue
		}

		privKey, err := crypto.PrivateKeyFromBytes(keyBytes)
		// AUDIT (2026) KEYS-14: Wipe intermediate keyBytes immediately
		// after conversion to PrivateKey. Previously keyBytes (4000 bytes of
		// raw Dilithium3 private key) remained in memory for the entire 24h
		// stress test duration.
		crypto.ZeroBytesSecure(keyBytes)
		if err != nil {
			continue
		}

		pubKey := privKey.PublicKey()
		accounts = append(accounts, &LoadedAccount{
			Address:    pubKey.Address(),
			PrivateKey: privKey,
			PublicKey:  pubKey,
			Nonce:      0,
		})
	}

	return accounts, nil
}

func sendTransaction(from *LoadedAccount, toAddr string) (string, error) {
	// Get nonce from network
	nonce, err := getNonce(from.Address.String())
	if err != nil {
		// If network fails, use cached nonce
		nonce = from.Nonce
	}

	// Always use the higher nonce to avoid "nonce too low"
	if from.Nonce > nonce {
		nonce = from.Nonce
	}

	// Parse to address
	to, err := types.ParseAddress(toAddr)
	if err != nil {
		return "", err
	}

	// Create transaction - send random amount between 0.001 and 1 QAU
	// 1 QAU = 10^18 wei
	randomAmount := big.NewInt(0)
	randomAmount.SetString("1000000000000000", 10) // 0.001 QAU base
	// Safe: nonce % 1000 is always 0-999, then +1 gives 1-1000 range
	safeNonce := nonce % 1000
	multiplier := big.NewInt(int64(safeNonce) + 1) //nolint:gosec,G115
	randomAmount.Mul(randomAmount, multiplier)

	tx := &encoding.Transaction{
		Version:   1,
		Type:      encoding.TxTypeTransfer,
		From:      from.Address,
		To:        &to,
		Nonce:     nonce,
		GasLimit:  21000,
		GasPrice:  big.NewInt(1000000000), // 1 Gwei
		Value:     randomAmount,
		PublicKey: from.PublicKey.Bytes(),
		ChainID:   1669,
	}

	// Sign
	sigHash, err := tx.SigningHash()
	if err != nil {
		return "", err
	}
	sig, err := crypto.Sign(from.PrivateKey, sigHash[:])
	if err != nil {
		return "", err
	}
	tx.Signature = sig

	// Serialize
	txData, err := encoding.MarshalTransaction(tx)
	if err != nil {
		return "", err
	}

	// Send
	txHash, err := sendRawTransaction(txData)
	if err != nil {
		return "", err
	}

	from.Nonce = nonce + 1
	return txHash, nil
}

func getNonce(addr string) (uint64, error) {
	// Convert QAU address to hex format for RPC
	hexAddr := addr
	if strings.HasPrefix(addr, "QAU") {
		// Parse QAU address and convert to hex
		parsedAddr, err := types.ParseAddress(addr)
		if err != nil {
			return 0, fmt.Errorf("invalid address: %v", err)
		}
		hexAddr = "0x" + hex.EncodeToString(parsedAddr[:])
	}

	// Security: Use proper JSON encoding to prevent JSON injection
	type RPCRequest struct {
		JSONRPC string   `json:"jsonrpc"`
		Method  string   `json:"method"`
		Params  []string `json:"params"`
		ID      int      `json:"id"`
	}
	reqBody, err := json.Marshal(RPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_getTransactionCount",
		Params:  []string{hexAddr, "pending"},
		ID:      1,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to marshal RPC request: %w", err)
	}
	resp, err := http.Post(*rpcURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var rpcResp RPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return 0, err
	}

	if rpcResp.Error != nil {
		return 0, errors.New(rpcResp.Error.Message)
	}

	var nonceHex string
	if err := json.Unmarshal(rpcResp.Result, &nonceHex); err != nil {
		return 0, fmt.Errorf("failed to parse nonce from RPC response: %w", err)
	}
	nonceHex = strings.TrimPrefix(nonceHex, "0x")

	// Parse hex string to uint64
	nonce, err := parseHexUint64(nonceHex)
	if err != nil {
		return 0, err
	}
	return nonce, nil
}

func parseHexUint64(s string) (uint64, error) {
	var result uint64
	for _, c := range s {
		result <<= 4
		switch {
		case c >= '0' && c <= '9':
			result |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			result |= uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			result |= uint64(c - 'A' + 10)
		default:
			return 0, fmt.Errorf("invalid hex char: %c", c)
		}
	}
	return result, nil
}

func sendRawTransaction(txData []byte) (string, error) {
	txHex := "0x" + hex.EncodeToString(txData)

	// Security: Use proper JSON encoding to prevent JSON injection
	type RPCRequest struct {
		JSONRPC string   `json:"jsonrpc"`
		Method  string   `json:"method"`
		Params  []string `json:"params"`
		ID      int      `json:"id"`
	}
	reqBody, err := json.Marshal(RPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_sendRawTransaction",
		Params:  []string{txHex},
		ID:      1,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal RPC request: %w", err)
	}
	resp, err := http.Post(*rpcURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var rpcResp RPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return "", err
	}

	if rpcResp.Error != nil {
		return "", errors.New(rpcResp.Error.Message)
	}

	var txHash string
	if err := json.Unmarshal(rpcResp.Result, &txHash); err != nil {
		return "", fmt.Errorf("failed to parse tx hash from RPC response: %w", err)
	}
	return txHash, nil
}
