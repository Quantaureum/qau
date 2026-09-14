// Quantaureum Node source, version 1.0.0.
// deploy_vest deploys 6 LinearVesting contracts on the primary node with commit-reveal
// front-running protection.
//
// Each contract is deployed by its own beneficiary account, with
// Value = full vesting allocation (so the contract holds the tokens).
// Transaction value >= 1 QAU, so commit-reveal is required.
//
// Flow per contract:
//  1. Load beneficiary key, verify address matches config
//  2. Build + sign deployment tx -> txHash
//  3. commitHash = sha256(txHash || random_secret)
//  4. CRV2: contract creation is exempt from commit-reveal — direct send
//  5. Wait for MinRevealBlocks (1 block; we wait 2 for safety)
//  6. eth_sendRawTransaction(tx)
//  7. Wait for receipt
//
// Usage:
//
//	deploy_vest <bytecode_file> <chain_id> [config.json]
//
// Config (or QAU_VESTING_CONFIG env): JSON array of
//
//	{name, key_file, beneficiary, amount_qau, cliff_secs, duration_secs}
//
// Env:
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

const (
	rpcURL       = "http://127.0.0.1:8545"
	gasForDeploy = 500000
	gasPrice     = 1
)

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}

// vestingContract is one entry of the vesting deployment config.
type vestingContract struct {
	Name         string `json:"name"`
	Beneficiary  string `json:"beneficiary"`
	KeyFile      string `json:"key_file"`
	AmountQAU    int64  `json:"amount_qau"`
	CliffSecs    int64  `json:"cliff_secs"`
	DurationSecs int64  `json:"duration_secs"`
}

func loadVestingContracts() []vestingContract {
	configPath := ""
	if len(os.Args) >= 4 && os.Args[3] != "" {
		configPath = os.Args[3]
	} else {
		configPath = os.Getenv("QAU_VESTING_CONFIG")
	}
	if configPath == "" {
		fatal("No vesting config provided. Pass as 3rd arg or set QAU_VESTING_CONFIG env var.")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		fatal("Failed to read config %s: %v", configPath, err)
	}
	var contracts []vestingContract
	if err := json.Unmarshal(data, &contracts); err != nil {
		fatal("Failed to parse config: %v", err)
	}
	if len(contracts) == 0 {
		fatal("Config contains no contracts")
	}
	return contracts
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: deploy_vest <bytecode_file> <chain_id> [config.json]\n")
		os.Exit(1)
	}
	bytecodeFile := os.Args[1]
	chainID, err := strconv.ParseUint(os.Args[2], 10, 64)
	if err != nil {
		fatal("invalid chain_id: %v", err)
	}

	bcHex, err := os.ReadFile(bytecodeFile)
	if err != nil {
		fatal("read bytecode: %v", err)
	}
	bcStr := strings.TrimSpace(string(bcHex))
	bcStr = strings.TrimPrefix(bcStr, "0x")
	bytecodeData, err := hex.DecodeString(bcStr)
	if err != nil {
		fatal("decode bytecode: %v", err)
	}

	contracts := loadVestingContracts()
	fmt.Printf("Loaded %d contracts, bytecode %d bytes, chainID %d\n",
		len(contracts), len(bytecodeData), chainID)

	results := []map[string]string{}
	for _, c := range contracts {
		addr := deployOneVesting(c, bytecodeData, chainID)
		if addr != "" {
			results = append(results, map[string]string{
				"name": c.Name, "contract_addr": addr, "beneficiary": c.Beneficiary,
				"amount_qau": fmt.Sprintf("%d", c.AmountQAU),
			})
			fmt.Printf("SUCCESS: %s -> %s\n", c.Name, addr)
		} else {
			fmt.Printf("FAILED: %s\n", c.Name)
		}
	}

	fmt.Println("\n=== Deployment Summary ===")
	for _, r := range results {
		fmt.Printf("  %-22s %s (%s QAU)\n", r["name"], r["contract_addr"], r["amount_qau"])
	}
	out, _ := json.MarshalIndent(results, "", "  ")
	//nolint:gosec // G303: deployment results deliberately at fixed /tmp path for ops scripts (R40.G), 0600 owner-only.
	os.WriteFile("/tmp/vest_deployment_results.json", out, 0600) // G306: deployment results, owner-only
	fmt.Println("\nSaved to /tmp/vest_deployment_results.json")
}

func deployOneVesting(c vestingContract, bytecodeData []byte, chainID uint64) string {
	fmt.Printf("\n%s\n", strings.Repeat("-", 60))
	fmt.Printf("Deploying %s (%s)\n", c.Name, c.Beneficiary)

	privKey, fromAddr := loadKey(c.KeyFile)
	fromHex := fromAddr.ToHexAddress()
	benefAddr, _ := types.ParseAddressWithFallback(c.Beneficiary)
	if fromAddr != benefAddr {
		fmt.Printf("  ERROR: key address %s != beneficiary %s\n", fromHex, c.Beneficiary)
		return ""
	}

	startTS := getBlockTimestamp()
	amountWei := new(big.Int).Mul(big.NewInt(c.AmountQAU), big.NewInt(1e18))
	fmt.Printf("  Beneficiary:   %s\n", c.Beneficiary)
	fmt.Printf("  Start:         %d\n", startTS)
	fmt.Printf("  Cliff:         %ds\n", c.CliffSecs)
	fmt.Printf("  Duration:      %ds\n", c.DurationSecs)
	fmt.Printf("  Amount:        %d QAU\n", c.AmountQAU)

	bal := getBalance(fromHex)
	cost := new(big.Int).Add(amountWei, big.NewInt(int64(gasForDeploy)))
	if bal.Cmp(cost) < 0 {
		fmt.Printf("  ERROR: balance %s < cost %s\n", bal.String(), cost.String())
		return ""
	}

	nonce := fetchNonce(fromHex)
	fmt.Printf("  Nonce:         %d\n", nonce)

	constructorArgs := buildConstructorArgs(c.Beneficiary, startTS, c.CliffSecs, c.DurationSecs, amountWei)
	fullBytecode := append(bytecodeData, constructorArgs...)

	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeCreate,
		Nonce:    nonce,
		From:     fromAddr,
		To:       nil,
		Value:    amountWei,
		GasLimit: gasForDeploy,
		GasPrice: big.NewInt(gasPrice),
		Data:     fullBytecode,
		ChainID:  chainID,
	}

	signingHash, err := tx.SigningHash()
	if err != nil {
		fmt.Printf("  ERROR: signingHash: %v\n", err)
		return ""
	}
	sig, err := crypto.Sign(privKey, signingHash[:])
	if err != nil {
		fmt.Printf("  ERROR: sign: %v\n", err)
		return ""
	}
	tx.Signature = sig
	tx.PublicKey = privKey.PublicKeyBytes()

	txHash := tx.Hash()
	txHashHex := "0x" + hex.EncodeToString(txHash[:])
	fmt.Printf("  Tx Hash:       %s\n", txHashHex)

	// CRV2: TxTypeCreate is exempt from the commit-reveal gate
	// (only TxTypeTransfer is gated) — send directly.
	// Submit raw tx
	txBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		fmt.Printf("  ERROR: marshal tx: %v\n", err)
		return ""
	}
	txHex := "0x" + hex.EncodeToString(txBytes)
	r := rpcCall("eth_sendRawTransaction", []string{txHex})
	if r == nil {
		fmt.Println("  ERROR: sendRawTransaction RPC nil")
		return ""
	}
	if errObj, ok := r["error"]; ok {
		fmt.Printf("  ERROR: sendRawTransaction: %v\n", errObj)
		return ""
	}
	fmt.Printf("  Send result:   %v\n", r["result"])

	// Wait for receipt
	receipt := waitForReceipt(txHashHex, 180)
	if receipt == nil {
		fmt.Println("  ERROR: no receipt after 180s")
		return ""
	}
	status, _ := receipt["status"].(string)
	contractAddr, _ := receipt["contractAddress"].(string)
	blockNum, _ := receipt["blockNumber"].(string)
	fmt.Printf("  Status:        %s\n", status)
	fmt.Printf("  Contract:      %s\n", contractAddr)
	fmt.Printf("  Block:         %s\n", blockNum)
	if status != "0x1" || contractAddr == "" {
		fmt.Println("  DEPLOYMENT FAILED")
		return ""
	}
	return contractAddr
}

func loadKey(keyFile string) (*crypto.PrivateKey, types.Address) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		fatal("read key file %s: %v", keyFile, err)
	}
	keyStr := string(data)
	idx := strings.Index(keyStr, "dilithium3:")
	if idx != -1 {
		keyStr = keyStr[idx+len("dilithium3:"):]
	}
	var cleanHex strings.Builder
	for _, c := range keyStr {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			cleanHex.WriteRune(c)
		}
	}
	keyHex := cleanHex.String()
	const privKeyHexLen = crypto.Dilithium3PrivateKeySize * 2 // 8000
	if len(keyHex) < privKeyHexLen {
		fatal("key too short in %s: got %d, need %d hex chars", keyFile, len(keyHex), privKeyHexLen)
	}
	privHex := keyHex[:privKeyHexLen]
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		fatal("decode private key from %s: %v", keyFile, err)
	}
	privKey, err := crypto.PrivateKeyFromBytes(privBytes)
	if err != nil {
		fatal("parse private key from %s: %v", keyFile, err)
	}
	pubKey := privKey.PublicKey()
	return privKey, pubKey.Address()
}

func buildConstructorArgs(beneficiary string, startTS, cliff, duration int64, amountWei *big.Int) []byte {
	addrBytes, _ := hex.DecodeString(strings.TrimPrefix(strings.ToLower(beneficiary), "0x"))
	paddedAddr := make([]byte, 32)
	copy(paddedAddr[12:], addrBytes)
	result := make([]byte, 0, 160)
	result = append(result, paddedAddr...)
	result = append(result, encodeUint256(big.NewInt(startTS))...)
	result = append(result, encodeUint256(big.NewInt(cliff))...)
	result = append(result, encodeUint256(big.NewInt(duration))...)
	result = append(result, encodeUint256(amountWei)...)
	return result
}

func encodeUint256(val *big.Int) []byte {
	padded := make([]byte, 32)
	b := val.Bytes()
	copy(padded[32-len(b):], b)
	return padded
}

func rpcCall(method string, params interface{}) map[string]interface{} {
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": method, "params": params, "id": 1,
	})
	resp, err := http.Post(rpcURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func fetchNonce(addrHex string) uint64 {
	result := rpcCall("eth_getTransactionCount", []string{addrHex, "latest"})
	if result == nil {
		return 0
	}
	hexNonce, _ := result["result"].(string)
	hexNonce = strings.TrimPrefix(hexNonce, "0x")
	if hexNonce == "" {
		return 0
	}
	n, _ := strconv.ParseUint(hexNonce, 16, 64)
	return n
}

func getBalance(addrHex string) *big.Int {
	result := rpcCall("eth_getBalance", []string{addrHex, "latest"})
	if result == nil {
		return big.NewInt(0)
	}
	hexBal, _ := result["result"].(string)
	hexBal = strings.TrimPrefix(hexBal, "0x")
	n, _ := new(big.Int).SetString(hexBal, 16)
	if n == nil {
		return big.NewInt(0)
	}
	return n
}

func getBlockNumber() uint64 {
	result := rpcCall("eth_blockNumber", []interface{}{})
	if result == nil {
		return 0
	}
	bnHex, _ := result["result"].(string)
	bnHex = strings.TrimPrefix(bnHex, "0x")
	if bnHex == "" {
		return 0
	}
	n, _ := strconv.ParseUint(bnHex, 16, 64)
	return n
}

func getBlockTimestamp() int64 {
	bn := getBlockNumber()
	result := rpcCall("eth_getBlockByNumber", []interface{}{fmt.Sprintf("0x%x", bn), false})
	if result == nil {
		return time.Now().Unix()
	}
	block, _ := result["result"].(map[string]interface{})
	if block == nil {
		return time.Now().Unix()
	}
	tsHex, _ := block["timestamp"].(string)
	tsHex = strings.TrimPrefix(tsHex, "0x")
	ts, err := strconv.ParseInt(tsHex, 16, 64)
	if err != nil || ts <= 0 {
		return time.Now().Unix()
	}
	return ts
}

func waitForReceipt(txHashHex string, timeoutSec int) map[string]interface{} {
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		result := rpcCall("eth_getTransactionReceipt", []string{txHashHex})
		if result != nil {
			if receipt, ok := result["result"].(map[string]interface{}); ok && receipt != nil {
				return receipt
			}
		}
		time.Sleep(3 * time.Second)
	}
	return nil
}
