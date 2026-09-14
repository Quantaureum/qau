// Quantaureum Node source, version 1.0.0.
// deploy_vesting_all deploys 6 LinearVesting contracts in a single run.
//
// It performs two phases:
//
//	Phase 1: Transfer gas money (0.5 QAU each) from the community account to
//	         each of the 6 vesting accounts. These transfers are < 1 QAU so
//	         commit-reveal is NOT required.
//	Phase 2: For each vesting account, sign a contract deployment transaction,
//	         submit a commitment, wait 2 blocks, then submit the raw
//	         transaction. This follows the exact same commit-reveal pattern
//	         as transfer_commit (cmd/transfer_commit/main.go).
//
// Usage:
//
//	deploy_vesting_all <community_keyfile> <bytecode_file> <chain_id> [vesting_config.json]
//
// The bytecode file should contain the pure LinearVesting bytecode (no 0x prefix,
// no constructor args). Constructor args are built internally.
//
// The optional vesting_config.json file specifies vesting accounts and parameters.
// If not provided, QAU_VESTING_CONFIG environment variable is used.
// See vesting_config.example.json for the format.
//
// Environment variables:
//
//		QAU_KEYSTORE_PASSWORD  - Password for unlocking community account
//	 (CRV2: commit-reveal auth secret removed; commitments are on-chain txs)
//		QAU_VALIDATOR_NODES    - Comma-separated SSH targets (e.g. "user@host,user@host")
//		QAU_VESTING_CONFIG     - Path to vesting config JSON (if not passed as arg)
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

const (
	rpcURL            = "http://localhost:8545"
	gasForDeploy      = 500000
	gasForTransfer    = 21000
	gasPrice          = 1
	gasTransferAmount = "500000000000000000" // 0.5 QAU in wei (< 1 QAU to bypass commit-reveal)
)

// getCommitAuthSecret reads the commit-auth HMAC secret from the
// QAU_COMMIT_AUTH_SECRET environment variable. Fails closed (fatal) if unset.

func loadValidatorNodes() []string {
	raw := os.Getenv("QAU_VALIDATOR_NODES")
	if raw == "" {
		return []string{}
	}
	var nodes []string
	for _, n := range strings.Split(raw, ",") {
		n = strings.TrimSpace(n)
		if n != "" {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// sshKeyPath returns the SSH identity file to use for peer SSH calls.
// Fails closed with a fatal error if QAU_SSH_KEY is unset and there are
// peer nodes to reach; returns "" when there are no peer nodes (so local-only
// operation never requires an SSH key).
// validatorNodes are loaded from the QAU_VALIDATOR_NODES environment variable
// as comma-separated SSH targets for optional peer RPC fan-out.
var validatorNodes = loadValidatorNodes()

func sshKeyPath() string {
	key := strings.TrimSpace(os.Getenv("QAU_SSH_KEY"))
	if key == "" && len(validatorNodes) > 0 {
		fmt.Fprintln(os.Stderr, "FATAL: QAU_SSH_KEY environment variable is not set")
		fmt.Fprintln(os.Stderr, "Set it to the path of the SSH private key authorized to reach the peer validator nodes listed in QAU_VALIDATOR_NODES.")
		os.Exit(1)
	}
	return key
}

func resultsFilePath() string {
	if path := strings.TrimSpace(os.Getenv("QAU_VESTING_RESULTS_FILE")); path != "" {
		return path
	}
	return filepath.Join(os.TempDir(), "vesting_deployment_results.json")
}

// vestingContract defines one LinearVesting deployment.
type vestingContract struct {
	Name         string `json:"name"`
	Beneficiary  string `json:"beneficiary"` // 0x... address
	KeyFile      string `json:"key_file"`
	AmountQAU    int64  `json:"amount_qau"`    // total vesting amount in QAU
	CliffSecs    int64  `json:"cliff_secs"`    // cliff duration in seconds (relative)
	DurationSecs int64  `json:"duration_secs"` // total vesting duration in seconds (relative)
}

// loadVestingContracts reads vesting config from a JSON file. The path is
// taken from the 4th CLI arg or the QAU_VESTING_CONFIG env var.
func loadVestingContracts() []vestingContract {
	configPath := ""
	// R40-DEPLOY: args layout is now: prog addr keyfile bytecode chainID [config]
	// Config path is at index 5 (optional), or via QAU_VESTING_CONFIG env var.
	if len(os.Args) >= 6 {
		configPath = os.Args[5]
	} else {
		configPath = os.Getenv("QAU_VESTING_CONFIG")
	}
	if configPath == "" {
		fatal("No vesting config provided. Pass as 4th arg or set QAU_VESTING_CONFIG env var.\n" +
			"See vesting_config.example.json for the format.")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		fatal("Failed to read vesting config %s: %v", configPath, err)
	}
	var contracts []vestingContract
	if err := json.Unmarshal(data, &contracts); err != nil {
		fatal("Failed to parse vesting config: %v", err)
	}
	return contracts
}

var vestingContracts = loadVestingContracts()

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "Usage: deploy_vesting_all <community_addr> <community_keyfile> <bytecode_file> <chain_id>\n")
		os.Exit(1)
	}

	communityAddr := os.Args[1]
	communityKeyFile := os.Args[2]
	bytecodeFile := os.Args[3]
	chainID, _ := strconv.ParseUint(os.Args[4], 10, 64)

	// Read bytecode
	bytecodeHex, err := os.ReadFile(bytecodeFile)
	if err != nil {
		fatal("Failed to read bytecode file: %v", err)
	}
	bytecodeStr := strings.TrimSpace(string(bytecodeHex))
	bytecodeStr = strings.TrimPrefix(bytecodeStr, "0x")
	bytecodeData, err := hex.DecodeString(bytecodeStr)
	if err != nil {
		fatal("Failed to decode bytecode: %v", err)
	}
	fmt.Printf("Bytecode loaded: %d bytes\n", len(bytecodeData))

	fmt.Printf("Community account: %s\n", communityAddr)

	// Load community private key for signing gas-transfer transactions
	communityPrivKey, communityFromAddr := loadKey(communityKeyFile)
	communityFromHex := communityFromAddr.ToHexAddress()
	fmt.Printf("Community key address: %s\n", communityFromHex)
	if !strings.EqualFold(communityFromHex, communityAddr) {
		fatal("Community key address %s != provided address %s", communityFromHex, communityAddr)
	}

	// ============================================================
	// Phase 1: Transfer gas money to each vesting account
	// R40-DEPLOY: Uses private-key signed raw transactions instead of
	// eth_sendTransaction, since the community key file has a raw
	// dilithium3 private key (not just mnemonic). Transfer amount is
	// 0.5 QAU which is < 1 QAU, so commit-reveal is NOT required.
	// ============================================================
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Phase 1: Transfer gas money (0.5 QAU each) via signed raw tx")
	fmt.Println(strings.Repeat("=", 60))

	communityNonce := fetchNonce(communityFromHex)
	fmt.Printf("Community nonce: %d\n", communityNonce)

	for _, vc := range vestingContracts {
		fmt.Printf("\nTransferring gas to %s (%s)...\n", vc.Name, vc.Beneficiary)

		oneQAU := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
		existingBal := getBalance(vc.Beneficiary)
		amountWei, _ := new(big.Int).SetString(gasTransferAmount, 10)
		vestingWei := new(big.Int).Mul(big.NewInt(vc.AmountQAU), big.NewInt(1e18))
		if existingBal.Cmp(new(big.Int).Add(vestingWei, oneQAU)) >= 0 {
			fmt.Printf("  Already has extra gas (%s QAU), skipping\n",
				new(big.Rat).SetFrac(existingBal, oneQAU).FloatString(2))
			continue
		}

		benefAddr, _ := types.ParseAddressWithFallback(vc.Beneficiary)

		tx := &encoding.Transaction{
			Version:  1,
			Type:     encoding.TxTypeTransfer,
			Nonce:    communityNonce,
			From:     communityFromAddr,
			To:       &benefAddr,
			Value:    amountWei,
			GasLimit: gasForTransfer,
			GasPrice: big.NewInt(gasPrice),
			Data:     nil,
			ChainID:  chainID,
		}

		signingHash, err := tx.SigningHash()
		if err != nil {
			fmt.Printf("  ERROR: signingHash: %v\n", err)
			continue
		}
		sig, err := crypto.Sign(communityPrivKey, signingHash[:])
		if err != nil {
			fmt.Printf("  ERROR: sign: %v\n", err)
			continue
		}
		tx.Signature = sig
		tx.PublicKey = communityPrivKey.PublicKeyBytes()

		txHash := tx.Hash()
		txHashHex := "0x" + hex.EncodeToString(txHash[:])
		fmt.Printf("  Tx: %s\n", txHashHex)

		txBytes, err := encoding.MarshalTransaction(tx)
		if err != nil {
			fmt.Printf("  ERROR: marshal tx: %v\n", err)
			continue
		}
		txHex := "0x" + hex.EncodeToString(txBytes)

		sendRawTransaction(txHex)
		communityNonce++

		receipt := waitForReceipt(txHashHex, 120)
		if receipt == nil {
			fmt.Printf("  ERROR: no receipt after 120s\n")
			continue
		}
		status, _ := receipt["status"].(string)
		if status != "0x1" {
			fmt.Printf("  ERROR: status=%s\n", status)
			continue
		}
		fmt.Printf("  OK (block %s)\n", receipt["blockNumber"])
	}

	// ============================================================
	// Phase 2: Deploy LinearVesting contracts
	// ============================================================
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Phase 2: Deploy LinearVesting contracts")
	fmt.Println(strings.Repeat("=", 60))

	results := []map[string]string{}

	for _, vc := range vestingContracts {
		fmt.Printf("\n%s\n", strings.Repeat("-", 60))
		fmt.Printf("Deploying %s LinearVesting\n", vc.Name)
		fmt.Printf("%s\n", strings.Repeat("-", 60))

		contractAddr := deployOneVesting(vc, bytecodeData, chainID)
		if contractAddr != "" {
			results = append(results, map[string]string{
				"name":          vc.Name,
				"contract_addr": contractAddr,
				"beneficiary":   vc.Beneficiary,
				"amount_qau":    fmt.Sprintf("%d", vc.AmountQAU),
			})
			fmt.Printf("SUCCESS: %s -> %s\n", vc.Name, contractAddr)
		} else {
			fmt.Printf("FAILED: %s\n", vc.Name)
		}
	}

	// Summary
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Deployment Summary")
	fmt.Println(strings.Repeat("=", 60))
	for _, r := range results {
		fmt.Printf("  %-20s %s (%s QAU)\n", r["name"], r["contract_addr"], r["amount_qau"])
	}

	// Save results.
	resultsJSON, _ := json.MarshalIndent(results, "", "  ")
	resultsPath := resultsFilePath()
	if err := os.WriteFile(resultsPath, resultsJSON, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: failed to save deployment results to %s: %v\n", resultsPath, err)
	} else {
		fmt.Printf("\nResults saved to %s\n", resultsPath)
	}
}

// deployOneVesting deploys a single LinearVesting contract with commit-reveal.
func deployOneVesting(vc vestingContract, bytecodeData []byte, chainID uint64) string {
	// Load account key
	privKey, fromAddr := loadKey(vc.KeyFile)
	fromHex := fromAddr.ToHexAddress()

	// Verify address matches beneficiary
	benefAddr, _ := types.ParseAddressWithFallback(vc.Beneficiary)
	if fromAddr != benefAddr {
		fmt.Printf("  ERROR: key address %s != beneficiary %s\n", fromHex, vc.Beneficiary)
		return ""
	}

	// Get current block timestamp for start
	startTS := getBlockTimestamp()
	fmt.Printf("  Beneficiary: %s\n", vc.Beneficiary)
	fmt.Printf("  Start TS:    %d\n", startTS)
	fmt.Printf("  Cliff:       %ds\n", vc.CliffSecs)
	fmt.Printf("  Duration:    %ds\n", vc.DurationSecs)
	fmt.Printf("  Amount:      %d QAU\n", vc.AmountQAU)

	// Check balance
	bal := getBalance(fromHex)
	amountWei := new(big.Int).Mul(big.NewInt(vc.AmountQAU), big.NewInt(1e18))
	cost := new(big.Int).Add(amountWei, big.NewInt(int64(gasForDeploy)))
	if bal.Cmp(cost) < 0 {
		fmt.Printf("  ERROR: balance %s < cost %s\n", bal.String(), cost.String())
		return ""
	}

	// Get nonce
	nonce := fetchNonce(fromHex)
	fmt.Printf("  Nonce:       %d\n", nonce)

	// Build constructor args: beneficiary, start, cliff, duration, totalAmount
	constructorArgs := buildConstructorArgs(vc.Beneficiary, startTS, vc.CliffSecs, vc.DurationSecs, amountWei)

	// Combine bytecode + constructor args
	fullBytecode := append(bytecodeData, constructorArgs...)

	// Build deployment transaction
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

	// Sign
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

	// Compute tx hash
	txHash := tx.Hash()
	txHashHex := "0x" + hex.EncodeToString(txHash[:])
	fmt.Printf("  Tx Hash:     %s\n", txHashHex)

	// CRV2: this tool deploys contracts (TxTypeCreate), which is exempt
	// from the commit-reveal gate — send directly, no commitment step.

	// Submit raw transaction
	txBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		fmt.Printf("  ERROR: marshal tx: %v\n", err)
		return ""
	}
	txHex := "0x" + hex.EncodeToString(txBytes)

	result := sendRawTransaction(txHex)
	if result == nil {
		fmt.Println("  ERROR: sendRawTransaction failed")
		return ""
	}
	fmt.Printf("  Send result: %v\n", result)

	// Wait for receipt
	receipt := waitForReceipt(txHashHex, 180)
	if receipt == nil {
		fmt.Println("  ERROR: no receipt after 180s")
		return ""
	}

	status, _ := receipt["status"].(string)
	contractAddr, _ := receipt["contractAddress"].(string)
	blockNum, _ := receipt["blockNumber"].(string)
	fmt.Printf("  Status:      %s\n", status)
	fmt.Printf("  Contract:    %s\n", contractAddr)
	fmt.Printf("  Block:       %s\n", blockNum)

	if status != "0x1" || contractAddr == "" {
		fmt.Println("  DEPLOYMENT FAILED!")
		return ""
	}

	return contractAddr
}

// loadKey reads a dilithium3 key file and returns the private key and derived address.
// Handles three formats:
//  1. Pure hex private key (8000 hex chars = 4000 bytes)
//  2. Bare key file (dilithium3:hex)
//  3. Full key file (mnemonic + address + dilithium3:hex)
func loadKey(keyFile string) (*crypto.PrivateKey, types.Address) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		fatal("Failed to read key file %s: %v", keyFile, err)
	}

	keyStr := string(data)
	// R38-DEPLOY FIX: Support pure hex private key format (no dilithium3: prefix)
	idx := strings.Index(keyStr, "dilithium3:")
	if idx != -1 {
		keyStr = keyStr[idx+len("dilithium3:"):]
	}
	// If no prefix found, assume pure hex and proceed directly

	// Keep only hex chars (filters out newlines, spaces, etc.)
	var cleanHex strings.Builder
	for _, c := range keyStr {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			cleanHex.WriteRune(c)
		}
	}
	keyHex := cleanHex.String()

	// Extract private key (first 8000 hex chars = 4000 bytes)
	const privKeyHexLen = crypto.Dilithium3PrivateKeySize * 2 // 8000
	if len(keyHex) < privKeyHexLen {
		fatal("Key too short in %s: got %d, need %d hex chars", keyFile, len(keyHex), privKeyHexLen)
	}
	privKeyHex := keyHex[:privKeyHexLen]

	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		fatal("Failed to decode private key from %s: %v", keyFile, err)
	}

	privKey, err := crypto.PrivateKeyFromBytes(privBytes)
	if err != nil {
		fatal("Failed to parse private key from %s: %v", keyFile, err)
	}

	pubKey := privKey.PublicKey()
	addr := pubKey.Address()
	return privKey, addr
}

// buildConstructorArgs builds the 5 x 32-byte constructor args for LinearVesting.
// Order: beneficiary, start, cliff, duration, totalAmount
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

// ============================================================
// RPC helpers
// ============================================================

func rpcCall(method string, params interface{}) map[string]interface{} {
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
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

func sendRawTransaction(txHex string) interface{} {
	// Send to the configured primary RPC endpoint.
	result := rpcCall("eth_sendRawTransaction", []string{txHex})
	if result == nil {
		fmt.Printf("  primary RPC error: nil result\n")
	} else if err, exists := result["error"]; exists {
		fmt.Printf("  primary RPC error: %v\n", err)
	} else {
		fmt.Printf("  primary result: %v\n", result["result"])
	}

	// Also fan out to configured peer RPC endpoints over SSH.
	payload, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_sendRawTransaction",
		"params":  []string{txHex},
		"id":      1,
	})
	for _, node := range validatorNodes {
		sshCmd := fmt.Sprintf(
			`curl -s -X POST http://127.0.0.1:8545 -H "Content-Type: application/json" -d '%s'`,
			string(payload),
		)
		//nolint:gosec // G204: ops tool — ssh target/args come from QAU_VALIDATOR_NODES + QAU_SSH_KEY env (R50), not untrusted input.
		cmd := exec.Command("ssh",
			"-o", "ConnectTimeout=5",
			"-i", sshKeyPath(),
			node, sshCmd,
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("  %s raw tx error: %v\n", node, err)
		} else {
			fmt.Printf("  %s raw tx result: %s\n", node, string(output))
		}
	}

	if result == nil {
		return nil
	}
	return result["result"]
}

func unlockAccount(addrHex, password string) {
	result := rpcCall("personal_unlockAccount", []string{addrHex, password, "3600"})
	if result == nil {
		fatal("Failed to unlock account %s: RPC returned nil", addrHex)
	}
	if errObj, exists := result["error"]; exists {
		fatal("Failed to unlock account %s: %v", addrHex, errObj)
	}
	fmt.Printf("Account %s unlocked\n", addrHex)
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

func getBlockTimestamp() int64 {
	result := rpcCall("eth_blockNumber", []interface{}{})
	if result == nil {
		return time.Now().Unix()
	}
	bnHex, _ := result["result"].(string)
	if bnHex == "" {
		return time.Now().Unix()
	}
	blockResult := rpcCall("eth_getBlockByNumber", []interface{}{bnHex, false})
	if blockResult == nil {
		return time.Now().Unix()
	}
	block, _ := blockResult["result"].(map[string]interface{})
	if block == nil {
		return time.Now().Unix()
	}
	tsHex, _ := block["timestamp"].(string)
	tsHex = strings.TrimPrefix(tsHex, "0x")
	if tsHex == "" {
		return time.Now().Unix()
	}
	ts, err := strconv.ParseInt(tsHex, 16, 64)
	if err != nil || ts <= 0 {
		return time.Now().Unix()
	}
	return ts
}

func waitForReceipt(txHashHex string, timeoutSec int) map[string]interface{} {
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		// Check the configured primary RPC endpoint first.
		result := rpcCall("eth_getTransactionReceipt", []string{txHashHex})
		if result != nil {
			if receipt, ok := result["result"].(map[string]interface{}); ok && receipt != nil {
				return receipt
			}
		}
		// Check configured peer RPC endpoints, which may be ahead.
		for _, node := range validatorNodes {
			sshCmd := fmt.Sprintf(
				`curl -s -X POST http://127.0.0.1:8545 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["%s"],"id":1}' --max-time 5 2>/dev/null`,
				txHashHex,
			)
			//nolint:gosec // G204: ops tool — see submitCommitment; env-driven ssh, no untrusted input.
			cmd := exec.Command("ssh",
				"-o", "ConnectTimeout=5",
				"-i", sshKeyPath(),
				node, sshCmd,
			)
			output, err := cmd.CombinedOutput()
			if err == nil {
				var remoteResult map[string]interface{}
				if json.Unmarshal(output, &remoteResult) == nil {
					if receipt, ok := remoteResult["result"].(map[string]interface{}); ok && receipt != nil {
						return receipt
					}
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
	return nil
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
