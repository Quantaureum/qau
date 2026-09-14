// Quantaureum Node source, version 1.0.0.
// transfer_commit — CRV2 high-value transfer tool.
//
// CRV2 (2026-08-26): the commit is now an on-chain TxTypeCommit transaction.
// No HMAC secret, no QAU_COMMIT_AUTH_SECRET, no qau_submitCommitment RPC.
//
// Flow:
//
//	① Build the reveal transfer tx (nonce N+1, Data = 32-byte salt)
//	② commitHash = SHA3(recipient ‖ value ‖ salt) — must equal the node's
//	  txpool.ComputeCommitHash
//	③ Build + send the commit tx (nonce N, Data = commitHash)
//	④ Wait ≥1 block for the commitment to be included
//	⑤ Send the reveal tx (eth_sendRawTransaction)
//
// Both txs are signed and pay gas: spam is priced, identity is the sender's
// own Dilithium3 key. See docs/commit-reveal-v2-design.md.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/txpool"
	"github.com/quantaureum/qau/types"
)

// RPC endpoints. Defaults keep the historical single-node behavior; the
// per-step overrides exist to rehearse a multi-validator deployment, where the
// wallet may submit the commitment and the reveal to different nodes and the
// commitment index has to agree across them.
//
//	QAU_RPC_URL         base endpoint            (default http://localhost:8545)
//	QAU_COMMIT_RPC_URL  where the commit goes    (default: base)
//	QAU_REVEAL_RPC_URL  where the reveal goes    (default: base)
const defaultRPCURL = "http://localhost:8545"

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func baseRPCURL() string   { return envOr("QAU_RPC_URL", defaultRPCURL) }
func commitRPCURL() string { return envOr("QAU_COMMIT_RPC_URL", baseRPCURL()) }
func revealRPCURL() string { return envOr("QAU_REVEAL_RPC_URL", baseRPCURL()) }

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "Usage: transfer_commit <keyfile> <to_address> <amount_qau> <chain_id>")
		os.Exit(1)
	}

	keyFile := os.Args[1]
	toAddrStr := os.Args[2]
	amountStr := os.Args[3]
	chainIDStr := os.Args[4]

	chainID, _ := strconv.ParseUint(chainIDStr, 10, 64)

	// Read key file
	data, err := ioutil.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read key file: %v\n", err)
		os.Exit(1)
	}

	// Extract dilithium3:hex key (handles mnemonic+address prefix format)
	keyStr := string(data)
	idx := strings.Index(keyStr, "dilithium3:")
	if idx == -1 {
		fmt.Fprintf(os.Stderr, "no dilithium3: found in key file\n")
		os.Exit(1)
	}
	keyStr = keyStr[idx+len("dilithium3:"):]

	// Keep only hex chars
	var cleanHex strings.Builder
	for _, c := range keyStr {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			cleanHex.WriteRune(c)
		}
	}
	keyHex := cleanHex.String()

	const privKeyHexLen = crypto.Dilithium3PrivateKeySize * 2
	if len(keyHex) < privKeyHexLen {
		fmt.Fprintf(os.Stderr, "key too short: got %d, need %d hex chars\n", len(keyHex), privKeyHexLen)
		os.Exit(1)
	}
	privHex := keyHex[:privKeyHexLen]

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

	toAddr, err := types.ParseAddressWithFallback(toAddrStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid to address: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("To: %s\n", toAddr.ToHexAddress())

	// AUDIT (2026) KEYS-13 FIX: pure-integer decimal parsing (no float64).
	amountWei, err := parseQauAmountToWei(amountStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid amount %q: %v\n", amountStr, err)
		os.Exit(1)
	}

	nonce := fetchNonce(fromHex)
	fmt.Printf("Nonce: %d (commit), %d (reveal)\n", nonce, nonce+1)

	// ① Build the reveal transfer tx with the salt in Data.
	salt := make([]byte, 32)
	if hexSalt := os.Getenv("QAU_FIXED_SALT"); len(hexSalt) >= 64 {
		if sb, err := hex.DecodeString(hexSalt[:64]); err == nil {
			copy(salt, sb)
		}
	} else if _, err := rand.Read(salt); err != nil {
		fmt.Fprintf(os.Stderr, "generate salt: %v\n", err)
		os.Exit(1)
	}

	revealTx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    nonce + 1,
		From:     fromAddr,
		To:       &toAddr,
		Value:    amountWei,
		GasLimit: 40000, // 21000 base + 32B data (512) + margin
		GasPrice: big.NewInt(1),
		Data:     salt,
		ChainID:  chainID,
	}
	signingHash, _ := revealTx.SigningHash()
	signature, err := crypto.Sign(privKey, signingHash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign reveal: %v\n", err)
		os.Exit(1)
	}
	revealTx.Signature = signature
	revealTx.PublicKey = pubKeyBytes
	revealHash := revealTx.Hash()

	// ② commitHash = SHA3(recipient ‖ value ‖ salt).
	commitHash := txpool.ComputeCommitHash(toAddr, amountWei, salt)

	// ③ Build + send the commit tx (nonce N, Data = commitHash).
	zeroAddr := types.Address{}
	commitTx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeCommit,
		Nonce:    nonce,
		From:     fromAddr,
		To:       &zeroAddr,
		Value:    big.NewInt(0),
		GasLimit: 40000,
		GasPrice: big.NewInt(1),
		Data:     commitHash[:],
		ChainID:  chainID,
	}
	cSigningHash, _ := commitTx.SigningHash()
	cSignature, err := crypto.Sign(privKey, cSigningHash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign commit: %v\n", err)
		os.Exit(1)
	}
	commitTx.Signature = cSignature
	commitTx.PublicKey = pubKeyBytes

	commitTxHash := commitTx.Hash()
	commitTxBytes, _ := encoding.MarshalTransaction(commitTx)
	fmt.Printf("Commit tx: 0x%s (commitHash 0x%s)\n",
		hex.EncodeToString(commitTxHash[:]),
		hex.EncodeToString(commitHash[:]))
	if os.Getenv("QAU_SKIP_COMMIT") == "" {
		sendRawTransactionTo(commitRPCURL(), "0x"+hex.EncodeToString(commitTxBytes))
	} else {
		fmt.Println("(QAU_SKIP_COMMIT set — not sending the commit tx; replay test)")
	}

	// ④ Wait ≥1 block for the commitment to be on chain.
	fmt.Println("Waiting 26 seconds for the commitment to be included...")
	time.Sleep(26 * time.Second)

	// ⑤ Send the reveal tx.
	fmt.Printf("Reveal tx: 0x%s\n", hex.EncodeToString(revealHash[:]))
	revealTxBytes, _ := encoding.MarshalTransaction(revealTx)
	sendRawTransactionTo(revealRPCURL(), "0x"+hex.EncodeToString(revealTxBytes))

	// Wait for confirmation
	fmt.Println("Waiting for confirmation...")
	for i := 0; i < 15; i++ {
		time.Sleep(13 * time.Second)
		receipt := getReceipt("0x" + hex.EncodeToString(revealHash[:]))
		if receipt != nil {
			status, _ := receipt["status"].(string)
			blockNum, _ := receipt["blockNumber"].(string)
			fmt.Printf("Confirmed! status=%s block=%s\n", status, blockNum)
			if status != "0x1" {
				fmt.Println("WARNING: Transaction failed (status != 0x1)")
			}
			return
		}
		fmt.Printf("Still pending... (attempt %d)\n", i+1)
	}
	fmt.Println("Transaction not confirmed after 15 attempts")
}

func fetchNonce(addrHex string) uint64 {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["%s","latest"],"id":1}`, addrHex)
	resp, err := http.Post(baseRPCURL(), "application/json", bytes.NewBufferString(body))
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	var result struct {
		Result string `json:"result"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	hexNonce := strings.TrimPrefix(result.Result, "0x")
	if hexNonce == "" {
		return 0
	}
	n, _ := strconv.ParseUint(hexNonce, 16, 64)
	return n
}

func getReceipt(txHashHex string) map[string]interface{} {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["%s"],"id":1}`, txHashHex)
	resp, err := http.Post(baseRPCURL(), "application/json", bytes.NewBufferString(body))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if r, ok := result["result"].(map[string]interface{}); ok && r != nil {
		return r
	}
	return nil
}

func sendRawTransactionTo(endpoint, txHex string) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["%s"],"id":1}`, txHex)
	//nolint:gosec // G107: ops tool — the endpoint comes from QAU_*_RPC_URL set by
	// the operator running the rehearsal, not from untrusted input.
	resp, err := http.Post(endpoint, "application/json", bytes.NewBufferString(body))
	if err != nil {
		fmt.Printf("  send error: %v\n", err)
		return
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	fmt.Printf("  send result via %s: %v\n", endpoint, result["result"])
	if errObj, ok := result["error"]; ok && errObj != nil {
		fmt.Printf("  send error via %s: %v\n", endpoint, errObj)
	}
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
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = strings.TrimPrefix(s, "-")
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		wei := new(big.Int)
		if _, ok := wei.SetString(s[2:], 16); !ok {
			return nil, fmt.Errorf("invalid hex wei: %q", s)
		}
		if neg {
			wei.Neg(wei)
		}
		return wei, nil
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 {
		return nil, fmt.Errorf("invalid decimal amount: %q", s)
	}
	intPart, fracPart := parts[0], ""
	if len(parts) == 2 {
		fracPart = parts[1]
	}
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
	if neg {
		wei.Neg(wei)
	}
	return wei, nil
}
