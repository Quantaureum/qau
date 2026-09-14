// Quantaureum Node source, version 1.0.0.
// airdrop: Quantaureum mainnet airdrop batch sender.
//
// Pulls pending registrations (status=pending/approved) from the website's
// airdrop admin API, signs transfer transactions locally with a Dilithium3
// key, submits them via eth_sendRawTransaction, and writes the txHash back
// to the website once confirmed.
//
// Usage:
//
//	AIRDROP_ADMIN_KEY=<key> airdrop -keyfile <dilithium3 key file> -chain <chainID> -rpc <RPC URL> -site <site API base URL>
//
// Common flags:
//
//	-limit  max registrations per run (default 200)
//	-dry-run print the pending list only; no signing, no sending
//	-confirm-timeout seconds to wait for a receipt (default 30)
//
// Environment variables (overridden by same-name flags):
//
//	AIRDROP_KEY_FILE / AIRDROP_RPC_URL / AIRDROP_CHAIN_ID / AIRDROP_SITE_URL / AIRDROP_ADMIN_KEY
//
// Security note: the key file and AIRDROP_ADMIN_KEY belong on the payout
// server (127.0.0.1 environments) only — never commit them. The website side
// (guard.ts) requires an admin JWT or X-Admin-Key on the admin endpoints.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type config struct {
	keyFile        string
	chainID        uint64
	rpcURL         string
	siteURL        string
	adminKey       string
	limit          int
	dryRun         bool
	confirmTimeout time.Duration
}

func loadConfig() config {
	var c config

	envOr := func(name, def string) string {
		if v := os.Getenv(name); v != "" {
			return v
		}
		return def
	}

	flag.StringVar(&c.keyFile, "keyfile", envOr("AIRDROP_KEY_FILE", ""), "path to the Dilithium3 private key file")
	flag.Uint64Var(&c.chainID, "chain", 0, "chain ID (decimal)")
	flag.StringVar(&c.rpcURL, "rpc", envOr("AIRDROP_RPC_URL", "http://localhost:8545"), "node JSON-RPC endpoint")
	flag.StringVar(&c.siteURL, "site", envOr("AIRDROP_SITE_URL", "http://localhost:3000"), "website API base URL")
	flag.StringVar(&c.adminKey, "adminkey", "", "deprecated and rejected; set AIRDROP_ADMIN_KEY env var")
	flag.IntVar(&c.limit, "limit", 200, "max registrations to process in one run")
	flag.BoolVar(&c.dryRun, "dry-run", false, "print the pending list only, do not send")
	flag.DurationVar(&c.confirmTimeout, "confirm-timeout", 30*time.Second, "timeout waiting for a receipt")

	flag.Parse()

	if c.chainID == 0 {
		if v := os.Getenv("AIRDROP_CHAIN_ID"); v != "" {
			var id uint64
			fmt.Sscanf(v, "%d", &id)
			c.chainID = id
		}
	}
	if c.chainID == 0 {
		fatal("chain ID required: -chain <chainID> or AIRDROP_CHAIN_ID")
	}
	if c.keyFile == "" {
		fatal("key file required: -keyfile <path> or AIRDROP_KEY_FILE")
	}
	flagWasSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "adminkey" {
			flagWasSet = true
		}
	})
	if flagWasSet {
		fatal("-adminkey is rejected: argv is visible in process listings; set AIRDROP_ADMIN_KEY env var")
	}
	c.adminKey = os.Getenv("AIRDROP_ADMIN_KEY")
	if c.adminKey == "" && !c.dryRun {
		fatal("admin key required: set AIRDROP_ADMIN_KEY env var (not needed for dry-run)")
	}
	return c
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "airdrop: "+format+"\n", args...)
	os.Exit(1)
}

// ---------------------------------------------------------------------------
// Signing and submission (same construction as cmd/transfer)
// ---------------------------------------------------------------------------

type signer struct {
	priv        *crypto.PrivateKey
	pubKey      []byte
	fromAddr    types.Address
	fromHex     string
	chainID     uint64
	rpcURL      string
	nextNonce   uint64
	qauDecimals *big.Int
}

func newSigner(keyFile string, chainID uint64, rpcURL string) (*signer, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	line := strings.TrimSpace(string(data))
	if strings.HasPrefix(line, "dilithium3:") {
		line = strings.TrimPrefix(line, "dilithium3:")
	}
	privHex := strings.SplitN(line, ":", 2)[0]
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	privKey, err := crypto.PrivateKeyFromBytes(privBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	pubKey := privKey.PublicKey()
	fromAddr := pubKey.Address()

	s := &signer{
		priv:        privKey,
		pubKey:      pubKey.Bytes(),
		fromAddr:    fromAddr,
		fromHex:     fromAddr.ToHexAddress(),
		chainID:     chainID,
		rpcURL:      rpcURL,
		qauDecimals: new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil),
	}

	// Seed the nonce counter from the chain.
	nonce, err := s.fetchNonce()
	if err != nil {
		return nil, fmt.Errorf("fetch nonce: %w", err)
	}
	s.nextNonce = nonce

	balance, err := s.fetchBalance()
	if err != nil {
		return nil, fmt.Errorf("fetch balance: %w", err)
	}
	fmt.Printf("payout account: %s\n", s.fromHex)
	fmt.Printf("account balance: %s wei\n", balance.String())
	return s, nil
}

func (s *signer) fetchNonce() (uint64, error) {
	var res struct {
		Result string `json:"result"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := rpcJSON(s.rpcURL, "eth_getTransactionCount",
		[]any{s.fromHex, "latest"}, &res); err != nil {
		return 0, err
	}
	if res.Error.Message != "" {
		return 0, fmt.Errorf("RPC error: %s", res.Error.Message)
	}
	var n uint64
	if _, err := fmt.Sscanf(strings.TrimPrefix(res.Result, "0x"), "%x", &n); err != nil {
		return 0, fmt.Errorf("parse nonce %q: %w", res.Result, err)
	}
	return n, nil
}

func (s *signer) fetchBalance() (*big.Int, error) {
	var res struct {
		Result string `json:"result"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := rpcJSON(s.rpcURL, "eth_getBalance",
		[]any{s.fromHex, "latest"}, &res); err != nil {
		return nil, err
	}
	if res.Error.Message != "" {
		return nil, fmt.Errorf("RPC error: %s", res.Error.Message)
	}
	bal, ok := new(big.Int).SetString(strings.TrimPrefix(res.Result, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("parse balance %q", res.Result)
	}
	return bal, nil
}

// sendTransfer builds, signs, and submits one transfer; it returns the tx
// hash once the node accepts the transaction.
func (s *signer) sendTransfer(to types.Address, amountQau *big.Int) (string, error) {
	amountWei := new(big.Int).Mul(amountQau, s.qauDecimals)

	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    s.nextNonce,
		From:     s.fromAddr,
		To:       &to,
		Value:    amountWei,
		GasLimit: 21000,
		GasPrice: big.NewInt(1), // same as cmd/transfer: 1 wei
		ChainID:  s.chainID,
	}

	signingHash, err := tx.SigningHash()
	if err != nil {
		return "", fmt.Errorf("signing hash: %w", err)
	}
	sig, err := crypto.Sign(s.priv, signingHash[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	tx.Signature = sig
	tx.PublicKey = s.pubKey

	txBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		return "", fmt.Errorf("marshal tx: %w", err)
	}

	var res struct {
		Result string `json:"result"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := rpcJSON(s.rpcURL, "eth_sendRawTransaction",
		[]any{"0x" + hex.EncodeToString(txBytes)}, &res); err != nil {
		return "", err
	}
	if res.Error.Message != "" {
		// Nonce-related errors here mean the local counter drifted from
		// the chain; the caller can re-sync and retry.
		return "", fmt.Errorf("RPC error: %s", res.Error.Message)
	}
	if res.Result == "" {
		return "", fmt.Errorf("node returned no transaction hash")
	}

	txHash := tx.Hash().String()
	s.nextNonce++
	return txHash, nil
}

// waitForReceipt polls for the receipt and reports whether the tx was
// confirmed on chain with status 0x1.
func (s *signer) waitForReceipt(txHash string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var res struct {
			Result json.RawMessage `json:"result"`
		}
		if err := rpcJSON(s.rpcURL, "eth_getTransactionReceipt",
			[]any{txHash}, &res); err == nil {
			var receipt struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(res.Result, &receipt) == nil && receipt.Status != "" {
				return receipt.Status == "0x1"
			}
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// ---------------------------------------------------------------------------
// Website admin API client
// ---------------------------------------------------------------------------

type pendingItem struct {
	ID            int    `json:"id"`
	UserID        string `json:"userId"`
	WalletAddress string `json:"walletAddress"`
	Amount        int    `json:"amount"`
}

func siteRequest(siteURL, path, adminKey, method string, body any, out any) error {
	url := strings.TrimSuffix(siteURL, "/") + path
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if adminKey != "" {
		req.Header.Set("X-Admin-Key", adminKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func rpcJSON(url, method string, params []any, out any) error {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// ---------------------------------------------------------------------------
// Main flow
// ---------------------------------------------------------------------------

func main() {
	cfg := loadConfig()

	// 1. Pull the pending list.
	var pending struct {
		Success       bool          `json:"success"`
		Count         int           `json:"count"`
		Registrations []pendingItem `json:"registrations"`
	}
	if err := siteRequest(cfg.siteURL, "/api/airdrop/admin/pending?limit="+
		fmt.Sprint(cfg.limit), cfg.adminKey, "GET", nil, &pending); err != nil {
		fatal("failed to fetch pending registrations: %v", err)
	}
	if !pending.Success {
		fatal("website returned a failure status")
	}
	if len(pending.Registrations) == 0 {
		fmt.Println("no pending registrations.")
		return
	}

	fmt.Printf("pending: %d registration(s)\n", len(pending.Registrations))
	total := new(big.Int)
	for _, r := range pending.Registrations {
		fmt.Printf("  #%d  %s  %d QAU\n", r.ID, r.WalletAddress, r.Amount)
		total.Add(total, big.NewInt(int64(r.Amount)))
	}
	fmt.Printf("total: %s QAU\n", total.String())

	if cfg.dryRun {
		fmt.Println("(dry-run — nothing sent)")
		return
	}

	// 2. Initialize the signer (validates key/nonce/balance).
	s, err := newSigner(cfg.keyFile, cfg.chainID, cfg.rpcURL)
	if err != nil {
		fatal("failed to initialize signer: %v", err)
	}

	// Balance pre-check: total payout (wei) must fit within 95% of the
	// balance, keeping a 5% reserve for gas and operational margin.
	need := new(big.Int).Mul(total, s.qauDecimals)
	bal, err := s.fetchBalance()
	if err != nil {
		fatal("failed to query balance: %v", err)
	}
	ceiling := new(big.Int).Div(new(big.Int).Mul(bal, big.NewInt(95)), big.NewInt(100))
	if need.Cmp(ceiling) > 0 {
		fatal("insufficient balance: need %s wei, account holds %s wei (5%% reserve included)",
			need.String(), bal.String())
	}

	// 3. Pay out one registration at a time.
	var sentOK, sentFail int
	var failures []map[string]any
	for _, r := range pending.Registrations {
		to, err := types.ParseAddressWithFallback(r.WalletAddress)
		if err != nil {
			fmt.Printf("  ✗ #%d invalid address %s: %v\n", r.ID, r.WalletAddress, err)
			failures = append(failures, map[string]any{"id": r.ID, "note": "invalid address: " + err.Error()})
			sentFail++
			continue
		}

		txHash, err := s.sendTransfer(to, big.NewInt(int64(r.Amount)))
		if err != nil {
			fmt.Printf("  ✗ #%d send failed: %v\n", r.ID, err)
			failures = append(failures, map[string]any{"id": r.ID, "note": "send failed: " + err.Error()})
			sentFail++
			continue
		}
		fmt.Printf("  → #%d submitted %s, waiting for confirmation...\n", r.ID, txHash)

		if !s.waitForReceipt(txHash, cfg.confirmTimeout) {
			fmt.Printf("  ✗ #%d receipt timeout (tx %s state unknown — resolve manually)\n", r.ID, txHash)
			failures = append(failures, map[string]any{"id": r.ID, "note": "receipt timeout, tx " + txHash})
			sentFail++
			continue
		}

		// 4. Write the txHash back to the website.
		if err := siteRequest(cfg.siteURL, "/api/airdrop/admin/record",
			cfg.adminKey, "POST", map[string]any{"id": r.ID, "txHash": txHash}, nil); err != nil {
			fmt.Printf("  ⚠ #%d on chain but write-back failed (tx %s): %v — record manually\n", r.ID, txHash, err)
			// An on-chain transfer is never rolled back when the write-back
			// fails; resolve manually, and mark the record as sent before
			// re-running so it is not paid twice.
			sentFail++
			continue
		}
		fmt.Printf("  ✓ #%d done: %d QAU → %s (tx %s)\n", r.ID, r.Amount, r.WalletAddress, txHash)
		sentOK++
	}

	// 5. Batch write-back of failure reasons.
	if len(failures) > 0 {
		if err := siteRequest(cfg.siteURL, "/api/airdrop/admin/record",
			cfg.adminKey, "POST", map[string]any{"failures": failures}, nil); err != nil {
			fmt.Printf("⚠ failed to write back failure reasons: %v\n", err)
		}
	}

	fmt.Printf("\ndone: %d sent / %d failed / %d total\n", sentOK, sentFail, len(pending.Registrations))
	if sentFail > 0 {
		os.Exit(1)
	}
}
