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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	batchFile      string
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
	flag.StringVar(&c.batchFile, "batch", envOr("AIRDROP_BATCH_FILE", ""), "pay a CSV file (address,amountQau[,memo]) instead of the website pending list")
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
	// Batch mode never talks to the website, so it needs no admin key.
	if c.adminKey == "" && !c.dryRun && c.batchFile == "" {
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
	priv           *crypto.PrivateKey
	pubKey         []byte
	fromAddr       types.Address
	fromHex        string
	chainID        uint64
	rpcURL         string
	nextNonce      uint64
	qauDecimals    *big.Int
	confirmTimeout time.Duration
}

func newSigner(keyFile string, chainID uint64, rpcURL string, confirmTimeout time.Duration) (*signer, error) {
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
	// F-10: wipe the decoded key material once the parsed key owns a copy.
	defer func() { _ = crypto.ZeroBytesSecure(privBytes) }()
	// Accept qaud/dev_export_keys style priv+pub concatenated keyfiles: when
	// the blob is exactly privSize+pubSize long, the public half is redundant
	// (re-derived from the private key below) and dropped.
	if len(privBytes) == crypto.Dilithium3PrivateKeySize+crypto.Dilithium3PublicKeySize {
		privBytes = privBytes[:crypto.Dilithium3PrivateKeySize]
	}
	privKey, err := crypto.PrivateKeyFromBytes(privBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	pubKey := privKey.PublicKey()
	fromAddr := pubKey.Address()

	s := &signer{
		priv:           privKey,
		pubKey:         pubKey.Bytes(),
		fromAddr:       fromAddr,
		fromHex:        fromAddr.ToHexAddress(),
		chainID:        chainID,
		rpcURL:         rpcURL,
		qauDecimals:    new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil),
		confirmTimeout: confirmTimeout,
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
	// "pending" includes accepted-but-unmined transactions, so a resync after
	// an ambiguous submit does not hand out a nonce that is already in flight.
	if err := rpcJSON(s.rpcURL, "eth_getTransactionCount",
		[]any{s.fromHex, "pending"}, &res); err != nil {
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

// resyncNonce refreshes the local cursor from the chain after a failure that
// may have consumed the commit nonce (R2-09). Otherwise the next commit reuses
// a consumed nonce and every following payment in the batch fails. When the
// RPC is unreachable, advance past the commit nonce as a best effort.
func (s *signer) resyncNonce() {
	if nonce, err := s.fetchNonce(); err == nil {
		if nonce > s.nextNonce {
			s.nextNonce = nonce
		}
		return
	}
	s.nextNonce++
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

// sendTransfer pays one registration using the chain's commit-reveal
// (front-running protection) flow, which is mandatory for transfers at or
// above the txpool threshold (10 QAU — any payout qualifies):
//
//	① commit tx  (TxTypeCommit, nonce N, To=zero, Data=SHA3(to‖value‖salt))
//	② wait for the commit to be included, then for MinRevealBlocks to pass
//	③ reveal tx  (TxTypeTransfer, nonce N+1, Data=32-byte salt)
//
// Returns the REVEAL tx hash (the tx that moves the funds) once the node
// accepts it; the caller confirms the receipt before writing it back.
func (s *signer) sendTransfer(to types.Address, amountQau *big.Int) (string, error) {
	amountWei := new(big.Int).Mul(amountQau, s.qauDecimals)

	salt := make([]byte, txpool.CRV2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate reveal salt: %w", err)
	}

	commitHash := txpool.ComputeCommitHash(to, amountWei, salt)
	zeroAddr := types.Address{}

	commitTx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeCommit,
		Nonce:    s.nextNonce,
		From:     s.fromAddr,
		To:       &zeroAddr,
		Value:    big.NewInt(0),
		GasLimit: 40000,
		GasPrice: big.NewInt(1),
		Data:     commitHash[:],
		ChainID:  s.chainID,
	}
	if err := s.signTx(commitTx); err != nil {
		return "", fmt.Errorf("sign commit: %w", err)
	}
	commitAccepted, err := s.sendRaw(commitTx)
	if err != nil {
		return "", fmt.Errorf("send commit: %w", err)
	}

	ok, commitBlock := s.waitForReceipt(commitAccepted.Hash().String(), s.confirmTimeout)
	if !ok {
		// The commit was accepted, so its nonce is consumed even though the
		// receipt is unknown; resync before the next payment.
		s.resyncNonce()
		return "", fmt.Errorf("commit tx %s not confirmed in time", commitAccepted.Hash().String())
	}

	// MinRevealBlocks is 1 on this network: the reveal must land at least
	// one block after the commit's inclusion block.
	if err := s.waitBlock(commitBlock+1, s.confirmTimeout); err != nil {
		return "", fmt.Errorf("waiting reveal window: %w", err)
	}

	revealTx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    s.nextNonce + 1,
		From:     s.fromAddr,
		To:       &to,
		Value:    amountWei,
		GasLimit: 40000,
		GasPrice: big.NewInt(1),
		Data:     salt,
		ChainID:  s.chainID,
	}
	if err := s.signTx(revealTx); err != nil {
		s.resyncNonce()
		return "", fmt.Errorf("sign reveal: %w", err)
	}
	if _, err := s.sendRaw(revealTx); err != nil {
		// The commit nonce is consumed; the reveal may or may not have been
		// accepted. Resync from the chain so the batch can continue.
		s.resyncNonce()
		return "", fmt.Errorf("send reveal: %w", err)
	}

	txHash := revealTx.Hash().String()
	s.nextNonce += 2
	return txHash, nil
}

// signTx signs a transaction with the payout Dilithium3 key.
func (s *signer) signTx(tx *encoding.Transaction) error {
	signingHash, err := tx.SigningHash()
	if err != nil {
		return fmt.Errorf("signing hash: %w", err)
	}
	sig, err := crypto.Sign(s.priv, signingHash[:])
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	tx.Signature = sig
	tx.PublicKey = s.pubKey
	return nil
}

// sendRaw marshals and submits one signed transaction via eth_sendRawTransaction.
func (s *signer) sendRaw(tx *encoding.Transaction) (*encoding.Transaction, error) {
	txBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		return nil, fmt.Errorf("marshal tx: %w", err)
	}
	var res struct {
		Result string `json:"result"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := rpcJSON(s.rpcURL, "eth_sendRawTransaction",
		[]any{"0x" + hex.EncodeToString(txBytes)}, &res); err != nil {
		return nil, err
	}
	if res.Error.Message != "" {
		return nil, fmt.Errorf("RPC error: %s", res.Error.Message)
	}
	if res.Result == "" {
		return nil, fmt.Errorf("node returned no transaction hash")
	}
	return tx, nil
}

// waitBlock waits until the chain head reaches height h (or the timeout).
func (s *signer) waitBlock(h uint64, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var res struct {
			Result string `json:"result"`
		}
		if err := rpcJSON(s.rpcURL, "eth_blockNumber", []any{}, &res); err == nil && strings.HasPrefix(res.Result, "0x") {
			if n, err := strconv.ParseUint(res.Result[2:], 16, 64); err == nil && n >= h {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for block %d", h)
}

// waitForReceipt polls for the receipt and reports whether the tx was
// confirmed on chain with status 0x1, plus the inclusion block number (0
// when unknown).
func (s *signer) waitForReceipt(txHash string, timeout time.Duration) (bool, uint64) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var res struct {
			Result json.RawMessage `json:"result"`
		}
		if err := rpcJSON(s.rpcURL, "eth_getTransactionReceipt",
			[]any{txHash}, &res); err == nil {
			var receipt struct {
				Status      string `json:"status"`
				BlockNumber string `json:"blockNumber"`
			}
			if json.Unmarshal(res.Result, &receipt) == nil && receipt.Status != "" {
				var incl uint64
				if strings.HasPrefix(receipt.BlockNumber, "0x") {
					if n, err := strconv.ParseUint(receipt.BlockNumber[2:], 16, 64); err == nil {
						incl = n
					}
				}
				return receipt.Status == "0x1", incl
			}
		}
		time.Sleep(2 * time.Second)
	}
	return false, 0
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
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(buf)) // #nosec G107 -- URL comes from operator flags, not request input
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// ---------------------------------------------------------------------------
// Main flow
// ---------------------------------------------------------------------------

// payoutItem is the normalized per-payment record the payout loop consumes.
// Website mode fills Label with the registration ID; batch mode fills it with
// the CSV memo (or address#amount when no memo is given).
type payoutItem struct {
	Label   string
	Address string
	Amount  int
	SiteID  int // >0 only in website mode: enables the txHash write-back
}

// readBatchCSV parses a payout CSV: one payment per line,
// "address,amountQau[,memo]". Blank lines and #-comments are skipped. Any
// malformed row stops the run — a typo'd payout file must never pay partially.
func readBatchCSV(path string) ([]payoutItem, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var items []payoutItem
	for ln, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			return nil, fmt.Errorf("batch line %d: want address,amount[,memo], got %q", ln+1, line)
		}
		addr := strings.TrimSpace(fields[0])
		if !strings.HasPrefix(addr, "0x") {
			return nil, fmt.Errorf("batch line %d: address %q must be 0x-prefixed", ln+1, addr)
		}
		amount, err := strconv.Atoi(strings.TrimSpace(fields[1]))
		if err != nil || amount <= 0 {
			return nil, fmt.Errorf("batch line %d: amount %q must be a positive integer", ln+1, fields[1])
		}
		label := fmt.Sprintf("%s#%d", addr, amount)
		if len(fields) >= 3 && strings.TrimSpace(fields[2]) != "" {
			label = strings.TrimSpace(fields[2])
		}
		items = append(items, payoutItem{Label: label, Address: addr, Amount: amount})
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("batch file %s contains no payable rows", path)
	}
	// Reject duplicate addresses: tier-B tranches are one row per address per
	// run by construction, and a duplicated paste must never double-pay.
	seen := make(map[string]bool)
	for _, it := range items {
		a := strings.ToLower(it.Address)
		if seen[a] {
			return nil, fmt.Errorf("batch file lists %s more than once", it.Address)
		}
		seen[a] = true
	}
	return items, nil
}

func main() {
	cfg := loadConfig()

	var items []payoutItem

	if cfg.batchFile != "" {
		// Batch mode (tier-B tranches and any offline-approved payouts):
		// same signer, same commit-reveal send path; no website interaction.
		batch, err := readBatchCSV(cfg.batchFile)
		if err != nil {
			fatal("bad batch file: %v", err)
		}
		items = batch
		fmt.Printf("batch: %d payment(s) from %s\n", len(items), cfg.batchFile)
	}

	// 1. Pull the pending list (website mode only; batch mode filled items above).
	var pending struct {
		Success       bool          `json:"success"`
		Count         int           `json:"count"`
		Registrations []pendingItem `json:"registrations"`
	}
	if cfg.batchFile == "" {
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
		for _, r := range pending.Registrations {
			items = append(items, payoutItem{
				Label:   fmt.Sprintf("#%d", r.ID),
				Address: r.WalletAddress,
				Amount:  r.Amount,
				SiteID:  r.ID,
			})
		}
		fmt.Printf("pending: %d registration(s)\n", len(items))
	}

	total := new(big.Int)
	for _, it := range items {
		fmt.Printf("  %s  %s  %d QAU\n", it.Label, it.Address, it.Amount)
		total.Add(total, big.NewInt(int64(it.Amount)))
	}
	fmt.Printf("total: %s QAU\n", total.String())

	if cfg.dryRun {
		fmt.Println("(dry-run — nothing sent)")
		return
	}

	// 2. Initialize the signer (validates key/nonce/balance).
	s, err := newSigner(cfg.keyFile, cfg.chainID, cfg.rpcURL, cfg.confirmTimeout)
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

	// 3. Pay out one item at a time.
	var sentOK, sentFail int
	var failures []map[string]any
	for _, it := range items {
		to, err := types.ParseAddressWithFallback(it.Address)
		if err != nil {
			fmt.Printf("  x %s invalid address %s: %v\n", it.Label, it.Address, err)
			failures = append(failures, map[string]any{"id": it.SiteID, "note": "invalid address: " + err.Error()})
			sentFail++
			continue
		}

		txHash, err := s.sendTransfer(to, big.NewInt(int64(it.Amount)))
		if err != nil {
			fmt.Printf("  x %s send failed: %v\n", it.Label, err)
			failures = append(failures, map[string]any{"id": it.SiteID, "note": "send failed: " + err.Error()})
			sentFail++
			continue
		}
		fmt.Printf("  -> %s submitted %s, waiting for confirmation...\n", it.Label, txHash)

		ok, _ := s.waitForReceipt(txHash, cfg.confirmTimeout)
		if !ok {
			fmt.Printf("  x %s receipt timeout (tx %s state unknown - resolve manually)\n", it.Label, txHash)
			failures = append(failures, map[string]any{"id": it.SiteID, "note": "receipt timeout, tx " + txHash})
			sentFail++
			continue
		}

		// 4. Website mode: write the txHash back. Batch mode has no website
		// record — the reconciler archives (label, address, amount, txHash)
		// from this run's output instead. The site validates the EVM-style
		// 0x-prefixed form, while tx.Hash().String() returns bare 64-hex.
		if it.SiteID > 0 {
			if err := siteRequest(cfg.siteURL, "/api/airdrop/admin/record",
				cfg.adminKey, "POST", map[string]any{"id": it.SiteID, "txHash": "0x" + txHash}, nil); err != nil {
				fmt.Printf("  ! %s on chain but write-back failed (tx %s): %v - record manually\n", it.Label, txHash, err)
				sentFail++
				continue
			}
		}
		fmt.Printf("  v %s done: %d QAU -> %s (tx %s)\n", it.Label, it.Amount, it.Address, txHash)
		sentOK++
	}

	// 5. Batch write-back of failure reasons (website mode only).
	if len(failures) > 0 && cfg.batchFile == "" {
		if err := siteRequest(cfg.siteURL, "/api/airdrop/admin/record",
			cfg.adminKey, "POST", map[string]any{"failures": failures}, nil); err != nil {
			fmt.Printf("! failed to write back failure reasons: %v\n", err)
		}
	}

	fmt.Printf("\ndone: %d sent / %d failed / %d total\n", sentOK, sentFail, len(items))
	if sentFail > 0 {
		os.Exit(1)
	}
}
