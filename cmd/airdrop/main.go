// Quantaureum Node source, version 1.0.0.
// airdrop: Quantaureum mainnet airdrop batch sender (distributor side of the
// three-phase payout protocol).
//
// Per registration the distributor drives:
//
//	reserve   POST /api/airdrop/admin/reserve {id} — atomically claim the row
//	          (the website's conditional UPDATE is the single-payment
//	          guarantee; 409 = another distributor holds it → skip, never pay)
//	commit    build + sign + broadcast the commit tx (nonce N), wait receipt
//	reveal    sign the reveal tx (nonce N+1) but DO NOT broadcast yet
//	intent    POST /api/airdrop/admin/record {id, phase:"intent", txHash, nonce}
//	          — the reveal hash is stored BEFORE the reveal is broadcast, so
//	          a crash in between can be reconciled against the chain instead
//	          of paying the address a second time
//	broadcast eth_sendRawTransaction the reveal tx, wait for a 0x1 receipt
//	paid      POST /api/airdrop/admin/record {id, phase:"paid", txHash} —
//	          written only after the receipt confirmed the transfer
//	failed    POST /api/airdrop/admin/record {id, phase:"failed", note} —
//	          releases the reservation with a retry backoff
//
// Stuck rows (reserved/broadcast with no confirmed receipt, e.g. from a
// crashed run) are reconciled at startup: a 0x1 receipt is written back as
// paid; an unrecoverable state is released for a later attempt.
//
// Pre-flight guards: eth_chainId must equal -chain, and when -expect-address
// is set the payout key must derive exactly that address (catches a stale
// key file or a mis-pointed RPC before a single transaction is signed).
//
// Usage:
//
//	AIRDROP_ADMIN_KEY=<key> airdrop -keyfile <dilithium3 key> -chain 1668 \
//	  -rpc http://127.0.0.1:8545 -site https://quantaureum.com \
//	  -expect-address 0x… [-limit 50]
//
// Flags:
//
//	-keyfile          path to the Dilithium3 key file
//	-chain            chain ID (decimal)
//	-rpc              node JSON-RPC endpoint (the local validator; never the
//	                 public query node)
//	-site             website API base URL
//	-limit            max registrations per run (default 200)
//	-dry-run          print the pending list only; no signing, no sending,
//	                 no reserving
//	-confirm-timeout  timeout waiting for a receipt (default 30s)
//	-reconcile-grace  minimum age of a stuck reservation before it is
//	                 reconciled (default 30m; skips rows a live run owns)
//	-expect-address   payout account must derive this address (0x-prefixed)
//	-lockfile         single-instance lock (default <tempdir>/qau-airdrop.lock)
//	-batch            pay a CSV (address,amountQau[,memo]) instead of the
//	                 website pending list (tier-B tranches; no site calls)
//
// Env vars (overridden by same-name flags): AIRDROP_KEY_FILE, AIRDROP_RPC_URL,
// AIRDROP_CHAIN_ID, AIRDROP_SITE_URL, AIRDROP_ADMIN_KEY, AIRDROP_EXPECT_ADDRESS.
// The key file and the admin key belong on the payout server only — never
// commit them.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
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
	expectAddress  string
	limit          int
	dryRun         bool
	batchFile      string
	confirmTimeout time.Duration
	reconcileGrace time.Duration
	lockFile       string
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
	flag.StringVar(&c.rpcURL, "rpc", envOr("AIRDROP_RPC_URL", "http://127.0.0.1:8545"), "node JSON-RPC endpoint (local validator)")
	flag.StringVar(&c.siteURL, "site", envOr("AIRDROP_SITE_URL", "http://127.0.0.1:3000"), "website API base URL")
	flag.StringVar(&c.adminKey, "adminkey", "", "deprecated and rejected; set AIRDROP_ADMIN_KEY env var")
	flag.StringVar(&c.expectAddress, "expect-address", envOr("AIRDROP_EXPECT_ADDRESS", ""), "payout account must derive this address (0x-prefixed)")
	flag.IntVar(&c.limit, "limit", 200, "max registrations to process in one run")
	flag.BoolVar(&c.dryRun, "dry-run", false, "print the pending list only; no signing, no sending, no reserving")
	flag.StringVar(&c.batchFile, "batch", envOr("AIRDROP_BATCH_FILE", ""), "pay a CSV file (address,amountQau[,memo]) instead of the website pending list")
	flag.DurationVar(&c.confirmTimeout, "confirm-timeout", 30*time.Second, "timeout waiting for a receipt")
	flag.DurationVar(&c.reconcileGrace, "reconcile-grace", 30*time.Minute, "min age of a stuck reservation before it is reconciled")
	flag.StringVar(&c.lockFile, "lockfile", filepath.Join(os.TempDir(), "qau-airdrop.lock"), "single-instance lock file")

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
	if c.keyFile == "" && !c.dryRun {
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
	if c.expectAddress != "" && !strings.HasPrefix(c.expectAddress, "0x") {
		fatal("-expect-address must be a 0x-prefixed address")
	}
	return c
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "airdrop: "+format+"\n", args...)
	os.Exit(1)
}

// ---------------------------------------------------------------------------
// HTTP clients (timeouts bounded so one hung endpoint cannot stall a batch)
// ---------------------------------------------------------------------------

var (
	rpcClient  = &http.Client{Timeout: 15 * time.Second}
	siteClient = &http.Client{Timeout: 30 * time.Second}
)

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
	// The private key is always the leading half of the blob; the public
	// half (re-derivable below) may follow a ':' or a '+' separator
	// (dev_export_keys writes one, the node's key extractor the other), or
	// be absent entirely. Take exactly the private-key hex prefix so all
	// three layouts parse identically.
	privHexLen := crypto.Dilithium3PrivateKeySize * 2 // 8000 hex chars
	if len(line) < privHexLen {
		return nil, fmt.Errorf("key file too short: %d hex chars, want at least %d", len(line), privHexLen)
	}
	privHex := line[:privHexLen]
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	// Wipe the decoded key material once the parsed key owns a copy.
	defer func() { _ = crypto.ZeroBytesSecure(privBytes) }()
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
	if err := rpcJSON(rpcClient, s.rpcURL, "eth_getTransactionCount",
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
// may have consumed the commit nonce. Otherwise the next commit reuses a
// consumed nonce and every following payment in the batch fails. When the RPC
// is unreachable, advance past the commit nonce as a best effort.
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
	if err := rpcJSON(rpcClient, s.rpcURL, "eth_getBalance",
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

// checkChainID fails pre-flight when the node serves a different chain — a
// mis-pointed RPC would otherwise replay the whole batch against the wrong
// network.
func (s *signer) checkChainID() error {
	var res struct {
		Result string `json:"result"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := rpcJSON(rpcClient, s.rpcURL, "eth_chainId", []any{}, &res); err != nil {
		return fmt.Errorf("chain pre-flight: %w", err)
	}
	if res.Error.Message != "" {
		return fmt.Errorf("chain pre-flight RPC error: %s", res.Error.Message)
	}
	got, err := strconv.ParseUint(strings.TrimPrefix(res.Result, "0x"), 16, 64)
	if err != nil {
		return fmt.Errorf("chain pre-flight: parse %q: %w", res.Result, err)
	}
	if got != s.chainID {
		return fmt.Errorf("chain pre-flight: node reports chain id %d, expected %d", got, s.chainID)
	}
	return nil
}

// buildPair constructs the unsigned commit-reveal pair. The commit-reveal
// flow is mandatory for transfers at or above the txpool threshold (10 QAU —
// any payout qualifies):
//
//	① commit tx  (TxTypeCommit, nonce N, To=zero, Data=SHA3(to‖value‖salt))
//	② wait for the commit to be included, then for MinRevealBlocks to pass
//	③ reveal tx  (TxTypeTransfer, nonce N+1, Data=32-byte salt)
func (s *signer) buildPair(to types.Address, amountWei *big.Int) (commit, reveal *encoding.Transaction, err error) {
	salt := make([]byte, txpool.CRV2SaltLen)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("generate reveal salt: %w", err)
	}
	commitHash := txpool.ComputeCommitHash(to, amountWei, salt)
	zeroAddr := types.Address{}
	commit = &encoding.Transaction{
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
	reveal = &encoding.Transaction{
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
	return commit, reveal, nil
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
	if err := rpcJSON(rpcClient, s.rpcURL, "eth_sendRawTransaction",
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
		if err := rpcJSON(rpcClient, s.rpcURL, "eth_blockNumber", []any{}, &res); err == nil && strings.HasPrefix(res.Result, "0x") {
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
		if err := rpcJSON(rpcClient, s.rpcURL, "eth_getTransactionReceipt",
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

// receiptStatus checks the receipt ONCE (no polling): used by the reconciler
// to decide what to do with a row whose transaction was recorded but whose
// fate was not. ok=false means no receipt is available yet.
func (s *signer) receiptStatus(txHash string) (ok bool, succeeded bool) {
	var res struct {
		Result json.RawMessage `json:"result"`
	}
	if err := rpcJSON(rpcClient, s.rpcURL, "eth_getTransactionReceipt",
		[]any{txHash}, &res); err != nil {
		return false, false
	}
	var receipt struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(res.Result, &receipt) != nil || receipt.Status == "" {
		return false, false
	}
	return true, receipt.Status == "0x1"
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
	code, err := siteRequestStatus(siteURL, path, adminKey, method, body, out)
	if err == nil && code >= 300 {
		return fmt.Errorf("site HTTP %d", code)
	}
	return err
}

// siteRequestStatus performs the call and reports the HTTP status so callers
// can branch on "not reservable" (409) without parsing the body.
func siteRequestStatus(siteURL, path, adminKey, method string, body any, out any) (int, error) {
	url := strings.TrimSuffix(siteURL, "/") + path
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if adminKey != "" {
		req.Header.Set("X-Admin-Key", adminKey)
	}
	resp, err := siteClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func rpcJSON(client *http.Client, url, method string, params []any, out any) error {
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
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(buf)) // #nosec G107 -- URL comes from operator flags, not request input
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// ---------------------------------------------------------------------------
// Single-instance lock
// ---------------------------------------------------------------------------

// acquireLock creates an exclusive lock file so two runs never pay the same
// batch concurrently. A lock older than 2h is treated as an abandoned
// crashed run and taken over.
func acquireLock(path string) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	const staleAfter = 2 * time.Hour
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create lock file: %w", err)
		}
		if st, statErr := os.Stat(path); statErr == nil && time.Since(st.ModTime()) > staleAfter {
			// Abandoned by a crashed run: take over and continue.
			_ = os.Remove(path)
			f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return nil, fmt.Errorf("take over stale lock: %w", err)
			}
		} else {
			return nil, fmt.Errorf("another airdrop run holds %s (delete the file if that run is dead)", path)
		}
	}
	_, _ = fmt.Fprintf(f, "pid %d at %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	_ = f.Close()
	return func() { _ = os.Remove(path) }, nil
}

// ---------------------------------------------------------------------------
// Website mode: fetch pending + reserve
// ---------------------------------------------------------------------------

// pendingPull fetches the payable queue. A nil row with a nil error means the
// registration could not be claimed — another distributor owns it.
func pendingPull(cfg config) ([]payoutItem, error) {
	var pending struct {
		Success       bool          `json:"success"`
		Count         int           `json:"count"`
		Registrations []pendingItem `json:"registrations"`
	}
	if err := siteRequest(cfg.siteURL, "/api/airdrop/admin/pending?limit="+
		fmt.Sprint(cfg.limit), cfg.adminKey, "GET", nil, &pending); err != nil {
		return nil, fmt.Errorf("fetch pending registrations: %w", err)
	}
	if !pending.Success {
		return nil, errors.New("website returned a failure status")
	}
	items := make([]payoutItem, 0, len(pending.Registrations))
	for _, r := range pending.Registrations {
		items = append(items, payoutItem{
			Label:   fmt.Sprintf("#%d", r.ID),
			Address: r.WalletAddress,
			Amount:  r.Amount,
			SiteID:  r.ID,
		})
	}
	return items, nil
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
	SiteID  int // >0 only in website mode: enables the protocol write-back
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

// outcome classifies one payment for the batch summary.
type outcome int

const (
	outPaid    outcome = iota
	outSkipped         // already claimed by another distributor
	outFailed          // released back to the queue with a note
	outUnknown         // state on the chain is uncertain; the reconciler resolves it
)

// payItem runs the full reserve → commit → intent → reveal → paid protocol
// for one website registration. Batch items (SiteID==0) skip the website
// calls and run the commit-reveal flow directly.
func payItem(s *signer, cfg config, it payoutItem) outcome {
	if it.SiteID > 0 {
		// Reserve BEFORE any chain interaction: the conditional UPDATE on the
		// website is the single-payment guarantee. A 409 means another
		// distributor holds the row — skip it, never pay it.
		var reg struct {
			Success      bool `json:"success"`
			Registration struct {
				ID            int    `json:"id"`
				WalletAddress string `json:"walletAddress"`
				Amount        int    `json:"amount"`
			} `json:"registration"`
		}
		code, err := siteRequestStatus(cfg.siteURL, "/api/airdrop/admin/reserve",
			cfg.adminKey, "POST", map[string]any{"id": it.SiteID}, &reg)
		if err != nil {
			if code == 409 {
				fmt.Printf("  - %s already claimed — skipped\n", it.Label)
				return outSkipped
			}
			fmt.Printf("  x %s reserve failed: %v\n", it.Label, err)
			// Reserve transport failure: the row was not claimed, so a plain
			// note (no release needed) keeps the audit trail honest.
			failItem(cfg, it.SiteID, "reserve failed: "+err.Error())
			return outFailed
		}
		// Use the authoritative address/amount the website returned at claim
		// time rather than the pre-reserve snapshot.
		if reg.Registration.WalletAddress != "" {
			it.Address = reg.Registration.WalletAddress
		}
		if reg.Registration.Amount > 0 {
			it.Amount = reg.Registration.Amount
		}
	}

	to, err := types.ParseAddressWithFallback(it.Address)
	if err != nil {
		fmt.Printf("  x %s invalid address %s: %v\n", it.Label, it.Address, err)
		if it.SiteID > 0 {
			failItem(cfg, it.SiteID, "invalid address: "+err.Error())
		}
		return outFailed
	}
	amountWei := new(big.Int).Mul(big.NewInt(int64(it.Amount)), s.qauDecimals)

	commit, reveal, err := s.buildPair(to, amountWei)
	if err != nil {
		fmt.Printf("  x %s build pair: %v\n", it.Label, err)
		if it.SiteID > 0 {
			failItem(cfg, it.SiteID, "build pair: "+err.Error())
		}
		return outFailed
	}

	if err := s.signTx(commit); err != nil {
		s.resyncNonce()
		fmt.Printf("  x %s sign commit: %v\n", it.Label, err)
		if it.SiteID > 0 {
			failItem(cfg, it.SiteID, "sign commit: "+err.Error())
		}
		return outFailed
	}
	if _, err := s.sendRaw(commit); err != nil {
		// The commit may still have been accepted — resync so the next
		// payment does not reuse a consumed nonce.
		s.resyncNonce()
		fmt.Printf("  x %s send commit: %v\n", it.Label, err)
		if it.SiteID > 0 {
			failItem(cfg, it.SiteID, "send commit: "+err.Error())
		}
		return outFailed
	}
	commitHash := commit.Hash().String()
	ok, commitBlock := s.waitForReceipt(commitHash, s.confirmTimeout)
	if !ok {
		s.resyncNonce()
		fmt.Printf("  x %s commit tx %s not confirmed in time\n", it.Label, commitHash)
		if it.SiteID > 0 {
			failItem(cfg, it.SiteID, "commit not confirmed, tx "+commitHash)
		}
		return outFailed
	}

	// MinRevealBlocks is 1 on this network: the reveal must land at least
	// one block after the commit's inclusion block.
	if err := s.waitBlock(commitBlock+1, s.confirmTimeout); err != nil {
		// The commit nonce is consumed but the reveal was never broadcast;
		// resync so the next payment does not reuse it.
		s.resyncNonce()
		fmt.Printf("  x %s reveal window: %v\n", it.Label, err)
		if it.SiteID > 0 {
			failItem(cfg, it.SiteID, "reveal window: "+err.Error())
		}
		return outFailed
	}

	if err := s.signTx(reveal); err != nil {
		s.resyncNonce()
		fmt.Printf("  x %s sign reveal: %v\n", it.Label, err)
		if it.SiteID > 0 {
			failItem(cfg, it.SiteID, "sign reveal: "+err.Error())
		}
		return outFailed
	}
	revealHash := reveal.Hash().String()

	if it.SiteID > 0 {
		// Record the intent BEFORE broadcasting the reveal: a crash in
		// between leaves a row whose transaction hash can be checked against
		// the chain instead of an unmarked payment.
		if err := siteRequest(cfg.siteURL, "/api/airdrop/admin/record", cfg.adminKey,
			"POST", map[string]any{"id": it.SiteID, "phase": "intent",
				"txHash": "0x" + revealHash, "nonce": reveal.Nonce}, nil); err != nil {
			fmt.Printf("  x %s record intent: %v (reveal not broadcast)\n", it.Label, err)
			failItem(cfg, it.SiteID, "record intent: "+err.Error())
			s.resyncNonce()
			return outFailed
		}
	}

	if _, err := s.sendRaw(reveal); err != nil {
		// The node may have accepted the reveal even though the submit errored;
		// the intent is already recorded with the reveal hash, so the
		// reconciler — not this run — gets the final say. Do NOT release:
		// releasing could re-queue an address whose reveal is already on chain.
		s.resyncNonce()
		fmt.Printf("  ! %s broadcast reveal: %v — left in-flight for reconciliation (tx %s)\n",
			it.Label, err, revealHash)
		return outUnknown
	}

	fmt.Printf("  -> %s submitted %s, waiting for confirmation...\n", it.Label, revealHash)
	confirmed, _ := s.waitForReceipt(revealHash, cfg.confirmTimeout)
	if !confirmed {
		// The receipt was not observed in time. The reveal hash is on record
		// (intent), so the reconciler settles it — do not release, the funds
		// may still move. The reveal nonce is likely consumed, so refresh.
		s.resyncNonce()
		fmt.Printf("  ! %s receipt timeout (tx %s) — left in-flight for reconciliation\n", it.Label, revealHash)
		return outUnknown
	}

	if it.SiteID > 0 {
		if err := siteRequest(cfg.siteURL, "/api/airdrop/admin/record",
			cfg.adminKey, "POST", map[string]any{"id": it.SiteID, "phase": "paid",
				"txHash": "0x" + revealHash}, nil); err != nil {
			// On chain but the write-back failed: the row stays in the
			// broadcast state and the reconciler marks it paid next run. The
			// reveal nonce was consumed, so refresh the cursor.
			s.resyncNonce()
			fmt.Printf("  ! %s paid on chain but write-back failed (tx %s): %v\n", it.Label, revealHash, err)
			return outUnknown
		}
	}
	s.nextNonce += 2
	fmt.Printf("  v %s done: %d QAU -> %s (tx %s)\n", it.Label, it.Amount, it.Address, revealHash)
	return outPaid
}

// failItem writes a single failure back to the website (the failed phase
// releases the reservation with a backoff and keeps the reason for audit).
func failItem(cfg config, id int, note string) {
	_ = siteRequest(cfg.siteURL, "/api/airdrop/admin/record",
		cfg.adminKey, "POST", map[string]any{"id": id, "phase": "failed", "note": note}, nil)
}

func main() {
	cfg := loadConfig()

	var items []payoutItem

	if cfg.batchFile != "" {
		batch, err := readBatchCSV(cfg.batchFile)
		if err != nil {
			fatal("bad batch file: %v", err)
		}
		items = batch
		fmt.Printf("batch: %d payment(s) from %s\n", len(items), cfg.batchFile)
	}

	if cfg.batchFile == "" {
		// Website mode only: fetch the queue, then settle whatever a previous
		// run left in flight before paying anything new.
		var err error
		items, err = pendingPull(cfg)
		if err != nil {
			fatal("%v", err)
		}
	}

	if len(items) == 0 {
		fmt.Println("no pending registrations.")
		return
	}

	total := new(big.Int)
	for _, it := range items {
		fmt.Printf("  %s  %s  %d QAU\n", it.Label, it.Address, it.Amount)
		total.Add(total, big.NewInt(int64(it.Amount)))
	}
	fmt.Printf("total: %s QAU\n", total.String())

	if cfg.dryRun {
		fmt.Println("(dry-run — nothing sent, nothing reserved)")
		return
	}

	unlock, err := acquireLock(cfg.lockFile)
	if err != nil {
		fatal("%v", err)
	}
	defer unlock()

	// Initialize the signer (validates key/nonce/balance) and pre-flight.
	s, err := newSigner(cfg.keyFile, cfg.chainID, cfg.rpcURL, cfg.confirmTimeout)
	if err != nil {
		fatal("failed to initialize signer: %v", err)
	}
	if cfg.expectAddress != "" && !strings.EqualFold(cfg.expectAddress, s.fromHex) {
		fatal("payout address mismatch: key derives %s, expected %s", s.fromHex, cfg.expectAddress)
	}
	if err := s.checkChainID(); err != nil {
		fatal("%v", err)
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

	// Website mode: settle stuck rows from crashed runs before paying new
	// ones, so a row that actually confirmed gets marked paid exactly once.
	if cfg.batchFile == "" && cfg.adminKey != "" {
		reconcileStuck(s, cfg)
	}

	// 3. Pay out one item at a time.
	var nPaid, nSkipped, nFailed, nUnknown int
	for _, it := range items {
		switch payItem(s, cfg, it) {
		case outPaid:
			nPaid++
		case outSkipped:
			nSkipped++
		case outFailed:
			nFailed++
		case outUnknown:
			nUnknown++
		}
	}

	fmt.Printf("\ndone: %d paid / %d skipped / %d failed / %d in-flight / %d total\n",
		nPaid, nSkipped, nFailed, nUnknown, len(items))
	if nFailed > 0 {
		os.Exit(1)
	}
}
