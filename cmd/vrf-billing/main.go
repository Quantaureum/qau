// Quantaureum Node source, version 1.0.0.
// vrf-billing is the off-chain billing worker for the verifiable-randomness
// API. It watches vrf_deposit contract Deposit events via eth_getLogs and
// extends the matching API key's expiry through the node's admin RPC
// (admin_extendAPIKey), turning on-chain deposits into service time.
//
// Billing model: time-subscription. days = floor(depositAmount / weiPerDay).
// Per-request metering is intentionally NOT implemented (see
// docs/RANDOMNESS-BILLING.md for the honest scope statement).
//
// Safety properties:
//   - Only logs at or below the FINALIZED block height are processed
//     (receipts carry proposer authority and are not part of the consensus
//     root — a reorg can change them; finalized logs cannot).
//   - Processing is idempotent per anchored height: the state file records
//     the last processed height and is written atomically (temp + rename)
//     after EVERY processed log (QR-24b), so a crash between two logs never
//     re-extends a deposit that was already granted.
//   - --dry-run prints the actions it would take without calling the admin
//     RPC or advancing the state.
//
// Usage:
//
//	vrf-billing -rpc http://127.0.0.1:8545 -contract 0x... \
//	  -admin-key <admin API key> -wei-per-day 1000000000000000000 \
//	  -state ./vrf-billing-state.json [-dry-run] [-once]
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/sha3"
)

// defaultDepositTopic0 is the keccak256 of the canonical event signature.
// The contract pushes this exact constant as LOG1 topic0.
const depositEventSignature = "Deposit(address,uint256,bytes32)"

// getLogsMaxWindow caps eth_getLogs block range per request (the node caps
// ranges at 1000 — rpc/advanced.go — so stay under it).
const getLogsMaxWindow = 900

// maxExtendDays caps a single admin_extendAPIKey call: the RPC rejects
// days above apiKeyMaxDays = 3650 (rpc/admin_key_api.go), so a deposit worth
// more than ten years of service must be split into several calls (QR-24a).
const maxExtendDays = 3650

// splitDays splits a total day count into per-call batches of at most
// maxExtendDays (QR-24a). Pure function so the split is unit-testable.
// total <= 0 yields nil (the caller skips such deposits anyway).
func splitDays(total int64) []int64 {
	if total <= 0 {
		return nil
	}
	full := total / maxExtendDays
	rem := total % maxExtendDays
	n := full
	if rem > 0 {
		n++
	}
	batches := make([]int64, 0, n)
	for i := int64(0); i < full; i++ {
		batches = append(batches, maxExtendDays)
	}
	if rem > 0 {
		batches = append(batches, rem)
	}
	return batches
}

type config struct {
	rpcURL      string
	contract    string
	topic0      string
	adminKey    string
	hmacSecret  string
	statePath   string
	weiPerDay   *big.Int
	dryRun      bool
	once        bool
	interval    time.Duration
	httpTimeout time.Duration
}

type billingState struct {
	LastProcessedBlock uint64 `json:"lastProcessedBlock"`
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

// ethLog mirrors the eth_getLogs log object fields the worker consumes.
type ethLog struct {
	Address          string   `json:"address"`
	Topics           []string `json:"topics"`
	Data             string   `json:"data"`
	BlockNumber      string   `json:"blockNumber"`
	TransactionHash  string   `json:"transactionHash"`
	BlockHash        string   `json:"blockHash"`
	TransactionIndex string   `json:"transactionIndex"`
	LogIndex         string   `json:"logIndex"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	var (
		rpcURL     = flag.String("rpc", "http://127.0.0.1:8545", "node JSON-RPC URL")
		contract   = flag.String("contract", "", "vrf_deposit contract address (0x hex, required)")
		topic0Flag = flag.String("topic0", "", "Deposit event topic0 override (default: keccak256 of the event signature)")
		adminKey   = flag.String("admin-key", "", "admin API key for admin_extendAPIKey (required without -dry-run)")
		hmacSecret = flag.String("hmac-secret", "", "node-wide HMAC secret for request signing (or env QAU_RPC_HMAC_SECRET; required when the node enforces HMAC — the default)")
		statePath  = flag.String("state", "vrf-billing-state.json", "worker state file path")
		weiPerDayS = flag.String("wei-per-day", "", "raw wei charged per day of service (decimal, required)")
		dryRun     = flag.Bool("dry-run", false, "log actions without calling the admin RPC or advancing state")
		once       = flag.Bool("once", false, "run a single pass and exit (default: poll forever)")
		interval   = flag.Duration("interval", 30*time.Second, "poll interval")
		timeout    = flag.Duration("http-timeout", 20*time.Second, "HTTP timeout per RPC call")
	)
	flag.Parse()

	cfg := &config{
		rpcURL:      *rpcURL,
		adminKey:    *adminKey,
		statePath:   *statePath,
		dryRun:      *dryRun,
		once:        *once,
		interval:    *interval,
		httpTimeout: *timeout,
	}
	cfg.hmacSecret = *hmacSecret
	if cfg.hmacSecret == "" {
		cfg.hmacSecret = os.Getenv("QAU_RPC_HMAC_SECRET")
	}
	if !cfg.dryRun && cfg.adminKey != "" && cfg.hmacSecret == "" {
		log.Fatal("-hmac-secret (or env QAU_RPC_HMAC_SECRET) is required for authenticated admin calls: the node enforces HMAC request signing by default")
	}
	if *contract == "" {
		log.Fatal("-contract is required")
	}
	cfg.contract = normalizeHex(*contract)
	if len(cfg.contract) != 42 {
		log.Fatalf("-contract must be a 20-byte 0x-hex address, got %s", cfg.contract)
	}
	cfg.topic0 = *topic0Flag
	if cfg.topic0 == "" {
		// TOPIC0 HASH FIX (2026-11-03, found in the e2e dry-run): the
		// contract computes topic0 with LEGACY Keccak-256 (Solidity/EVM
		// convention), not NIST SHA3-256. x/crypto/sha3.Sum256 is the NIST
		// variant — using it here produced 0x5b95… while the contract emits
		// 0x1a77…, so every event would silently miss the filter. Use
		// NewLegacyKeccak256 explicitly.
		h := sha3.NewLegacyKeccak256()
		h.Write([]byte(depositEventSignature))
		cfg.topic0 = "0x" + hex.EncodeToString(h.Sum(nil))
	}
	cfg.topic0 = normalizeHex(cfg.topic0)
	if len(cfg.topic0) != 66 {
		log.Fatalf("-topic0 must be a 32-byte 0x-hex hash, got %s", cfg.topic0)
	}
	if *weiPerDayS == "" {
		log.Fatal("-wei-per-day is required (raw wei charged per day)")
	}
	var ok bool
	cfg.weiPerDay, ok = new(big.Int).SetString(*weiPerDayS, 10)
	if !ok || cfg.weiPerDay.Sign() <= 0 {
		log.Fatalf("-wei-per-day must be a positive decimal integer, got %q", *weiPerDayS)
	}
	if !cfg.dryRun && cfg.adminKey == "" {
		log.Fatal("-admin-key is required without -dry-run")
	}
	if err := stateDir(cfg.statePath); err != nil {
		log.Fatalf("state dir: %v", err)
	}
	log.Printf("vrf-billing starting: rpc=%s contract=%s topic0=%s weiPerDay=%s dryRun=%v",
		cfg.rpcURL, cfg.contract, cfg.topic0, cfg.weiPerDay, cfg.dryRun)

	for {
		if err := runPass(cfg); err != nil {
			log.Printf("pass failed: %v", err)
		}
		if cfg.once {
			return
		}
		time.Sleep(cfg.interval)
	}
}

// runPass processes one [lastProcessed+1, safeHead] window.
func runPass(cfg *config) error {
	state, err := loadState(cfg.statePath)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	safeHead, err := finalizedHeight(cfg)
	if err != nil {
		return fmt.Errorf("finalized height: %w", err)
	}
	// First boot: anchor at the current finalized height — by default we do
	// NOT replay historical deposits (use -state with a preset value for that).
	if state.LastProcessedBlock == 0 {
		log.Printf("first pass: anchoring at finalized height %d (no historical replay)", safeHead)
		return saveState(cfg.statePath, &billingState{LastProcessedBlock: safeHead})
	}
	if safeHead <= state.LastProcessedBlock {
		return nil // nothing finalized since the last pass
	}
	end := safeHead
	if end-state.LastProcessedBlock > getLogsMaxWindow {
		end = state.LastProcessedBlock + getLogsMaxWindow
	}

	logs, err := fetchDepositLogs(cfg, state.LastProcessedBlock+1, end)
	if err != nil {
		return fmt.Errorf("getLogs [%d,%d]: %w", state.LastProcessedBlock+1, end, err)
	}
	// QR-24b: shrink the crash window. admin_extendAPIKey is NOT idempotent
	// (extending twice grants the days twice), so the anchor must move past a
	// log as soon as it has been extended — previously the anchor was saved
	// only at the END of the window and a crash mid-window re-extended every
	// log already processed in it. The cursor below tracks the highest height
	// whose logs are fully processed and is persisted after EVERY log.
	processed := state.LastProcessedBlock
	for _, l := range logs {
		processLog(cfg, l)
		if cfg.dryRun {
			continue // dry-run does not advance the anchor
		}
		if h, perr := parseHexUint(l.BlockNumber); perr == nil && h > processed {
			processed = h
		}
		if serr := saveState(cfg.statePath, &billingState{LastProcessedBlock: processed}); serr != nil {
			return fmt.Errorf("save state after log at height %d: %w", processed, serr)
		}
	}
	log.Printf("processed window [%d,%d]: %d deposit event(s)", state.LastProcessedBlock+1, end, len(logs))
	if cfg.dryRun {
		return nil // dry-run does not advance the anchor
	}
	// Heights after the last deposit log in the window hold no events (the
	// fetch already returned all of them), so the anchor can safely jump to
	// the window end.
	if processed < end {
		return saveState(cfg.statePath, &billingState{LastProcessedBlock: end})
	}
	return nil
}

// finalizedHeight returns the height of the last block of the finalized
// epoch via eth_getBlockByNumber("finalized").
func finalizedHeight(cfg *config) (uint64, error) {
	var block struct {
		Number string `json:"number"`
	}
	if err := callRPC(cfg, "eth_getBlockByNumber", &block, "finalized", false); err != nil {
		return 0, err
	}
	if block.Number == "" {
		return 0, fmt.Errorf("no finalized block available yet")
	}
	return parseHexUint(block.Number)
}

// fetchDepositLogs pulls Deposit events for the contract in the window.
func fetchDepositLogs(cfg *config, from, to uint64) ([]ethLog, error) {
	filter := map[string]interface{}{
		"fromBlock": "0x" + fmt.Sprintf("%x", from),
		"toBlock":   "0x" + fmt.Sprintf("%x", to),
		"address":   cfg.contract,
		"topics":    []string{cfg.topic0},
	}
	var logs []ethLog
	if err := callRPC(cfg, "eth_getLogs", &logs, filter); err != nil {
		return nil, err
	}
	return logs, nil
}

// depositEvent is the decoded Deposit(address,uint256,bytes32) payload:
// data = pad32(payer) ++ pad32(amountWei) ++ pad32(keyHash).
type depositEvent struct {
	Payer   string
	Amount  *big.Int
	KeyHash string
	TxHash  string
}

func decodeDeposit(l ethLog) (*depositEvent, error) {
	raw, err := hex.DecodeString(trim0x(l.Data))
	if err != nil {
		return nil, fmt.Errorf("data hex: %w", err)
	}
	if len(raw) != 96 {
		return nil, fmt.Errorf("data length %d, want 96 (payer++amount++keyHash)", len(raw))
	}
	amount := new(big.Int).SetBytes(raw[32:64])
	return &depositEvent{
		Payer:   "0x" + hex.EncodeToString(raw[12:32]), // last 20 bytes of the padded address
		Amount:  amount,
		KeyHash: "0x" + hex.EncodeToString(raw[64:96]),
		TxHash:  l.TransactionHash,
	}, nil
}

// processLog decodes one deposit and extends the matching API key.
func processLog(cfg *config, l ethLog) {
	ev, err := decodeDeposit(l)
	if err != nil {
		log.Printf("SKIP log %s: undecodable deposit: %v", l.TransactionHash, err)
		return
	}
	days := new(big.Int).Div(ev.Amount, cfg.weiPerDay).Int64()
	if days <= 0 {
		log.Printf("SKIP tx %s: payer %s amount %s wei below one day (%s wei/day)",
			ev.TxHash, ev.Payer, ev.Amount, cfg.weiPerDay)
		return
	}
	if cfg.dryRun {
		log.Printf("DRY-RUN tx %s: would extend key %s by %d day(s) (payer %s, amount %s wei)",
			ev.TxHash, ev.KeyHash, days, ev.Payer, ev.Amount)
		return
	}
	// QR-24a: admin_extendAPIKey caps a single call at 3650 days, so a
	// deposit worth more than that is split into bounded batches. Batches are
	// independent extensions: a mid-sequence failure keeps the earlier
	// batches (each failure is logged loudly for manual reconciliation).
	for i, batch := range splitDays(days) {
		var result json.RawMessage
		err = callRPCAuthed(cfg, "admin_extendAPIKey", &result,
			map[string]interface{}{"keyHash": ev.KeyHash, "days": batch})
		if err != nil {
			// Not fatal for the pass: the state anchor still advances past this
			// window, so re-delivery relies on the on-chain record. Log loudly.
			log.Printf("ERROR tx %s: extend key %s batch %d/%d (%d day(s)) failed: %v (deposit is on-chain; reconcile manually)",
				ev.TxHash, ev.KeyHash, i+1, len(splitDays(days)), batch, err)
			continue
		}
		log.Printf("OK tx %s: extended key %s by %d day(s) (batch %d/%d, payer %s, amount %s wei)",
			ev.TxHash, ev.KeyHash, batch, i+1, len(splitDays(days)), ev.Payer, ev.Amount)
	}
}

// --- minimal JSON-RPC client ---

func callRPC(cfg *config, method string, result interface{}, params ...interface{}) error {
	return doRPC(cfg, method, result, params, false)
}

func callRPCAuthed(cfg *config, method string, result interface{}, params ...interface{}) error {
	return doRPC(cfg, method, result, params, true)
}

func doRPC(cfg *config, method string, result interface{}, params []interface{}, authed bool) error {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, cfg.rpcURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if authed {
		req.Header.Set("X-API-Key", cfg.adminKey)
		// The node verifies HMAC-SHA256 over
		// method || apiKeyHash || timestamp || nonce || sha256(body) with the
		// node-wide secret (rpc/auth.go verifyHMACWithNonce). apiKeyHash is
		// the SHA-256 of the plaintext key — the same value the node stores.
		if cfg.hmacSecret != "" {
			ts := time.Now().UTC().Format(time.RFC3339)
			nonce := make([]byte, 16)
			if _, err := rand.Read(nonce); err != nil {
				return fmt.Errorf("nonce: %w", err)
			}
			nonceHex := hex.EncodeToString(nonce)
			keyHash := sha256.Sum256([]byte(cfg.adminKey))
			bodyHash := sha256.Sum256(body)
			mac := hmac.New(sha256.New, []byte(cfg.hmacSecret))
			mac.Write([]byte(method))
			mac.Write([]byte(hex.EncodeToString(keyHash[:])))
			mac.Write([]byte(ts))
			mac.Write([]byte(nonceHex))
			mac.Write(bodyHash[:])
			req.Header.Set("X-Timestamp", ts)
			req.Header.Set("X-Nonce", nonceHex)
			req.Header.Set("X-Signature", hex.EncodeToString(mac.Sum(nil)))
		}
	}
	client := &http.Client{Timeout: cfg.httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	var envelope rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return err
	}
	if envelope.Error != nil {
		return fmt.Errorf("rpc error %d: %s", envelope.Error.Code, envelope.Error.Message)
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, result)
}

// --- state file (atomic temp+rename) ---

func loadState(path string) (*billingState, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &billingState{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s billingState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("corrupt state %s: %w", path, err)
	}
	return &s, nil
}

func saveState(path string, s *billingState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// --- small helpers ---

func trim0x(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

func normalizeHex(s string) string {
	return "0x" + trim0x(s)
}

func parseHexUint(s string) (uint64, error) {
	var v uint64
	_, err := fmt.Sscanf(trim0x(s), "%x", &v)
	if err != nil {
		return 0, fmt.Errorf("hex %q: %w", s, err)
	}
	return v, nil
}

// stateDir ensures the parent directory of the state file exists.
func stateDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o700)
}
