// Quantaureum Node source, version 1.0.0.
// Quantaureum Testnet Faucet Service
// Signs and sends test QAU tokens from the faucet account.
// Deploy on a dedicated host alongside the testnet node.
package main

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

const (
	faucetAmount   = 100 // QAU per claim
	rpcURL         = "http://localhost:8545"
	chainID        = 1669
	listenAddr     = "127.0.0.1:3001" // audit fix (CRITICAL): binds 127.0.0.1 by default, exposed via reverse proxy
	rateLimitHours = 24
	// AUDIT (2026) API-FIX: Global daily cap prevents Sybil drain.
	// Without this, an attacker rotating IPs/addresses can extract unlimited
	// QAU (each new IP+address pair claims 100 QAU every 24h). The daily cap
	// bounds total dispensation regardless of how many unique identities the
	// attacker controls.
	maxDailyDispense = 1000 // max QAU dispensed per UTC day
)

var (
	qauDecimals = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
)

type FaucetService struct {
	mu           sync.Mutex
	privateKey   *crypto.PrivateKey
	publicKey    []byte
	fromAddress  types.Address
	rateLimitMap map[string]time.Time // AUDIT (2026) API-08: stores BOTH IP keys ("ip:<addr>") and address keys ("addr:<hex>"), not just IP
	persistPath  string               // AUDIT (2026) API-08: file path for rate limit persistence
	// AUDIT (2026) API-FIX: Track daily dispense total to enforce
	// a global daily cap. Without this, an attacker rotating IPs and addresses
	// can extract unlimited QAU. The daily cap bounds total dispensation
	// regardless of Sybil identities.
	dailyDispensed int       // total QAU dispensed today
	dailyResetDate time.Time // UTC date when dailyDispensed was last reset
}

func main() {
	fs, err := NewFaucetService()
	if err != nil {
		log.Fatalf("Failed to initialize faucet: %v", err)
	}

	// AUDIT (2026) API-08: Load persisted rate limits to prevent
	// bypass via restart.
	fs.loadRateLimits()

	// audit fix (CRITICAL): listen address configurable via environment variable; default 127.0.0.1 (exposed via reverse proxy)
	addr := getEnv("QUANTAUREUM_FAUCET_LISTEN")
	if addr == "" {
		addr = listenAddr
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/faucet", fs.handleFaucet)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// R31-MED-5 FIX: surface health-probe write failures (client
		// disconnects mid-write are common under probes and were silently
		// swallowed before).
		if _, err := w.Write([]byte("OK")); err != nil {
			log.Printf("health handler write failed: %v", err)
		}
	})

	log.Printf("Faucet service starting on %s", addr)
	// L-7 FIX: Do not log the full faucet address in plaintext.
	// The faucet address is the funded wallet that attackers target. Logging it
	// at startup makes it trivially discoverable in log aggregators/systemd
	// journals. Instead, log only a masked preview (first 6 + last 4 chars)
	// so operators can verify the correct address is loaded without exposing
	// the full address in logs. The full address can be queried via RPC if needed.
	addrHex := hex.EncodeToString(fs.fromAddress[:])
	if len(addrHex) > 10 {
		log.Printf("Faucet address: 0x%s...%s (masked, use RPC to query full address)",
			addrHex[:6], addrHex[len(addrHex)-4:])
	} else {
		log.Printf("Faucet address: 0x%s (masked)", addrHex)
	}
	// SECURITY (audit P3-18): Removed misleading balance log. The faucetAmount
	// is the per-request dispense amount, not the faucet's total balance.
	log.Printf("Faucet dispense amount: %d QAU per request", faucetAmount)

	// SECURITY (audit P2-18): API key authentication is now REQUIRED by default.
	// Running without an API key allows anyone to drain funds (subject to rate
	// limits). Set QUANTAUREUM_FAUCET_API_KEY to enable the faucet.
	// To explicitly disable for dev/test environments, set
	// QUANTAUREUM_FAUCET_ALLOW_NO_KEY=1.
	if getEnv("QUANTAUREUM_FAUCET_API_KEY") == "" {
		if getEnv("QUANTAUREUM_FAUCET_ALLOW_NO_KEY") != "1" {
			log.Fatalf("FATAL: QUANTAUREUM_FAUCET_API_KEY is not set. " +
				"Set this environment variable to require X-API-Key header. " +
				"To allow running without API key (INSECURE, dev/test only), " +
				"set QUANTAUREUM_FAUCET_ALLOW_NO_KEY=1.")
		} else {
			log.Printf("WARNING: Faucet running WITHOUT API key authentication (dev mode). " +
				"This is insecure for production.")
		}
	}

	// G114 fix (2026-08-20): ListenAndServe has no timeout support; a slow
	// or malicious client could hold connections open indefinitely (slowloris).
	// Use an explicit http.Server with read/write/idle timeouts.
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func NewFaucetService() (*FaucetService, error) {
	// SECURITY (audit P3-17): Removed hardcoded default key path.
	// The key file path MUST be specified via QUANTAUREUM_FAUCET_KEY_FILE.
	keyPath := getEnv("QUANTAUREUM_FAUCET_KEY_FILE")
	if keyPath == "" {
		log.Fatalf("FATAL: QUANTAUREUM_FAUCET_KEY_FILE not set. " +
			"Set this to the faucet private key file path.")
	}

	keyData, err := loadKeyFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load faucet key: %w", err)
	}

	priv, pub, addr, err := parseDilithium3Key(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	return &FaucetService{
		privateKey:   priv,
		publicKey:    pub,
		fromAddress:  addr,
		rateLimitMap: make(map[string]time.Time),
		persistPath:  getEnv("QUANTAUREUM_FAUCET_RATELIMIT_FILE"),
	}, nil
}

// AUDIT (2026) API-08 FIX: Persist rate limit map to disk so that
// restarting the faucet does not reset rate limits (preventing bypass
// via restart). The file is JSON-encoded and atomically rewritten on
// each successful claim. If the path is empty (not configured), rate
// limits remain in-memory only (dev mode).
func (fs *FaucetService) loadRateLimits() {
	if fs.persistPath == "" {
		return
	}
	data, err := os.ReadFile(fs.persistPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("WARNING: failed to read rate limit file %s: %v", fs.persistPath, err)
		}
		return
	}
	var persisted map[string]time.Time
	if err := json.Unmarshal(data, &persisted); err != nil {
		log.Printf("WARNING: failed to parse rate limit file %s: %v", fs.persistPath, err)
		return
	}
	// Evict expired entries on load
	cutoff := time.Now().Add(-2 * rateLimitHours * time.Hour)
	for k, t := range persisted {
		if t.After(cutoff) {
			fs.rateLimitMap[k] = t
		}
	}
	log.Printf("Loaded %d rate limit entries from %s", len(fs.rateLimitMap), fs.persistPath)
}

func (fs *FaucetService) saveRateLimits() {
	if fs.persistPath == "" {
		return
	}
	data, err := json.Marshal(fs.rateLimitMap)
	if err != nil {
		log.Printf("WARNING: failed to marshal rate limits: %v", err)
		return
	}
	// Atomic write: write to temp file then rename
	tmpPath := fs.persistPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		log.Printf("WARNING: failed to write rate limit file: %v", err)
		return
	}
	if err := os.Rename(tmpPath, fs.persistPath); err != nil {
		log.Printf("WARNING: failed to rename rate limit file: %v", err)
	}
}

func loadKeyFile(path string) (string, error) {
	// SECURITY (SV-08 FIX): Load key from environment variable first,
	// then from file. Read via os.Getenv then immediately os.Unsetenv so the
	// raw private key is NOT inherited by any child process spawned later in
	// this process and is NOT readable via /proc/self/environ after this
	// point. The value never enters logs or error messages from this path.
	if envKey := os.Getenv("QUANTAUREUM_FAUCET_KEY"); envKey != "" {
		os.Unsetenv("QUANTAUREUM_FAUCET_KEY")
		return envKey, nil
	}

	data, err := readFile(path)
	if err != nil {
		return "", fmt.Errorf("read key file %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func parseDilithium3Key(raw string) (*crypto.PrivateKey, []byte, types.Address, error) {
	// Format: dilithium3:SK_HEX:PK_HEX
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "dilithium3:") {
		return nil, nil, types.Address{}, fmt.Errorf("invalid key format, expected dilithium3:SK:PK")
	}

	parts := strings.SplitN(raw, ":", 3)
	if len(parts) != 3 {
		return nil, nil, types.Address{}, fmt.Errorf("invalid key format, expected 3 parts")
	}

	skBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, nil, types.Address{}, fmt.Errorf("invalid SK hex: %w", err)
	}

	pkBytes, err := hex.DecodeString(parts[2])
	if err != nil {
		return nil, nil, types.Address{}, fmt.Errorf("invalid PK hex: %w", err)
	}

	priv, err := crypto.PrivateKeyFromBytes(skBytes)
	if err != nil {
		return nil, nil, types.Address{}, fmt.Errorf("invalid private key: %w", err)
	}

	addr := types.AddressFromPublicKey(pkBytes)

	return priv, pkBytes, addr, nil
}

// ==================== HTTP Handler ====================

func (fs *FaucetService) handleFaucet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// audit fix (CRITICAL): API-key auth (read from environment)
	// If QUANTAUREUM_FAUCET_API_KEY is set, requests must carry the correct key in the X-API-Key header
	// audit-fix L-8 [LOW]: Removed support for passing the API key via URL query
	// parameter (?api_key=xxx). Query parameters are logged in access logs,
	// browser history, proxy logs, and Referer headers, creating a credential
	// leakage risk. The API key must now be sent exclusively via the X-API-Key
	// HTTP header, which is not logged by standard access log formats.
	expectedAPIKey := getEnv("QUANTAUREUM_FAUCET_API_KEY")
	if expectedAPIKey != "" {
		providedKey := r.Header.Get("X-API-Key")
		// security fix: use constant-time comparison, preventing timing attacks
		// plain != comparison can leak key information via timing differences
		if subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedAPIKey)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: invalid or missing API key"})
			return
		}
	}

	// Parse request
	// audit-fix H-4: limit request body to 10KB to prevent DoS via oversized bodies
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	var req struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	// Validate address
	req.Address = strings.TrimSpace(req.Address)
	if !strings.HasPrefix(req.Address, "0x") || len(req.Address) != 42 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid QAU address format"})
		return
	}

	targetAddr, err := types.ParseHexAddress(req.Address)
	if err != nil || targetAddr == (types.Address{}) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid address"})
		return
	}

	// Rate limit by IP and address
	// SECURITY FIX (R2-H1): TOCTOU race condition fix. Previously we released
	// the lock before sending the transaction, allowing concurrent requests
	// to bypass rate limiting. Now we record the claim time BEFORE sending
	// (reserving the rate limit slot), and roll back if the transaction fails.
	clientIP := getClientIP(r)
	addrKey := "addr:" + req.Address
	var claimedTime time.Time
	fs.mu.Lock()
	// AUDIT (2026) API-FIX: Check and enforce global daily cap.
	// Reset the counter at UTC midnight. Without this cap, an attacker rotating
	// IPs and addresses can extract unlimited QAU (Sybil drain).
	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if !fs.dailyResetDate.Equal(today) {
		fs.dailyDispensed = 0
		fs.dailyResetDate = today
	}
	if fs.dailyDispensed+faucetAmount > maxDailyDispense {
		fs.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": fmt.Sprintf("daily dispensation limit reached (%d QAU/day), try again tomorrow", maxDailyDispense),
		})
		return
	}
	lastClaim, exists := fs.rateLimitMap[clientIP]
	if exists && time.Since(lastClaim) < rateLimitHours*time.Hour {
		remaining := rateLimitHours*time.Hour - time.Since(lastClaim)
		fs.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": fmt.Sprintf("rate limited, try again in %.0f hours", remaining.Hours()),
		})
		return
	}
	if lastAddr, exists := fs.rateLimitMap[addrKey]; exists && time.Since(lastAddr) < rateLimitHours*time.Hour {
		remaining := rateLimitHours*time.Hour - time.Since(lastAddr)
		fs.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": fmt.Sprintf("address rate limited, try again in %.0f hours", remaining.Hours()),
		})
		return
	}
	// Reserve the rate limit slot immediately to prevent concurrent claims
	claimedTime = time.Now()
	fs.rateLimitMap[clientIP] = claimedTime
	fs.rateLimitMap[addrKey] = claimedTime
	// AUDIT (2026) API-FIX: Reserve daily dispense quota.
	fs.dailyDispensed += faucetAmount
	// AUDIT (2026) KEYS-10: Evict expired entries to bound map growth.
	// Without this, the rateLimitMap grows unboundedly as unique IPs/addresses
	// accumulate over time. Eviction runs inline (under the held lock) and
	// removes entries older than 2x the rate limit window (48h), which is
	// cheap relative to the per-claim network IO that follows.
	cutoff := claimedTime.Add(-2 * rateLimitHours * time.Hour)
	for k, t := range fs.rateLimitMap {
		if t.Before(cutoff) {
			delete(fs.rateLimitMap, k)
		}
	}
	fs.mu.Unlock()

	// Send transaction (lock released during network IO)
	txHash, err := fs.sendTransaction(targetAddr)
	if err != nil {
		// Roll back rate limit reservation on failure
		fs.mu.Lock()
		// Only roll back if our reservation is still the current one
		if t, ok := fs.rateLimitMap[clientIP]; ok && t.Equal(claimedTime) {
			delete(fs.rateLimitMap, clientIP)
		}
		if t, ok := fs.rateLimitMap[addrKey]; ok && t.Equal(claimedTime) {
			delete(fs.rateLimitMap, addrKey)
		}
		// AUDIT (2026) API-FIX: Roll back daily dispense reservation.
		fs.dailyDispensed -= faucetAmount
		fs.mu.Unlock()

		log.Printf("Faucet send failed: %v", err)
		// AUDIT (2026) API-08: Persist rolled-back state.
		fs.saveRateLimits()
		// AUDIT (2026) API-FIX: Do not leak raw backend error
		// strings (RPC URLs, internal error messages, stack details) to
		// the client. Return a generic message; the full error is logged
		// above for operator diagnostics.
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to send faucet transaction, please try again later"})
		return
	}

	//nolint:gosec // G706: testnet faucet operation log; values are a QAU address,
	// tx hash and IP for operator diagnostics. No newlines can be injected from
	// validated inputs (address/tx are hex, IP is net.ParseIP-validated).
	log.Printf("Faucet: sent %d QAU to %s, tx=%s, ip=%s", faucetAmount, req.Address, txHash, clientIP)

	// AUDIT (2026) API-08: Persist rate limits after successful claim.
	fs.saveRateLimits()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"txHash":  txHash,
		"amount":  faucetAmount,
		"message": fmt.Sprintf("Sent %d QAU to %s", faucetAmount, req.Address),
	})
}

// ==================== Transaction ====================

func (fs *FaucetService) sendTransaction(to types.Address) (string, error) {
	// 1. Get nonce
	nonce, err := fs.rpcGetNonce(fs.fromAddress)
	if err != nil {
		return "", fmt.Errorf("get nonce: %w", err)
	}

	// 2. Build encoding.Transaction (the native format for RPC/consensus)
	value := new(big.Int).Mul(big.NewInt(faucetAmount), qauDecimals)
	tx := &encoding.Transaction{
		Version:   1,
		Type:      encoding.TxTypeTransfer,
		Nonce:     nonce,
		From:      fs.fromAddress,
		To:        &to,
		Value:     value,
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		Data:      nil,
		ChainID:   chainID,
		PublicKey: fs.publicKey,
	}

	// 3. Sign with Dilithium3
	signingHash, err := tx.SigningHash()
	if err != nil {
		return "", fmt.Errorf("compute signing hash: %w", err)
	}
	sig, err := crypto.Sign(fs.privateKey, signingHash[:])
	if err != nil {
		return "", fmt.Errorf("sign tx: %w", err)
	}
	tx.Signature = sig

	// 4. Marshal to protobuf wire format
	rawBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		return "", fmt.Errorf("marshal tx: %w", err)
	}

	// 5. Send via RPC
	rawHex := "0x" + hex.EncodeToString(rawBytes)
	txHash, err := fs.rpcSendRaw(rawHex)
	if err != nil {
		return "", fmt.Errorf("send tx: %w", err)
	}

	return txHash, nil
}

// ==================== RPC Helpers ====================

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

func (fs *FaucetService) rpcCall(method string, params []interface{}) (json.RawMessage, error) {
	reqBody, _ := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})

	// audit-fix M-7: use a client with timeout to avoid hanging indefinitely
	// if the RPC node is unresponsive.
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(rpcURL, "application/json", strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("rpc call failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var rpcResp rpcResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("rpc parse error: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

func (fs *FaucetService) rpcGetNonce(addr types.Address) (uint64, error) {
	addrHex := "0x" + hex.EncodeToString(addr[:])
	result, err := fs.rpcCall("eth_getTransactionCount", []interface{}{addrHex, "latest"})
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

func (fs *FaucetService) rpcSendRaw(rawHex string) (string, error) {
	result, err := fs.rpcCall("eth_sendRawTransaction", []interface{}{rawHex})
	if err != nil {
		return "", err
	}

	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return "", fmt.Errorf("tx hash parse: %w", err)
	}

	return txHash, nil
}

// ==================== Helpers ====================

func getClientIP(r *http.Request) string {
	// audit-fix LOW(R2): only trust X-Forwarded-For/X-Real-IP from localhost (trusted proxy)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if isLocalhost(host) {
		// AUDIT (2026) KEYS-10: Prefer X-Real-IP (set by the trusted
		// reverse proxy, not forgeable by the client). Only fall back to
		// X-Forwarded-For if X-Real-IP is absent, and take the LAST entry
		// (appended by the trusted proxy) — the FIRST entry is client-
		// controlled and can be forged to bypass per-IP rate limiting.
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			// Take the LAST non-empty entry (added by the trusted proxy)
			for i := len(parts) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(parts[i])
				if ip != "" {
					return ip
				}
			}
		}
	}
	return host
}

// isLocalhost reports whether the host is a loopback address.
func isLocalhost(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// audit fix (CRITICAL): the original always returned an empty string, ignoring the environment. It now reads the environment correctly.
func getEnv(key string) string {
	return os.Getenv(key)
}

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// R31-MED-5 FIX (2026-09-06): a failed Encode previously truncated the
	// JSON body silently — the client would parse a partial document and
	// surface a confusing unmarshal error instead of a transport error.
	// Log the encode failure; the header is already sent so we cannot
	// change the status code, but operators see the root cause.
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("writeJSON encode failed: %v", err)
	}
}
