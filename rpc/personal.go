// Quantaureum Node source, version 1.0.0.
// Package rpc provides personal account management API
package rpc

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quantaureum/qau/accounts"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/types"
)

// requireTLS checks that the connection is TLS-secured.
// All methods that transmit passwords or private keys must call this first.
// Like Ethereum's geth, sensitive operations are blocked over plaintext HTTP
// unless --allow-insecure-unlock is set (for development/testing).
// Supports reverse proxy setups via X-Forwarded-Proto header (e.g. Caddy, Nginx).
func (api *PersonalAPI) requireTLS(ctx context.Context) *Error {
	// If --allow-insecure-unlock is set, skip TLS check (Ethereum-compatible)
	api.mu.RLock()
	allowInsecure := api.allowInsecureUnlock
	api.mu.RUnlock()
	if allowInsecure {
		return nil
	}

	if httpReq, ok := ctx.Value(contextKeyHTTPRequest{}).(*http.Request); ok {
		// Direct TLS connection
		if httpReq.TLS != nil {
			return nil
		}
		// Reverse proxy: check X-Forwarded-Proto header
		// audit-fix MEDIUM(R2): only trust X-Forwarded-Proto from localhost (trusted proxy)
		if strings.EqualFold(httpReq.Header.Get("X-Forwarded-Proto"), "https") {
			if host, _, err := net.SplitHostPort(httpReq.RemoteAddr); err == nil {
				if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
					return nil
				}
			}
		}
		return NewError(ErrCodeUnauthorized,
			"this method requires a TLS-secured connection (HTTPS/WSS). "+
				"Use --allow-insecure-unlock to bypass (development only), "+
				"or use eth_sendRawTransaction for offline signing")
	}
	// Non-HTTP transport (e.g. IPC) — allow without TLS check
	return nil
}

// PersonalAPI provides personal account management
type PersonalAPI struct {
	mu          sync.RWMutex
	keystoreDir string
	accounts    map[types.Address]*accounts.Account
	unlocked    map[types.Address]time.Time // address -> unlock expiry
	unlockDur   time.Duration
	txPool      TxPool
	stateReader StateReader
	//  Cache mapping address→keystore filepath to avoid O(n) directory
	// scan on every UnlockAccount call. Set to nil to force rebuild.
	keystoreIndex map[types.Address]string
	// audit-fix M-2: gates dev-only methods like UnlockFromPrivateKey
	devMode   bool
	chainInfo ChainInfo
	// allow-insecure-unlock: bypasses TLS requirement (Ethereum-compatible)
	allowInsecureUnlock bool
}

// isProductionEnv returns true if NODE_ENV is set to production
func isProductionEnv() bool {
	return os.Getenv("NODE_ENV") == "production" || os.Getenv("NODE_ENV") == "prod"
}

// NewPersonalAPI creates a new PersonalAPI.
// Set devMode=true only in development to enable UnlockFromPrivateKey.
func NewPersonalAPI(keystoreDir string, txPool TxPool, stateReader StateReader, chainInfo ChainInfo) *PersonalAPI {
	api := &PersonalAPI{
		keystoreDir: keystoreDir,
		accounts:    make(map[types.Address]*accounts.Account),
		unlocked:    make(map[types.Address]time.Time),
		unlockDur:   5 * time.Minute, // default unlock duration
		txPool:      txPool,
		stateReader: stateReader,
		chainInfo:   chainInfo,
	}
	// SECURITY FIX: DevMode is always false in production environments
	// Even if explicitly set, production mode cannot be bypassed
	if isProductionEnv() {
		api.devMode = false
	}
	// Load existing accounts
	api.loadAccounts()
	return api
}

// compile-time development mode flag
// Set at build time: go build -ldflags "-X github.com/quantaureum/qau/rpc.DEV_MODE_ENABLED=false"
// Default to false for security; explicitly enable only for dev/test builds
var DEV_MODE_ENABLED = "false"

// SetDevMode enables or disables dev-mode-only methods.
// audit-fix M-2: must be called explicitly to enable UnlockFromPrivateKey.
// audit-fix H-3: CRITICAL - DevMode cannot be enabled at runtime in any environment
func (api *PersonalAPI) SetDevMode(enabled bool) {
	api.mu.Lock()
	defer api.mu.Unlock()
	// audit-fix H-3: Use compile-time flag to prevent runtime bypass
	// If DEV_MODE_ENABLED != "true" (set at build time), always disable
	if DEV_MODE_ENABLED != "true" {
		api.devMode = false
		return
	}
	// Even in dev builds, log this security-sensitive operation
	log.Printf("[SECURITY] DEV_MODE set to %v", enabled)
	api.devMode = enabled
}

// SetAllowInsecureUnlock bypasses TLS requirement for personal_* methods.
// Ethereum-compatible: equivalent to geth's --allow-insecure-unlock flag.
// WARNING: This exposes private key material over plaintext HTTP. Use only
// for development/testing or when combined with a reverse proxy.
//
// FIX: Block allow-insecure-unlock in production environments.
// Previously, SetAllowInsecureUnlock could be called at any time, including
// in production, which would expose passwords and private keys over plaintext
// HTTP. Now we check QAU_PRODUCTION=1 and refuse to enable the bypass,
// logging a security warning instead.
func (api *PersonalAPI) SetAllowInsecureUnlock(allowed bool) {
	if allowed {
		// M-5: Refuse to enable insecure unlock in production
		if params.IsProductionEnv() {
			log.Printf("[SECURITY] SetAllowInsecureUnlock(true) rejected: QAU_PRODUCTION=1 is set. " +
				"personal_* methods require TLS in production.")
			return
		}
		log.Printf("[SECURITY] --allow-insecure-unlock enabled: personal_* methods available over plaintext HTTP")
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	api.allowInsecureUnlock = allowed
}

// RegisterHandlers registers personal API handlers
func (api *PersonalAPI) RegisterHandlers(server *Server) {
	server.RegisterHandler("personal_newAccount", api.NewAccount)
	server.RegisterHandler("personal_listAccounts", api.ListAccounts)
	server.RegisterHandler("personal_unlockAccount", api.UnlockAccount)
	server.RegisterHandler("personal_lockAccount", api.LockAccount)
	server.RegisterHandler("personal_sendTransaction", api.SendTransaction)
	server.RegisterHandler("personal_sign", api.Sign)
	server.RegisterHandler("personal_importRawKey", api.ImportRawKey)
}

// UnlockFromPrivateKey unlocks an account directly from a private key.
// SECURITY WARNING: This method is for DEVELOPMENT MODE ONLY!
// It is NOT exposed as an RPC endpoint and should only be called internally
// during node initialization when DevMode is enabled.
// In production, accounts must be unlocked via personal_unlockAccount with password.
// audit-fix M-2: guarded by devMode flag to prevent accidental production use.
// L12-036 FIX: RISK — devMode is a runtime flag that could be accidentally enabled
// in production (e.g., misconfigured config file or env var). For stronger isolation,
// consider using Go build tags (//go:build dev) to exclude this method entirely from
// production binaries. See: https://pkg.go.dev/go/build#hdr-Build_Constraints
func (api *PersonalAPI) UnlockFromPrivateKey(privateKeyHex string) error {
	api.mu.RLock()
	isDevMode := api.devMode
	api.mu.RUnlock()
	if !isDevMode {
		return fmt.Errorf("UnlockFromPrivateKey is disabled in production mode; enable dev mode first")
	}
	keyBytes, err := parseHexBytes(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid key hex: %w", err)
	}

	// L9-024 FIX: Use crypto.ZeroBytesSecure (indirect function call) instead of
	// a simple for loop to prevent compiler dead-store elimination.
	defer func() { _ = crypto.ZeroBytesSecure(keyBytes) }()

	privKey, err := crypto.PrivateKeyFromBytes(keyBytes)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	account, err := accounts.NewAccountFromPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to create account: %w", err)
	}

	api.mu.Lock()
	api.accounts[account.Address] = account
	// R7-M4 FIX: previously unlocked for 365 days, an excessive window that
	// effectively made the dev key permanently hot. Reduce to a normal dev
	// session length (8h). Dev tools that need longer can re-unlock.
	api.unlocked[account.Address] = time.Now().Add(8 * time.Hour)
	api.mu.Unlock()

	// R39-P3 FIX: Log only the first 8 hex chars (4 bytes) of the address
	// to avoid leaking the full account address to log streams.
	log.Printf("[PersonalAPI] Dev account unlocked: 0x%s...", hex.EncodeToString(account.Address[:4]))
	return nil
}

// loadAccounts loads accounts from keystore directory
func (api *PersonalAPI) loadAccounts() {
	if api.keystoreDir == "" {
		return
	}

	files, err := os.ReadDir(api.keystoreDir)
	if err != nil {
		return
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if strings.Contains(f.Name(), "..") {
			continue
		}
		filePath := filepath.Join(api.keystoreDir, f.Name())
		if !strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(api.keystoreDir)+string(os.PathSeparator)) {
			continue
		}
		data, err := os.ReadFile(filePath) // #nosec G304 -- path traversal validated above
		if err != nil {
			continue
		}
		addr, err := accounts.GetKeystoreAddress(data)
		if err != nil {
			continue
		}
		// Store placeholder - actual account loaded on unlock
		api.accounts[addr] = nil
	}
}

// NewAccount creates a new account with the given password
// SECURITY FIX (audit P3-01): Added requireTLS check to match other password-handling
// methods (unlockAccount, sendTransaction, sign, importRawKey). Without TLS, the
// password could be sniffed over the network.
func (api *PersonalAPI) NewAccount(ctx context.Context, params json.RawMessage) (any, *Error) {
	if err := api.requireTLS(ctx); err != nil {
		return nil, err
	}

	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}
	password := args[0]

	// audit-fix P5-L4: Enforce minimum password length to prevent trivially
	// guessable passwords that would make keystore brute-force trivial.
	const minPasswordLength = 8
	if len(password) < minPasswordLength {
		return nil, NewError(ErrCodeInvalidParams,
			fmt.Sprintf("password must be at least %d characters", minPasswordLength))
	}

	// Generate new key pair
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, NewError(ErrCodeInternal, "failed to generate key pair")
	}

	// Create account
	account, err := accounts.NewAccountFromPrivateKey(keyPair.Private)
	if err != nil {
		return nil, NewError(ErrCodeInternal, "failed to create account")
	}

	// Export to keystore
	keystoreData, err := accounts.ExportKeystore(account, password)
	if err != nil {
		return nil, NewError(ErrCodeInternal, "failed to export keystore")
	}

	// Save keystore file
	if api.keystoreDir != "" {
		// audit-fix L-2: check MkdirAll error
		if err := os.MkdirAll(api.keystoreDir, 0700); err != nil {
			return nil, NewError(ErrCodeInternal, "failed to create keystore directory")
		}
		filename := fmt.Sprintf("UTC--%s--%s",
			time.Now().UTC().Format("2006-01-02T15-04-05.000000000Z"),
			hex.EncodeToString(account.Address[:]))
		filePath := filepath.Join(api.keystoreDir, filename)
		if err := os.WriteFile(filePath, keystoreData, 0600); err != nil {
			return nil, NewError(ErrCodeInternal, "failed to save keystore")
		}
		//  Cache the keystore file path for O(1) lookup
		api.mu.Lock()
		if api.keystoreIndex == nil {
			api.keystoreIndex = make(map[types.Address]string)
		}
		api.keystoreIndex[account.Address] = filePath
		api.mu.Unlock()
	}

	api.mu.Lock()
	api.accounts[account.Address] = account
	api.mu.Unlock()

	return formatAddress(account.Address), nil
}

// ListAccounts returns all account addresses
func (api *PersonalAPI) ListAccounts(ctx context.Context, params json.RawMessage) (any, *Error) {
	api.mu.RLock()
	defer api.mu.RUnlock()

	addrs := make([]string, 0, len(api.accounts))
	for addr := range api.accounts {
		addrs = append(addrs, formatAddress(addr))
	}
	return addrs, nil
}

// UnlockAccount unlocks an account for a duration
func (api *PersonalAPI) UnlockAccount(ctx context.Context, params json.RawMessage) (any, *Error) {
	// SECURITY: Reject plaintext connections — password is transmitted in the clear.
	if err := api.requireTLS(ctx); err != nil {
		return nil, err
	}

	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, ErrInvalidParams
	}

	addrStr, ok := args[0].(string)
	if !ok {
		return nil, ErrInvalidParams
	}
	password, ok := args[1].(string)
	if !ok {
		return nil, ErrInvalidParams
	}

	// Optional duration in seconds
	duration := api.unlockDur
	if len(args) > 2 {
		if dur, ok := args[2].(float64); ok && dur > 0 {
			duration = time.Duration(dur) * time.Second
		}
	}
	// audit-fix R4-M2: cap unlock duration to prevent indefinite unlocks
	const MaxUnlockDuration = 24 * time.Hour
	if duration > MaxUnlockDuration {
		duration = MaxUnlockDuration
	}

	addr, err := parseAddress(addrStr)
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid address")
	}

	// Load and decrypt keystore
	account, err := api.loadAndDecrypt(addr, password)
	if err != nil {
		return nil, NewError(ErrCodeUnauthorized, "failed to unlock account: invalid password")
	}

	api.mu.Lock()
	api.accounts[addr] = account
	api.unlocked[addr] = time.Now().Add(duration)
	api.mu.Unlock()

	return true, nil
}

// loadAndDecrypt loads and decrypts an account from keystore
func (api *PersonalAPI) loadAndDecrypt(addr types.Address, password string) (*accounts.Account, error) {
	if api.keystoreDir == "" {
		return nil, fmt.Errorf("keystore directory not configured")
	}

	addrHex := hex.EncodeToString(addr[:])

	// FIX: Try cached index first (O(1)) before falling back to full
	// directory scan (O(n)). The index is built on first access and invalidated
	// when accounts are imported.
	api.mu.RLock()
	cachedPath, hit := api.keystoreIndex[addr]
	api.mu.RUnlock()
	if hit {
		if acct, err := api.loadFromKeystoreFile(cachedPath, addrHex, password, addr); err == nil {
			return acct, nil
		}
		// Cache miss (file deleted/renamed) — fall through to full scan
	}

	files, err := os.ReadDir(api.keystoreDir)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		// Check if filename contains address
		if len(f.Name()) < 40 {
			continue
		}
		if strings.Contains(f.Name(), "..") {
			continue
		}
		filePath := filepath.Join(api.keystoreDir, f.Name())
		if !strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(api.keystoreDir)+string(os.PathSeparator)) {
			continue
		}
		data, err := os.ReadFile(filePath) // #nosec G304 -- path traversal validated above
		if err != nil {
			continue
		}
		fileAddr, err := accounts.GetKeystoreAddress(data)
		if err != nil {
			continue
		}
		// audit-fix HIGH-5: Use constant-time comparison to prevent timing attacks
		// An attacker could potentially guess the address byte-by-byte by measuring
		// response times if regular string comparison was used
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(fileAddr[:])), []byte(addrHex)) == 1 {
			// Cache the file path for future lookups
			api.mu.Lock()
			if api.keystoreIndex == nil {
				api.keystoreIndex = make(map[types.Address]string)
			}
			api.keystoreIndex[addr] = filePath
			api.mu.Unlock()
			return accounts.ImportKeystore(data, password)
		}
	}

	return nil, fmt.Errorf("account not found")
}

// loadFromKeystoreFile loads and decrypts a keystore file at the given path,
// verifying the address matches. Returns error if the file doesn't exist or
// the address doesn't match.
func (api *PersonalAPI) loadFromKeystoreFile(filePath, addrHex string, password string, addr types.Address) (*accounts.Account, error) {
	data, err := os.ReadFile(filePath) // #nosec G304 -- path from trusted cache
	if err != nil {
		return nil, err
	}
	fileAddr, err := accounts.GetKeystoreAddress(data)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(fileAddr[:])), []byte(addrHex)) == 1 {
		return accounts.ImportKeystore(data, password)
	}
	return nil, fmt.Errorf("address mismatch")
}

// LockAccount locks an account
func (api *PersonalAPI) LockAccount(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid address")
	}

	api.mu.Lock()
	delete(api.unlocked, addr)
	// audit-fix M-3: PrivateKey.Bytes() returns a copy; zeroing it does not clear the
	// original key material inside mode3.PrivateKey. Use Account.Lock() which nils the
	// PrivateKey reference, allowing GC to reclaim the backing memory. This is the best
	// we can do without a Zeroize() method on the underlying Dilithium implementation.
	if acc, ok := api.accounts[addr]; ok && acc != nil {
		acc.Lock() // sets acc.PrivateKey = nil, drops reference to key material
	}
	delete(api.accounts, addr)
	api.mu.Unlock()

	return true, nil
}

// isUnlocked checks if an account is unlocked.
// audit-fix M-6: expired-entry cleanup is deferred to a single goroutine and
// guarded by a re-check under the write lock to avoid redundant cleanup from
// concurrent readers.
func (api *PersonalAPI) isUnlocked(addr types.Address) bool {
	api.mu.RLock()
	defer api.mu.RUnlock()

	expiry, ok := api.unlocked[addr]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		go api.cleanupExpiredUnlock(addr)
		return false
	}
	return true
}

// cleanupExpiredUnlock removes an expired unlock entry under a write lock.
// audit-fix M-6: re-checks expiry under the write lock so that only one of
// multiple concurrent readers actually performs the cleanup.
func (api *PersonalAPI) cleanupExpiredUnlock(addr types.Address) {
	api.mu.Lock()
	defer api.mu.Unlock()

	// Re-check: another goroutine may have already cleaned up or re-unlocked.
	expiry, ok := api.unlocked[addr]
	if !ok {
		return
	}
	if !time.Now().After(expiry) {
		return // re-unlocked in the meantime
	}
	delete(api.unlocked, addr)
	if acc, ok := api.accounts[addr]; ok && acc != nil {
		acc.Lock()
	}
	delete(api.accounts, addr)
}

// getUnlockedAccount returns an unlocked account.
// audit-fix R4-L2: performs unlock-check and account retrieval within a single
// RLock acquisition to eliminate the TOCTOU race between isUnlocked and account lookup.
func (api *PersonalAPI) getUnlockedAccount(addr types.Address) *accounts.Account {
	api.mu.RLock()
	defer api.mu.RUnlock()

	expiry, ok := api.unlocked[addr]
	if !ok {
		return nil
	}
	if time.Now().After(expiry) {
		go api.cleanupExpiredUnlock(addr)
		return nil
	}
	return api.accounts[addr]
}

// SendTransaction signs and sends a transaction.
// audit-fix R40-H10: This method transmits the account password as plaintext in
// the JSON-RPC payload. To mitigate credential interception, we now require a TLS
// connection. Callers on plaintext connections should use eth_sendRawTransaction
// (sign offline, submit the pre-signed blob) instead.
func (api *PersonalAPI) SendTransaction(ctx context.Context, params json.RawMessage) (any, *Error) {
	// SECURITY: Reject plaintext connections — password is transmitted in the clear.
	if err := api.requireTLS(ctx); err != nil {
		return nil, err
	}

	// audit-fix R40-H10: Emit deprecation warning in server log.
	//  ENHANCED WARNING: personal_sendTransaction transmits the account
	// password as plaintext in the JSON-RPC payload. Even with TLS, the
	// password is exposed to the node operator (logged in RPC middleware)
	// and to any TLS-terminating proxy. This method is DEPRECATED and will be
	// removed in a future release. All clients MUST migrate to offline signing:
	// sign the transaction locally with the private key (never transmit the
	// password) and submit the pre-signed blob via eth_sendRawTransaction.
	log.Printf("[PersonalAPI] DEPRECATION WARNING: personal_sendTransaction called — " +
		"this method transmits passwords in plaintext in the JSON-RPC payload and will be removed in a future release. " +
		"Migrate to offline signing with eth_sendRawTransaction")

	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, ErrInvalidParams
	}

	txMap, ok := args[0].(map[string]any)
	if !ok {
		return nil, ErrInvalidParams
	}
	password, ok := args[1].(string)
	if !ok {
		return nil, ErrInvalidParams
	}

	// Parse from address
	fromStr, ok := txMap["from"].(string)
	if !ok {
		return nil, NewError(ErrCodeInvalidParams, "missing from address")
	}
	from, err := parseAddress(fromStr)
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid from address")
	}

	// Load and decrypt account
	account, err := api.loadAndDecrypt(from, password)
	if err != nil {
		return nil, NewError(ErrCodeUnauthorized, "failed to unlock account")
	}
	// R12-RPC-P4-2 FIX: Zeroize the decrypted private key after use.
	defer func() {
		if account != nil && account.PrivateKey != nil {
			_ = account.PrivateKey.Zeroize()
		}
	}()
	tx, rpcErr := api.buildTransaction(txMap, from)
	if rpcErr != nil {
		return nil, rpcErr
	}

	// Sign transaction
	tx.PublicKey = account.PrivateKey.PublicKey().Bytes()
	signingHash, err := tx.SigningHash()
	if err != nil {
		return nil, NewError(ErrCodeInternal, "failed to compute signing hash: "+err.Error())
	}
	signature, err := crypto.Sign(account.PrivateKey, signingHash[:])
	if err != nil {
		return nil, NewError(ErrCodeInternal, "failed to sign transaction")
	}
	tx.Signature = signature

	// Serialize and send
	txData, err := encoding.MarshalTransaction(tx)
	if err != nil {
		return nil, NewError(ErrCodeInternal, "failed to serialize transaction")
	}

	hash, err := api.txPool.AddTransaction(txData)
	if err != nil {
		return nil, NewError(ErrCodeInvalidTx, err.Error())
	}

	return formatHexHash(hash), nil
}

// buildTransaction builds a transaction from RPC parameters
func (api *PersonalAPI) buildTransaction(txMap map[string]any, from types.Address) (*encoding.Transaction, *Error) {
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		From:     from,
		ChainID:  0, // will be set below once chainInfo is available
		GasLimit: 21000,
		GasPrice: nil, // L12-023 FIX: no hardcoded default; set from suggested gas price below
		Value:    big.NewInt(0),
	}

	// Set chain ID from chain info (required for replay protection)
	if api.chainInfo != nil {
		tx.ChainID = api.chainInfo.ChainID()
	}

	// Parse to (supports both string and null values)
	hasTo := false
	if toVal, ok := txMap["to"]; ok && toVal != nil {
		if toStr, ok := toVal.(string); ok && toStr != "" && toStr != "0x" && toStr != "0x0" {
			to, err := parseAddress(toStr)
			if err != nil {
				return nil, NewError(ErrCodeInvalidParams, "invalid to address")
			}
			tx.To = &to
			hasTo = true
		}
	}

	// Parse value
	if valStr, ok := txMap["value"].(string); ok {
		val, err := parseHexBigInt(valStr)
		if err != nil {
			return nil, NewError(ErrCodeInvalidParams, "invalid value hex")
		}
		tx.Value = val
	}

	// Parse gas
	if gasStr, ok := txMap["gas"].(string); ok {
		gas, err := parseHexUint64(gasStr)
		if err != nil {
			return nil, NewError(ErrCodeInvalidParams, "invalid gas hex")
		}
		tx.GasLimit = gas
	}

	// Parse gasPrice
	if gpStr, ok := txMap["gasPrice"].(string); ok {
		gp, err := parseHexBigInt(gpStr)
		if err != nil {
			return nil, NewError(ErrCodeInvalidParams, "invalid gasPrice hex")
		}
		tx.GasPrice = gp
	}

	// L12-023 FIX: If caller did not provide a gasPrice, use the suggested
	// gas price from the chain instead of a hardcoded 1 Gwei default.
	if tx.GasPrice == nil || tx.GasPrice.Sign() == 0 {
		tx.GasPrice = api.suggestedGasPrice()
	}

	// Parse nonce or get from state
	if nonceStr, ok := txMap["nonce"].(string); ok {
		nonce, err := parseHexUint64(nonceStr)
		if err != nil {
			return nil, NewError(ErrCodeInvalidParams, "invalid nonce hex")
		}
		tx.Nonce = nonce
	} else {
		// Use pending nonce (on-chain nonce + pending tx count) to ensure
		// consecutive transactions from the same address get distinct nonces.
		// This matches Ethereum's behavior where getTransactionCount("pending")
		// returns the next available nonce.
		if api.txPool != nil {
			tx.Nonce = api.txPool.GetPendingNonce(from)
		} else if api.stateReader != nil {
			tx.Nonce = api.stateReader.GetNonce(from)
		}
	}

	// Parse data (support both "data" and "input" fields, like Ethereum)
	hasData := false
	if dataStr, ok := txMap["data"].(string); ok {
		data, err := parseHexBytes(dataStr)
		if err != nil {
			return nil, NewError(ErrCodeInvalidParams, "invalid data hex")
		}
		if len(data) > 0 {
			tx.Data = data
			hasData = true
		}
	}
	// "input" is an alias for "data" (Ethereum compatibility per EIP-1470)
	if !hasData {
		if inputStr, ok := txMap["input"].(string); ok {
			data, err := parseHexBytes(inputStr)
			if err != nil {
				return nil, NewError(ErrCodeInvalidParams, "invalid input hex")
			}
			if len(data) > 0 {
				tx.Data = data
				hasData = true
			}
		}
	}

	// Parse explicit type (allows caller to override auto-detection)
	explicitType := false
	if typeStr, ok := txMap["type"].(string); ok {
		if t, err := parseHexUint64(typeStr); err == nil && t <= math.MaxUint8 {
			tx.Type = encoding.TxType(t)
			explicitType = true
		}
	}

	// Auto-detect transaction type (like Ethereum):
	// - No 'to' + has 'data' → Contract creation (TxTypeCreate)
	// - Has 'to' + has 'data' → Contract call (TxTypeContract)
	// - No 'data' → Transfer (TxTypeTransfer, default)
	// Explicit type from caller takes precedence over auto-detection.
	if !explicitType {
		if !hasTo && hasData {
			tx.Type = encoding.TxTypeCreate
			// Contract creation needs more gas
			if tx.GasLimit == 21000 {
				tx.GasLimit = 1000000 // 1M gas default for contract creation
			}
		} else if hasTo && hasData {
			tx.Type = encoding.TxTypeContract
			// Contract calls need more gas than a simple transfer
			if tx.GasLimit == 21000 {
				tx.GasLimit = 1000000 // 1M gas default for contract calls
			}
		}
	}

	return tx, nil
}

// suggestedGasPrice returns the chain's suggested gas price for new transactions.
// L12-023 FIX: Replaces the hardcoded 1 Gwei default in buildTransaction.
// Currently returns the same default as the eth_gasPrice RPC endpoint.
// TODO(economics): Query the block pool / txpool for recent gas usage and
// compute a dynamic price (e.g., median of recent blocks, EIP-1559 base fee).
func (api *PersonalAPI) suggestedGasPrice() *big.Int {
	// FIX: Use named constant instead of hardcoded magic number.
	return big.NewInt(DefaultGasPriceWei) // 1 Gwei
}

// Sign signs data with an account.
// audit-fix P5-M3: Like SendTransaction, this method receives a password in the
// clear, so it requires a TLS-secured connection to prevent credential interception.
func (api *PersonalAPI) Sign(ctx context.Context, params json.RawMessage) (any, *Error) {
	// SECURITY: Reject plaintext connections — password is transmitted in the clear.
	if err := api.requireTLS(ctx); err != nil {
		return nil, err
	}

	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 3 {
		return nil, ErrInvalidParams
	}

	dataHex := args[0]
	addrStr := args[1]
	password := args[2]

	addr, err := parseAddress(addrStr)
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid address")
	}

	data, err := parseHexBytes(dataHex)
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid data")
	}

	// Load and decrypt account
	account, err := api.loadAndDecrypt(addr, password)
	if err != nil {
		return nil, NewError(ErrCodeUnauthorized, "failed to unlock account")
	}
	// R12-RPC-P4-2 FIX: Zeroize the decrypted private key after use.
	defer func() {
		if account != nil && account.PrivateKey != nil {
			_ = account.PrivateKey.Zeroize()
		}
	}()

	// Sign data
	signature, err := crypto.Sign(account.PrivateKey, data)
	if err != nil {
		return nil, NewError(ErrCodeInternal, "failed to sign")
	}

	return formatHexBytes(signature), nil
}

// ImportRawKey imports a raw private key.
// Supports both raw hex format and "dilithium3:<privKeyHex><pubKeyHex>" format
// (automatically extracts the private key portion).
// Available in both dev and production mode (requires password for keystore encryption).
func (api *PersonalAPI) ImportRawKey(ctx context.Context, params json.RawMessage) (any, *Error) {
	// SECURITY: Reject plaintext connections — private key and password are transmitted in the clear.
	if err := api.requireTLS(ctx); err != nil {
		return nil, err
	}

	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, ErrInvalidParams
	}

	keyHex := args[0]
	password := args[1]

	// L10-022: Validate key format before attempting to parse.
	// Key must start with "dilithium3:" prefix (after optional "0x" prefix)
	// and have the correct hex length (11904 hex chars = privKey + pubKey).
	keyToValidate := keyHex
	if strings.HasPrefix(keyToValidate, "0x") {
		keyToValidate = keyToValidate[2:]
	}
	if !strings.HasPrefix(keyToValidate, "dilithium3:") {
		// RP-06 FIX: Return a generic error message instead of revealing the
		// expected key prefix, which leaks format information to callers.
		return nil, NewError(ErrCodeInvalidParams, "invalid key format")
	}
	hexPart := keyToValidate[len("dilithium3:"):]
	// Count actual hex characters (ignore separators like ':')
	hexCount := 0
	for _, c := range hexPart {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			hexCount++
		}
	}
	const expectedHexLen = 11904 // 4000 bytes privKey + 1952 bytes pubKey = 5952 bytes = 11904 hex chars
	if hexCount != expectedHexLen {
		// RP-06 FIX: Return a generic error message instead of revealing the
		// expected hex length, which leaks key size information to callers.
		return nil, NewError(ErrCodeInvalidParams, "invalid key format")
	}

	// audit-fix P5-L4: Enforce minimum password length for keystore encryption
	const minPasswordLength = 8
	if len(password) < minPasswordLength {
		return nil, NewError(ErrCodeInvalidParams,
			fmt.Sprintf("password must be at least %d characters", minPasswordLength))
	}

	// Auto-detect and extract private key from "dilithium3:<hex>" format
	keyHex, err := extractDilithium3PrivateKey(keyHex)
	if err != nil {
		// RP-06 FIX: Return a generic error message instead of wrapping the
		// internal error, which may reveal expected key lengths or format details.
		return nil, NewError(ErrCodeInvalidParams, "invalid key format")
	}

	keyBytes, err := parseHexBytes(keyHex)
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid key: not valid hex")
	}
	// L9-012 FIX: Zeroize raw private key bytes after use to prevent memory leakage.
	defer func() { _ = crypto.ZeroBytesSecure(keyBytes) }()

	privKey, err := crypto.PrivateKeyFromBytes(keyBytes)
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, fmt.Sprintf("invalid private key: %v", err))
	}

	account, err := accounts.NewAccountFromPrivateKey(privKey)
	if err != nil {
		return nil, NewError(ErrCodeInternal, "failed to create account")
	}

	// Export to keystore
	keystoreData, err := accounts.ExportKeystore(account, password)
	if err != nil {
		return nil, NewError(ErrCodeInternal, "failed to export keystore")
	}

	// Save keystore file
	if api.keystoreDir != "" {
		// audit-fix L-2: check MkdirAll error
		if err := os.MkdirAll(api.keystoreDir, 0700); err != nil {
			return nil, NewError(ErrCodeInternal, "failed to create keystore directory")
		}
		filename := fmt.Sprintf("UTC--%s--%s",
			time.Now().UTC().Format("2006-01-02T15-04-05.000000000Z"),
			hex.EncodeToString(account.Address[:]))
		filePath := filepath.Join(api.keystoreDir, filename)
		if err := os.WriteFile(filePath, keystoreData, 0600); err != nil {
			return nil, NewError(ErrCodeInternal, "failed to save keystore")
		}
		//  Cache the keystore file path for O(1) lookup
		api.mu.Lock()
		if api.keystoreIndex == nil {
			api.keystoreIndex = make(map[types.Address]string)
		}
		api.keystoreIndex[account.Address] = filePath
		api.mu.Unlock()
	}

	api.mu.Lock()
	api.accounts[account.Address] = account
	// Note: Account is NOT auto-unlocked for security reasons
	// User must call personal_unlockAccount separately
	api.mu.Unlock()

	// R31-P5-4 FIX: Do not log the imported account address. While the address
	// is a public key hash (not the private key), logging it creates a traceable
	// record of which accounts are being imported, which could aid an attacker
	// with log access in correlating import activity. Log only the event itself.
	log.Printf("[PersonalAPI] Key imported successfully")
	return formatAddress(account.Address), nil
}

// extractDilithium3PrivateKey handles the "dilithium3:<privKeyHex><pubKeyHex>" format
// by stripping the prefix and extracting only the private key portion (4000 bytes = 8000 hex chars).
// If the input doesn't have the prefix, it's returned as-is (raw hex format).
func extractDilithium3PrivateKey(keyHex string) (string, error) {
	const prefix = "dilithium3:"
	const privKeyHexLen = crypto.Dilithium3PrivateKeySize * 2                                     // 8000
	const combinedHexLen = (crypto.Dilithium3PrivateKeySize + crypto.Dilithium3PublicKeySize) * 2 // 11904

	// Strip "0x" prefix if present (common hex convention)
	keyHex = strings.TrimPrefix(keyHex, "0x")
	keyHex = strings.TrimPrefix(keyHex, "0X")

	if !strings.HasPrefix(keyHex, prefix) {
		// Pure private key format: must be exactly 8000 hex chars
		if len(keyHex) != privKeyHexLen {
			return "", fmt.Errorf("invalid private key length: got %d, expected %d hex chars", len(keyHex), privKeyHexLen)
		}
		return keyHex, nil
	}

	// Strip prefix
	hexData := keyHex[len(prefix):]

	// Filter out any whitespace/newlines
	hexData = strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, hexData)

	// Combined format must be exactly 11904 hex chars (privKey + pubKey)
	if len(hexData) != combinedHexLen {
		return "", fmt.Errorf("invalid combined key length: got %d, expected %d hex chars", len(hexData), combinedHexLen)
	}

	// Extract only the private key portion
	return hexData[:privKeyHexLen], nil
}

// Helper functions
func formatAddress(addr types.Address) string {
	return "0x" + hex.EncodeToString(addr[:])
}

func parseHexBigInt(s string) (*big.Int, error) {
	s = stripHexPrefix(s)
	val := new(big.Int)
	_, ok := val.SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex number")
	}
	return val, nil
}

func parseHexUint64(s string) (uint64, error) {
	s = stripHexPrefix(s)
	// L13-018: Use strconv.ParseUint instead of fmt.Sscanf to properly detect overflow.
	// fmt.Sscanf with %x silently truncates values exceeding uint64 max (0xFFFFFFFFFFFFFFFF).
	val, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid hex uint64: %w", err)
	}
	return val, nil
}

// =============================================================================
// AccountManager interface implementation
// =============================================================================

// IsUnlocked checks if an account is unlocked (implements AccountManager)
func (api *PersonalAPI) IsUnlocked(addr types.Address) bool {
	return api.isUnlocked(addr)
}

// UnlockAccountDirect unlocks an account directly (implements AccountManager)
func (api *PersonalAPI) UnlockAccountDirect(addr types.Address, password string) error {
	account, err := api.loadAndDecrypt(addr, password)
	if err != nil {
		return err
	}

	api.mu.Lock()
	api.accounts[addr] = account
	api.unlocked[addr] = time.Now().Add(api.unlockDur)
	api.mu.Unlock()

	return nil
}

// SignTransaction signs a transaction (implements AccountManager)
func (api *PersonalAPI) SignTransaction(from types.Address, txParams any) ([]byte, error) {
	// Get unlocked account
	account := api.getUnlockedAccount(from)
	if account == nil {
		return nil, fmt.Errorf("account not unlocked")
	}

	// Convert txParams to map
	txMap, ok := txParams.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid transaction parameters")
	}

	// Build transaction
	tx, rpcErr := api.buildTransaction(txMap, from)
	if rpcErr != nil {
		return nil, fmt.Errorf("%s", rpcErr.Message)
	}

	// Sign transaction
	tx.PublicKey = account.PrivateKey.PublicKey().Bytes()
	signingHash, err := tx.SigningHash()
	if err != nil {
		return nil, NewError(ErrCodeInternal, "failed to compute signing hash: "+err.Error())
	}
	signature, err := crypto.Sign(account.PrivateKey, signingHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}
	tx.Signature = signature

	// Serialize transaction
	txData, err := encoding.MarshalTransaction(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	return txData, nil
}
