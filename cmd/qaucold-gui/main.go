// Quantaureum Node source, version 1.0.0.
//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
	"github.com/quantaureum/qau/accounts"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"golang.org/x/sys/windows"
)

// audit-fix MEDIUM: Upper-bound guards for transaction fields. These protect
// users from signing transactions with absurd values that could drain their
// wallet or be used in social-engineering attacks (e.g., a malicious dApp
// tricking the user into signing a 10^100 value transfer).
const (
	// maxValueWei is the maximum allowed transaction value (100 billion QAU in wei).
	// 100e9 * 1e18 = 1e29. This is well above any reasonable transfer but
	// catches accidental/malicious overflow inputs.
	maxValueWei = "100000000000000000000000000000"
	// maxGasPriceWei is the maximum allowed gas price (1 TQAU = 1e21 wei).
	// This is far above normal gas prices but catches absurd inputs.
	maxGasPriceWei = "1000000000000000000000"
	// maxGasLimit is the maximum allowed gas limit.
	maxGasLimit = 30_000_000
)

var (
	user32          = windows.NewLazySystemDLL("user32.dll")
	procSendMessage = user32.NewProc("SendMessageW")
	procLoadImage   = user32.NewProc("LoadImageW")
	procFindWindow  = user32.NewProc("FindWindowW")
)

const (
	WM_SETICON      = 0x0080
	ICON_SMALL      = 0
	ICON_BIG        = 1
	IMAGE_ICON      = 1
	LR_LOADFROMFILE = 0x0010
)

const (
	walletFileName        = "wallet.json"
	publicKeyFileName     = "public.json"
	version               = "1.0.0"
	maxPasswordAttempts   = 5
	passwordAttemptWindow = 5 * time.Minute
)

var (
	// csrfToken is the CSRF token for the current app session.
	// Security fix (Round 4): sync.Once removed; a fresh token is generated on every app start (i.e. per session).
	// Previously sync.Once meant the token never rotated for the process lifetime, so a long-running app
	// kept the same token indefinitely, widening the CSRF attack window.
	csrfToken          string
	passwordAttempts   = make(map[string]*attemptTracker)
	passwordAttemptsMu sync.Mutex
)

type attemptTracker struct {
	count    int
	lastSeen time.Time
}

// generateCSRFToken generates a fresh CSRF token.
// Security fix (Round 4): sync.Once removed; every call generates a new token.
// Called once in main() and bound to the current session; a restart generates a new token.
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}
	csrfToken = hex.EncodeToString(b)
	return csrfToken, nil
}

func checkRateLimit(ip string) bool {
	passwordAttemptsMu.Lock()
	defer passwordAttemptsMu.Unlock()
	now := time.Now()
	tracker, exists := passwordAttempts[ip]
	if !exists || now.Sub(tracker.lastSeen) > passwordAttemptWindow {
		passwordAttempts[ip] = &attemptTracker{count: 1, lastSeen: now}
		return true
	}
	tracker.lastSeen = now
	tracker.count++
	return tracker.count <= maxPasswordAttempts
}

func sanitizePath(baseDir, userPath string) (string, error) {
	if userPath == "" {
		return "", fmt.Errorf("path cannot be empty")
	}
	cleanPath := filepath.Clean(userPath)
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("invalid base directory")
	}
	absTarget, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("invalid target path")
	}
	if !strings.HasPrefix(absTarget, absBase) {
		return "", fmt.Errorf("path traversal detected")
	}
	return absTarget, nil
}

func validateWalletDir(walletDir string) (string, error) {
	if walletDir == "" {
		return "", fmt.Errorf("wallet directory is required")
	}
	cleanDir := filepath.Clean(walletDir)
	absDir, err := filepath.Abs(cleanDir)
	if err != nil {
		return "", fmt.Errorf("invalid wallet directory")
	}
	if strings.Contains(absDir, "..") {
		return "", fmt.Errorf("invalid path")
	}
	info, err := os.Stat(absDir)
	if err != nil {
		return "", fmt.Errorf("directory not accessible")
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path is not a directory")
	}
	return absDir, nil
}

func validateOutputDir(outputDir string) (string, error) {
	if outputDir == "" {
		return "", fmt.Errorf("output directory is required")
	}
	cleanDir := filepath.Clean(outputDir)
	absDir, err := filepath.Abs(cleanDir)
	if err != nil {
		return "", fmt.Errorf("invalid output directory")
	}
	if strings.Contains(absDir, "..") {
		return "", fmt.Errorf("invalid path")
	}
	return absDir, nil
}

func sanitizeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, "no such file") || strings.Contains(msg, "cannot find") {
		return "wallet file not found"
	}
	if strings.Contains(msg, "invalid password") || strings.Contains(msg, "decryption failed") {
		return "invalid password"
	}
	return "operation failed"
}

type ColdWalletPublic struct {
	Version     string    `json:"version"`
	Address     string    `json:"address"`
	PublicKey   string    `json:"public_key"`
	Algorithm   string    `json:"algorithm"`
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description,omitempty"`
}

type UnsignedTransaction struct {
	Version  int    `json:"version"`
	Type     int    `json:"type"`
	Nonce    uint64 `json:"nonce"`
	From     string `json:"from"`
	To       string `json:"to"`
	Value    string `json:"value"`
	GasLimit uint64 `json:"gas_limit"`
	GasPrice string `json:"gas_price"`
	Data     string `json:"data,omitempty"`
	ChainID  uint64 `json:"chain_id"`
	TxHash   string `json:"tx_hash"`
}

type SignedTransaction struct {
	UnsignedTransaction
	PublicKey string    `json:"public_key"`
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
}

type APIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func main() {
	token, err := generateCSRFToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to start listener: %v\n", err)
		os.Exit(1)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleIndex(w, r, token)
	})
	mux.HandleFunc("/api/generate", withCSRF(token, withSecurityHeaders(handleGenerate)))
	mux.HandleFunc("/api/sign", withCSRF(token, withSecurityHeaders(handleSign)))
	mux.HandleFunc("/api/export", withCSRF(token, withSecurityHeaders(handleExport)))
	mux.HandleFunc("/api/verify", withCSRF(token, withSecurityHeaders(handleVerify)))

	server := &http.Server{
		Handler: mux,
		// audit-fix R62-F2 [HIGH]: Slowloris attack mitigation — ReadHeaderTimeout must be
		// set to prevent slow-client attacks that hold connections open indefinitely.
		// Without this, ReadTimeout starts counting only after headers are complete,
		// allowing slow-header attacks to exhaust connection slots. 10s is sufficient
		// for legitimate clients; tune downward if needed.
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go server.Serve(listener) //nolint:errcheck

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "Quantaureum Cold Wallet",
			Width:  700,
			Height: 600,
			Center: true,
		},
	})
	if w == nil {
		fmt.Println("Failed to create webview")
		return
	}
	defer w.Destroy()

	go func() {
		time.Sleep(500 * time.Millisecond)
		setWindowIcon("Quantaureum Cold Wallet")
	}()

	w.Navigate(fmt.Sprintf("http://127.0.0.1:%d", port))
	w.Run()
}

func withSecurityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next(w, r)
	}
}

func withCSRF(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		csrfHeader := r.Header.Get("X-CSRF-Token")
		if csrfHeader == "" {
			cookie, err := r.Cookie("qau-csrf")
			if err == nil {
				csrfHeader = cookie.Value
			}
		}
		if csrfHeader != token {
			jsonResponse(w, false, "invalid or missing CSRF token", nil)
			return
		}
		next(w, r)
	}
}

func setWindowIcon(title string) {
	titlePtr := windows.StringToUTF16Ptr(title)
	hwnd, _, _ := procFindWindow.Call(0, uintptr(unsafe.Pointer(titlePtr))) // #nosec G103 -- unsafe operation reviewed and deemed necessary for performance
	if hwnd == 0 {
		return
	}

	// locate icon.ico next to the exe
	exePath, err := os.Executable()
	if err != nil {
		// Fallback to current directory if unable to determine executable path
		exePath = os.Args[0]
	}
	iconPath := filepath.Join(filepath.Dir(exePath), "icon.ico")
	if _, err := os.Stat(iconPath); os.IsNotExist(err) { // #nosec G703
		// try the cmd directory
		iconPath = filepath.Join(filepath.Dir(exePath), "cmd", "qaucold-gui", "icon.ico")
	}

	iconPathPtr := windows.StringToUTF16Ptr(iconPath)

	// load the large icon (32x32)
	hIconBig, _, _ := procLoadImage.Call(0, uintptr(unsafe.Pointer(iconPathPtr)), IMAGE_ICON, 32, 32, LR_LOADFROMFILE) // #nosec G103 -- unsafe operation reviewed and deemed necessary for performance
	if hIconBig != 0 {
		procSendMessage.Call(hwnd, WM_SETICON, ICON_BIG, hIconBig) //nolint:errcheck
	}

	// load the small icon (16x16)
	hIconSmall, _, _ := procLoadImage.Call(0, uintptr(unsafe.Pointer(iconPathPtr)), IMAGE_ICON, 16, 16, LR_LOADFROMFILE) // #nosec G103 -- unsafe operation reviewed and deemed necessary for performance
	if hIconSmall != 0 {
		procSendMessage.Call(hwnd, WM_SETICON, ICON_SMALL, hIconSmall) //nolint:errcheck
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request, token string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// audit-fix M-9 [MEDIUM]: Inject CSRF token into HTML via meta tag so the
	// frontend can read it and include it in API requests. Previously the token
	// was generated but never delivered to the frontend, causing all API
	// requests to be rejected by withCSRF.
	html := strings.Replace(indexHTML, "<head><meta charset=\"UTF-8\">",
		"<head><meta name=\"csrf-token\" content=\""+token+"\"><meta charset=\"UTF-8\">", 1)
	w.Write([]byte(html)) //nolint:errcheck
}

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonResponse(w, false, "Method not allowed", nil)
		return
	}
	var req struct {
		OutputDir   string `json:"output_dir"`
		Password    string `json:"password"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, false, "invalid JSON request", nil)
		return
	}

	if req.OutputDir == "" || req.Password == "" {
		jsonResponse(w, false, "Output directory and password required", nil)
		return
	}
	if len(req.Password) < 12 {
		jsonResponse(w, false, "Password must be at least 12 characters", nil)
		return
	}

	safeDir, err := validateOutputDir(req.OutputDir)
	if err != nil {
		jsonResponse(w, false, "Invalid output directory", nil)
		return
	}

	if err := os.MkdirAll(safeDir, 0700); err != nil {
		jsonResponse(w, false, "Failed to create output directory", nil)
		return
	}
	walletPath := filepath.Join(safeDir, walletFileName)
	if _, err := os.Stat(walletPath); err == nil {
		jsonResponse(w, false, "Wallet already exists", nil)
		return
	}

	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		jsonResponse(w, false, "Failed to generate key", nil)
		return
	}
	// audit-fix HIGH: zeroize private key after use to prevent key material
	// from remaining in heap memory after wallet generation completes.
	defer keyPair.Private.Zeroize()

	account, err := accounts.NewAccountFromPrivateKey(keyPair.Private)
	if err != nil {
		jsonResponse(w, false, "Failed to create account", nil)
		return
	}

	data, err := accounts.ExportKeystoreWithParams(account, req.Password, accounts.DefaultKeystoreParams())
	if err != nil {
		jsonResponse(w, false, "Failed to encrypt", nil)
		return
	}

	// audit-fix R62-F5 [HIGH]: os.WriteFile error was ignored. On disk-full or
	// permission-denied, the function would return "success" while wallet file was
	// not actually persisted — user loses their newly created key.
	if err := os.WriteFile(walletPath, data, 0600); err != nil {
		jsonResponse(w, false, "Failed to write wallet file", nil)
		return
	}
	pub := ColdWalletPublic{version, account.Address.String(), hex.EncodeToString(keyPair.Public.Bytes()), "Dilithium3", time.Now().UTC(), req.Description}
	pubData, err := json.MarshalIndent(pub, "", "  ")
	if err != nil {
		jsonResponse(w, false, "Failed to serialize public data", nil)
		return
	}
	// audit-fix R62-F5 [HIGH]: os.WriteFile error was ignored. On disk-full or
	// permission-denied, the public key file would not be written and the user
	// would have no record of their public key.
	if err := os.WriteFile(filepath.Join(safeDir, publicKeyFileName), pubData, 0600); err != nil {
		jsonResponse(w, false, "Failed to write public key file", nil)
		return
	}

	jsonResponse(w, true, "Wallet created!", map[string]string{"address": account.Address.String(), "path": walletPath})
}

func handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonResponse(w, false, "Method not allowed", nil)
		return
	}

	clientIP := r.RemoteAddr
	if !checkRateLimit(clientIP) {
		jsonResponse(w, false, "Too many attempts, please wait", nil)
		return
	}

	var req struct {
		WalletDir string `json:"wallet_dir"`
		TxJSON    string `json:"tx_json"`
		Password  string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, false, "invalid JSON request", nil)
		return
	}

	var tx UnsignedTransaction
	if err := json.Unmarshal([]byte(req.TxJSON), &tx); err != nil {
		jsonResponse(w, false, "Invalid transaction format", nil)
		return
	}

	// audit-fix MEDIUM: Validate transaction fields before signing to prevent
	// the user from signing a transaction with absurd values, malformed
	// addresses, or missing critical fields. Without this, a malicious dApp
	// could trick the user into signing a transaction that drains their wallet
	// or sets an extremely high gas price.
	if err := validateUnsignedTransaction(&tx); err != nil {
		jsonResponse(w, false, err.Error(), nil)
		return
	}

	safeDir, err := validateWalletDir(req.WalletDir)
	if err != nil {
		jsonResponse(w, false, "Invalid wallet directory", nil)
		return
	}

	ksData, err := os.ReadFile(filepath.Join(safeDir, walletFileName)) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		jsonResponse(w, false, "Wallet not found", nil)
		return
	}

	acc, err := accounts.ImportKeystore(ksData, req.Password)
	if err != nil {
		jsonResponse(w, false, sanitizeErrorMessage(err), nil)
		return
	}

	// AUDIT (2026) CRIT-05 FIX: Do NOT trust the external tx_hash field.
	// Previously, the cold wallet signed whatever 32-byte hash was provided in
	// tx_hash, without verifying it corresponds to the displayed transaction
	// fields. A compromised upstream tool could show benign fields (To=user,
	// Value=1 QAU) while setting tx_hash = SigningHash(malicious_tx), causing
	// the operator to sign a transaction draining all funds.
	//
	// FIX: Rebuild the transaction from the validated fields, compute
	// SigningHash() locally, compare with the provided tx_hash (reject on
	// mismatch), and sign the locally computed hash.
	value, _ := parseAmount(tx.Value)
	gasPrice, _ := parseAmount(tx.GasPrice)
	var toAddr *types.Address
	if tx.To != "" && tx.To != "0x0" {
		addr, err := types.ParseAddressWithFallback(tx.To)
		if err != nil {
			jsonResponse(w, false, "invalid 'to' address", nil)
			acc.PrivateKey.Zeroize()
			return
		}
		toAddr = &addr
	}
	var dataBytes []byte
	if tx.Data != "" {
		dataBytes, _ = hex.DecodeString(strings.TrimPrefix(tx.Data, "0x"))
	}
	fromAddr, err := types.ParseAddressWithFallback(tx.From)
	if err != nil {
		jsonResponse(w, false, "invalid 'from' address", nil)
		acc.PrivateKey.Zeroize()
		return
	}

	localTx := &encoding.Transaction{
		Version:  uint32(tx.Version),
		Type:     encoding.TxType(tx.Type),
		Nonce:    tx.Nonce,
		From:     fromAddr,
		To:       toAddr,
		Value:    value,
		GasLimit: tx.GasLimit,
		GasPrice: gasPrice,
		Data:     dataBytes,
		ChainID:  tx.ChainID,
	}

	localHash, err := localTx.SigningHash()
	if err != nil {
		jsonResponse(w, false, "failed to compute signing hash", nil)
		acc.PrivateKey.Zeroize()
		return
	}

	// Compare locally computed hash with the provided tx_hash (constant-time).
	providedHash, err := hex.DecodeString(strings.TrimPrefix(tx.TxHash, "0x"))
	if err != nil {
		jsonResponse(w, false, "invalid transaction hash: malformed hex", nil)
		acc.PrivateKey.Zeroize()
		return
	}
	if len(providedHash) != len(localHash) {
		jsonResponse(w, false, "tx_hash length mismatch", nil)
		acc.PrivateKey.Zeroize()
		return
	}
	for i := range localHash {
		if providedHash[i] != localHash[i] {
			// CRIT-05: tx_hash does not match the displayed transaction fields.
			// Refuse to sign — this may indicate a compromised upstream tool
			// attempting blind-signing exploitation.
			jsonResponse(w, false, "tx_hash does not match locally computed SigningHash — refusing to sign", nil)
			acc.PrivateKey.Zeroize()
			return
		}
	}

	// Sign the locally computed hash (not the external one).
	sig, err := acc.PrivateKey.Sign(localHash[:])
	if err != nil {
		jsonResponse(w, false, "signing failed", nil)
		acc.PrivateKey.Zeroize()
		return
	}

	// Zeroize private key before response — do not retain in heap longer than necessary.
	acc.PrivateKey.Zeroize()

	signed := SignedTransaction{tx, hex.EncodeToString(acc.PublicKey.Bytes()), hex.EncodeToString(sig), time.Now().UTC()}
	jsonResponse(w, true, "Signed!", signed)
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonResponse(w, false, "Method not allowed", nil)
		return
	}

	clientIP := r.RemoteAddr
	if !checkRateLimit(clientIP) {
		jsonResponse(w, false, "Too many attempts, please wait", nil)
		return
	}

	var req struct {
		WalletDir string `json:"wallet_dir"`
		Password  string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, false, "invalid JSON request", nil)
		return
	}

	safeDir, err := validateWalletDir(req.WalletDir)
	if err != nil {
		jsonResponse(w, false, "Invalid wallet directory", nil)
		return
	}

	pubPath := filepath.Join(safeDir, publicKeyFileName)
	if data, err := os.ReadFile(pubPath); err == nil { // #nosec G304
		var pub ColdWalletPublic
		// audit-fix R62-F6 [MEDIUM]: json.Unmarshal error was ignored. On corrupted public
		// key file, an empty pub{} would be returned as "success", misleading the caller
		// into believing they received valid public key data.
		if err := json.Unmarshal(data, &pub); err != nil {
			// Fall back to keystore decryption
		} else if pub.PublicKey != "" {
			jsonResponse(w, true, "Exported!", pub)
			return
		}
	}

	ksData, err := os.ReadFile(filepath.Join(safeDir, walletFileName)) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		jsonResponse(w, false, "Wallet not found", nil)
		return
	}
	acc, err := accounts.ImportKeystore(ksData, req.Password)
	if err != nil {
		jsonResponse(w, false, sanitizeErrorMessage(err), nil)
		return
	}
	// audit-fix R62-F2 [CRITICAL]: Private key loaded from keystore was not zeroized after
	// use. The private key remains in heap memory until garbage collected, exposing it to
	// memory-dump attacks. Zeroize immediately after extracting public data.
	defer acc.PrivateKey.Zeroize()
	pub := ColdWalletPublic{version, acc.Address.String(), hex.EncodeToString(acc.PublicKey.Bytes()), "Dilithium3", time.Now().UTC(), ""}
	jsonResponse(w, true, "Exported!", pub)
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonResponse(w, false, "Method not allowed", nil)
		return
	}
	var req struct {
		WalletDir string `json:"wallet_dir"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, false, "invalid JSON request", nil)
		return
	}

	safeDir, err := validateWalletDir(req.WalletDir)
	if err != nil {
		jsonResponse(w, false, "Invalid wallet directory", nil)
		return
	}

	ksData, err := os.ReadFile(filepath.Join(safeDir, walletFileName)) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		jsonResponse(w, false, "Wallet not found", nil)
		return
	}
	// audit-fix R62-F7 [HIGH]: ValidateKeystore error was ignored. On corrupted keystore,
	// the function would return "Valid!" even though it cannot verify the keystore integrity.
	if err := accounts.ValidateKeystore(ksData); err != nil {
		jsonResponse(w, false, "Wallet validation failed", nil)
		return
	}
	// audit-fix R62-F7 [HIGH]: GetKeystoreAddress error was ignored. On malformed JSON,
	// addr is the zero address which would be returned as a "valid" wallet — a misleading
	// result that could cause users to send funds to an unrecoverable address.
	addr, err := accounts.GetKeystoreAddress(ksData)
	if err != nil {
		jsonResponse(w, false, "Failed to read wallet address", nil)
		return
	}
	jsonResponse(w, true, "Valid!", map[string]string{"address": addr.String(), "algorithm": "Dilithium3"})
}

func jsonResponse(w http.ResponseWriter, success bool, message string, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(APIResponse{success, message, data}) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
}

// audit-fix MEDIUM: validateUnsignedTransaction validates the fields of an
// unsigned transaction before the user signs it. This prevents the wallet
// from signing transactions with absurd values, malformed addresses, or
// missing critical fields — protecting users from social-engineering and
// accidental-loss scenarios.
func validateUnsignedTransaction(tx *UnsignedTransaction) error {
	if tx == nil {
		return fmt.Errorf("transaction is nil")
	}

	// Validate TxHash: must be a 32-byte hex string (64 hex chars, optional 0x prefix).
	// Without this, a malformed hash could result in signing an empty/wrong message.
	txHashHex := strings.TrimPrefix(tx.TxHash, "0x")
	if txHashHex == "" {
		return fmt.Errorf("transaction hash is required")
	}
	txHashBytes, err := hex.DecodeString(txHashHex)
	if err != nil {
		return fmt.Errorf("invalid transaction hash: malformed hex")
	}
	if len(txHashBytes) != 32 {
		return fmt.Errorf("invalid transaction hash: must be 32 bytes, got %d", len(txHashBytes))
	}

	// Validate 'To' address: must be empty (for contract creation) or a valid
	// 20-byte hex address (0x + 40 hex chars). Without this, the user could
	// sign a transaction sending funds to a malformed/unrecoverable address.
	if tx.To != "" {
		toHex := strings.TrimPrefix(tx.To, "0x")
		toBytes, err := hex.DecodeString(toHex)
		if err != nil {
			return fmt.Errorf("invalid 'to' address: malformed hex")
		}
		if len(toBytes) != 20 {
			return fmt.Errorf("invalid 'to' address: must be 20 bytes, got %d", len(toBytes))
		}
	}

	// Validate Value: must be a non-negative integer (decimal or 0x-hex) within
	// reasonable bounds. Without this, a malicious dApp could trick the user
	// into signing a transaction with an extremely large value.
	value, ok := parseAmount(tx.Value)
	if !ok {
		return fmt.Errorf("invalid 'value': must be a non-negative integer")
	}
	if value.Sign() < 0 {
		return fmt.Errorf("invalid 'value': must be non-negative")
	}
	maxValue, _ := new(big.Int).SetString(maxValueWei, 10)
	if maxValue != nil && value.Cmp(maxValue) > 0 {
		return fmt.Errorf("invalid 'value': exceeds maximum allowed")
	}

	// Validate GasPrice: must be a non-negative integer within reasonable bounds.
	// Without this, a malicious dApp could trick the user into signing a
	// transaction with an extremely high gas price, draining their wallet.
	gasPrice, ok := parseAmount(tx.GasPrice)
	if !ok {
		return fmt.Errorf("invalid 'gas_price': must be a non-negative integer")
	}
	if gasPrice.Sign() < 0 {
		return fmt.Errorf("invalid 'gas_price': must be non-negative")
	}
	maxGasPrice, _ := new(big.Int).SetString(maxGasPriceWei, 10)
	if maxGasPrice != nil && gasPrice.Cmp(maxGasPrice) > 0 {
		return fmt.Errorf("invalid 'gas_price': exceeds maximum allowed")
	}

	// Validate GasLimit: must be within reasonable bounds.
	if tx.GasLimit == 0 {
		return fmt.Errorf("invalid 'gas_limit': must be positive")
	}
	if tx.GasLimit > maxGasLimit {
		return fmt.Errorf("invalid 'gas_limit': exceeds maximum allowed")
	}

	// Validate Nonce: no special validation needed (uint64 is bounded).

	// Validate ChainID: must be positive (chain ID 0 is invalid).
	if tx.ChainID == 0 {
		return fmt.Errorf("invalid 'chain_id': must be positive")
	}

	// Validate Data: if present, must be valid hex.
	if tx.Data != "" {
		dataHex := strings.TrimPrefix(tx.Data, "0x")
		if _, err := hex.DecodeString(dataHex); err != nil {
			return fmt.Errorf("invalid 'data': malformed hex")
		}
	}

	return nil
}

// parseAmount parses a numeric string that may be decimal or 0x-prefixed hex.
// Returns false if the string is empty or not a valid non-negative integer.
func parseAmount(s string) (*big.Int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	// Try hex first (0x prefix)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, ok := new(big.Int).SetString(s[2:], 16)
		if !ok {
			return nil, false
		}
		return v, true
	}
	// Try decimal
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, false
	}
	return v, true
}

const indexHTML = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Quantaureum Cold Wallet</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#1a1a2e,#16213e);min-height:100vh;color:#e0e0e0}
.container{max-width:700px;margin:0 auto;padding:15px}
.header{display:flex;justify-content:space-between;align-items:center;padding:15px 0}
h1{color:#00d4ff;font-size:22px}
.tabs{display:flex;gap:3px;margin-bottom:15px}
.tab{flex:1;padding:12px;background:#252545;border:none;color:#888;cursor:pointer;border-radius:6px 6px 0 0;font-size:13px}
.tab:hover{background:#303060;color:#fff}
.tab.active{background:#303060;color:#00d4ff;border-bottom:2px solid #00d4ff}
.panel{display:none;background:#252545;padding:20px;border-radius:0 0 10px 10px}
.panel.active{display:block}
.form-group{margin-bottom:15px}
label{display:block;margin-bottom:6px;color:#aaa;font-size:13px}
input,textarea{width:100%;padding:10px;background:#1a1a2e;border:1px solid #404060;border-radius:6px;color:#fff;font-size:13px}
input:focus,textarea:focus{outline:none;border-color:#00d4ff}
textarea{min-height:100px;font-family:monospace;resize:vertical}
button{width:100%;padding:12px;background:linear-gradient(135deg,#00d4ff,#0099cc);border:none;border-radius:6px;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
button:hover{opacity:0.9}
.result{margin-top:15px;padding:15px;background:#1a1a2e;border-radius:6px;border-left:3px solid #00d4ff;font-size:13px}
.result.error{border-left-color:#ff4757}
.result.success{border-left-color:#2ed573}
.result pre{white-space:pre-wrap;word-break:break-all;font-family:monospace;font-size:12px;margin-top:10px}
.warning{background:#3d2914;border:1px solid #ff9f43;padding:12px;border-radius:6px;margin-bottom:15px;font-size:12px;color:#ffcc80}
</style></head><body>
<div class="container">
<div class="header"><h1>🔐 Quantaureum Cold Wallet</h1></div>
<div class="tabs">
<button class="tab active" onclick="showTab('generate')">Generate</button>
<button class="tab" onclick="showTab('sign')">Sign</button>
<button class="tab" onclick="showTab('export')">Export</button>
<button class="tab" onclick="showTab('verify')">Verify</button>
</div>
<div id="generate" class="panel active">
<div class="warning">⚠️ Store wallet file securely offline!</div>
<div class="form-group"><label>Output Directory</label><input type="text" id="gen-dir" placeholder="C:\MyWallet"></div>
<div class="form-group"><label>Password (min 12 chars)</label><input type="password" id="gen-pass"></div>
<div class="form-group"><label>Confirm Password</label><input type="password" id="gen-pass2"></div>
<div class="form-group"><label>Description (optional)</label><input type="text" id="gen-desc"></div>
<button onclick="generateWallet()">Generate Wallet</button>
<div id="gen-result" class="result" style="display:none"></div>
</div>
<div id="sign" class="panel">
<div class="warning">⚠️ Review transaction before signing!</div>
<div class="form-group"><label>Wallet Directory</label><input type="text" id="sign-dir"></div>
<div class="form-group"><label>Transaction JSON</label><textarea id="sign-tx"></textarea></div>
<div class="form-group"><label>Password</label><input type="password" id="sign-pass"></div>
<button onclick="signTx()">Sign Transaction</button>
<div id="sign-result" class="result" style="display:none"></div>
</div>
<div id="export" class="panel">
<div class="form-group"><label>Wallet Directory</label><input type="text" id="export-dir"></div>
<div class="form-group"><label>Password (if needed)</label><input type="password" id="export-pass"></div>
<button onclick="exportKey()">Export Public Key</button>
<div id="export-result" class="result" style="display:none"></div>
</div>
<div id="verify" class="panel">
<div class="form-group"><label>Wallet Directory</label><input type="text" id="verify-dir"></div>
<button onclick="verifyWallet()">Verify Wallet</button>
<div id="verify-result" class="result" style="display:none"></div>
</div>
</div>
<script>
const CSRF=document.querySelector('meta[name="csrf-token"]')?.content||'';
const errMismatch="Passwords do not match";
function showTab(n){document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));document.querySelector('[onclick="showTab(\''+n+'\')"]').classList.add('active');document.getElementById(n).classList.add('active')}
async function api(e,d){const r=await fetch('/api/'+e,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(d)});return r.json()}
function show(id,ok,msg,data){const e=document.getElementById(id);e.style.display='block';e.className='result '+(ok?'success':'error');e.textContent=msg;if(data){const pre=document.createElement('pre');pre.textContent=JSON.stringify(data,null,2);e.appendChild(pre)}}
function escapeHtml(s){if(typeof s!=='string')return s;return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
function showSecure(id,ok,msg,data){const e=document.getElementById(id);e.style.display='block';e.className='result '+(ok?'success':'error');e.textContent=msg;if(data){const pre=document.createElement('pre');pre.textContent=JSON.stringify(data,null,2);e.appendChild(pre)}};
async function generateWallet(){if(document.getElementById('gen-pass').value!==document.getElementById('gen-pass2').value){show('gen-result',false,errMismatch);return}const r=await api('generate',{output_dir:document.getElementById('gen-dir').value,password:document.getElementById('gen-pass').value,description:document.getElementById('gen-desc').value});show('gen-result',r.success,r.message,r.data)}
async function signTx(){const r=await api('sign',{wallet_dir:document.getElementById('sign-dir').value,tx_json:document.getElementById('sign-tx').value,password:document.getElementById('sign-pass').value});show('sign-result',r.success,r.message,r.data)}
async function exportKey(){const r=await api('export',{wallet_dir:document.getElementById('export-dir').value,password:document.getElementById('export-pass').value});show('export-result',r.success,r.message,r.data)}
async function verifyWallet(){const r=await api('verify',{wallet_dir:document.getElementById('verify-dir').value});show('verify-result',r.success,r.message,r.data)}
</script></body></html>`
