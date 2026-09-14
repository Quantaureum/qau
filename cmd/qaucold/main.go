// Quantaureum Node source, version 1.0.0.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quantaureum/qau/accounts"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	walletFileName    = "wallet.json"
	publicKeyFileName = "public.json"
	version           = "1.0.0"
)

// audit-fix MEDIUM: Upper-bound guards for transaction fields. These protect
// users from signing transactions with absurd values that could drain their
// wallet or be used in social-engineering attacks.
const (
	// maxValueWei is the maximum allowed transaction value (100 billion QAU in wei).
	maxValueWei = "100000000000000000000000000000"
	// maxGasPriceWei is the maximum allowed gas price (1 TQAU = 1e21 wei).
	maxGasPriceWei = "1000000000000000000000"
	// maxGasLimit is the maximum allowed gas limit.
	maxGasLimit = 30_000_000
)

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

var rootCmd = &cobra.Command{
	Use:   "qaucold",
	Short: "Quantaureum Cold Wallet Tool",
	Long:  "A quantum-safe cold wallet tool for Quantaureum blockchain.",
}

var generateCmd = &cobra.Command{Use: "generate", Short: "Generate new cold wallet", RunE: runGenerate}
var signCmd = &cobra.Command{Use: "sign", Short: "Sign transaction offline", RunE: runSign}
var exportCmd = &cobra.Command{Use: "export", Short: "Export public key", RunE: runExport}
var verifyCmd = &cobra.Command{Use: "verify", Short: "Verify wallet", RunE: runVerify}

var walletDir, txFile, outputFile, description string

func init() {
	generateCmd.Flags().StringVarP(&walletDir, "output", "o", "", "Output directory")
	generateCmd.Flags().StringVarP(&description, "desc", "d", "", "Description")
	generateCmd.MarkFlagRequired("output") // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	signCmd.Flags().StringVarP(&walletDir, "wallet", "w", "", "Wallet directory")
	signCmd.Flags().StringVarP(&txFile, "tx", "t", "", "Transaction file")
	signCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file")
	signCmd.MarkFlagRequired("wallet") // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	signCmd.MarkFlagRequired("tx")     // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	exportCmd.Flags().StringVarP(&walletDir, "wallet", "w", "", "Wallet directory")
	exportCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file")
	exportCmd.MarkFlagRequired("wallet") // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	verifyCmd.Flags().StringVarP(&walletDir, "wallet", "w", "", "Wallet directory")
	verifyCmd.MarkFlagRequired("wallet") // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	rootCmd.AddCommand(generateCmd, signCmd, exportCmd, verifyCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runGenerate(cmd *cobra.Command, args []string) error {
	fmt.Println("=== QUANTAUREUM COLD WALLET GENERATOR ===")
	if _, err := os.Stat(walletDir); os.IsNotExist(err) {
		// audit-fix R3-M5: check MkdirAll error
		if err := os.MkdirAll(walletDir, 0700); err != nil {
			return fmt.Errorf("failed to create wallet directory: %w", err)
		}
	}
	walletPath := filepath.Join(walletDir, walletFileName)
	if _, err := os.Stat(walletPath); err == nil {
		return fmt.Errorf("wallet exists at %s", walletPath)
	}
	password, err := getPasswordWithConfirm("Password (min 12 chars): ")
	if err != nil {
		return err
	}
	if len(password) < 12 {
		return fmt.Errorf("password too short")
	}
	fmt.Println("Generating Dilithium3 key pair...")
	// audit-fix R3-M5: check all errors
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}
	// audit-fix R3-H1 / LEGACY-2: Use Zeroize for deterministic multi-pass key zeroing
	defer keyPair.Private.Zeroize()

	account, err := accounts.NewAccountFromPrivateKey(keyPair.Private)
	if err != nil {
		return fmt.Errorf("failed to create account: %w", err)
	}
	fmt.Println("Encrypting...")
	data, err := accounts.ExportKeystoreWithParams(account, password, accounts.DefaultKeystoreParams())
	if err != nil {
		return fmt.Errorf("failed to export keystore: %w", err)
	}
	if err := os.WriteFile(walletPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write wallet: %w", err)
	}
	pub := ColdWalletPublic{version, account.Address.String(), hex.EncodeToString(keyPair.Public.Bytes()), "Dilithium3", time.Now().UTC(), description}
	pubData, err := json.MarshalIndent(pub, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(walletDir, publicKeyFileName), pubData, 0600); err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}
	fmt.Printf("\nAddress: %s\nWallet: %s\n", account.Address.String(), walletPath)
	return nil
}

func runSign(cmd *cobra.Command, args []string) error {
	fmt.Println("=== OFFLINE SIGNER ===")
	// audit-fix R3-M5: check all errors
	txData, err := os.ReadFile(txFile) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to read transaction file: %w", err)
	}
	var tx UnsignedTransaction
	if err := json.Unmarshal(txData, &tx); err != nil {
		return fmt.Errorf("failed to parse transaction: %w", err)
	}
	// audit-fix MEDIUM: Validate transaction fields before signing to prevent
	// the user from signing a transaction with absurd values, malformed
	// addresses, or missing critical fields. Without this, a malicious or
	// corrupted transaction file could trick the user into signing a
	// transaction that drains their wallet or sets an extreme gas price.
	if err := validateUnsignedTransaction(&tx); err != nil {
		return fmt.Errorf("invalid transaction: %w", err)
	}
	fmt.Printf("To: %s\nValue: %s\n", tx.To, tx.Value)
	fmt.Print("Sign? (yes/no): ")
	r := bufio.NewReader(os.Stdin)
	c, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}
	if strings.TrimSpace(c) != "yes" {
		return nil
	}
	ksData, err := os.ReadFile(filepath.Join(walletDir, walletFileName)) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to read wallet: %w", err)
	}
	pw, err := getPassword("Password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	acc, err := accounts.ImportKeystore(ksData, pw)
	if err != nil {
		return err
	}
	// audit-fix R3-H1 / LEGACY-2: Use Zeroize for deterministic multi-pass key zeroing
	defer acc.PrivateKey.Zeroize()

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
			return fmt.Errorf("invalid 'to' address: %w", err)
		}
		toAddr = &addr
	}
	var dataBytes []byte
	if tx.Data != "" {
		dataBytes, _ = hex.DecodeString(strings.TrimPrefix(tx.Data, "0x"))
	}
	fromAddr, err := types.ParseAddressWithFallback(tx.From)
	if err != nil {
		return fmt.Errorf("invalid 'from' address: %w", err)
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
		return fmt.Errorf("failed to compute signing hash: %w", err)
	}

	// Compare locally computed hash with the provided tx_hash.
	providedHash, err := hex.DecodeString(strings.TrimPrefix(tx.TxHash, "0x"))
	if err != nil {
		return fmt.Errorf("invalid transaction hash: %w", err)
	}
	if len(providedHash) != len(localHash) {
		return fmt.Errorf("tx_hash length mismatch: provided %d bytes, expected %d", len(providedHash), len(localHash))
	}
	for i := range localHash {
		if providedHash[i] != localHash[i] {
			return fmt.Errorf("AUDIT CRIT-05: tx_hash does not match locally computed SigningHash — refusing to sign. " +
				"The displayed transaction fields do not match the provided hash. " +
				"This may indicate a compromised upstream tool attempting blind-signing exploitation.")
		}
	}

	// Sign the locally computed hash (not the external one).
	sig, err := acc.PrivateKey.Sign(localHash[:])
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	signed := SignedTransaction{tx, hex.EncodeToString(acc.PublicKey.Bytes()), hex.EncodeToString(sig), time.Now().UTC()}
	out, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal signed transaction: %w", err)
	}
	if outputFile != "" {
		// audit-fix R3-L1: use 0600 permissions for signed transaction file
		if err := os.WriteFile(outputFile, out, 0600); err != nil {
			return fmt.Errorf("failed to write signed transaction: %w", err)
		}
	} else {
		fmt.Println(string(out))
	}
	return nil
}

func runExport(cmd *cobra.Command, args []string) error {
	pubPath := filepath.Join(walletDir, publicKeyFileName)
	if d, err := os.ReadFile(pubPath); err == nil { // #nosec G304
		fmt.Println(string(d))
		return nil
	}
	// audit-fix R62-F1 [CRITICAL]: os.ReadFile error was ignored, causing nil ksData
	// to be passed to ImportKeystore, which would return (nil, err) — acc.Address panics.
	ksData, err := os.ReadFile(filepath.Join(walletDir, walletFileName)) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to read wallet: %w", err)
	}
	// audit-fix R62-F1 [CRITICAL]: getPassword error was ignored.
	pw, err := getPassword("Password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	// audit-fix R62-F1 [CRITICAL]: ImportKeystore error was ignored.
	// If password is wrong, acc is nil and acc.Address panics.
	acc, err := accounts.ImportKeystore(ksData, pw)
	if err != nil {
		return fmt.Errorf("failed to decrypt wallet: %w", err)
	}
	// audit-fix R62-F1: Zeroize private key immediately after extracting public data.
	defer acc.PrivateKey.Zeroize()
	pub := ColdWalletPublic{version, acc.Address.String(), hex.EncodeToString(acc.PublicKey.Bytes()), "Dilithium3", time.Now().UTC(), ""}
	out, err := json.MarshalIndent(pub, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

func runVerify(cmd *cobra.Command, args []string) error {
	ksData, err := os.ReadFile(filepath.Join(walletDir, walletFileName)) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to read wallet: %w", err)
	}
	// audit-fix R62-F1 [CRITICAL]: ValidateKeystore error was ignored.
	// On corrupted keystore, addr becomes zero address — misleading to user.
	if err := accounts.ValidateKeystore(ksData); err != nil {
		return fmt.Errorf("wallet validation failed: %w", err)
	}
	// audit-fix R62-F1 [CRITICAL]: GetKeystoreAddress error was ignored.
	// On malformed JSON, addr is zero address — security misdirection.
	addr, err := accounts.GetKeystoreAddress(ksData)
	if err != nil {
		return fmt.Errorf("failed to read wallet address: %w", err)
	}
	fmt.Printf("Address: %s\nValid: YES\n", addr.String())
	return nil
}

func getPassword(p string) (string, error) {
	fmt.Print(p)
	b, err := term.ReadPassword(int(os.Stdin.Fd())) // #nosec G115 -- stdin fd is always a small positive int
	fmt.Println()
	return string(b), err
}

func getPasswordWithConfirm(p string) (string, error) {
	pw, err := getPassword(p)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	if pw == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	c, err := getPassword("Confirm: ")
	if err != nil {
		return "", fmt.Errorf("failed to read confirmation: %w", err)
	}
	if pw != c {
		return "", fmt.Errorf("mismatch")
	}
	return pw, nil
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
	// 20-byte hex address (0x + 40 hex chars).
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

	// Validate Value: must be a non-negative integer within reasonable bounds.
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
