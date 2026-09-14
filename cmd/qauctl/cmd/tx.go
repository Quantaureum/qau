// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the qauctl management tool.
package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"github.com/spf13/cobra"
)

func newTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tx",
		Short: "Create, sign, and send transactions",
		Long: `Create, sign, and send transactions on the Quantaureum blockchain.

Transactions are signed OFFLINE using a local key (from keystore), then sent
via eth_sendRawTransaction. This is the secure way to send transactions —
your private key never leaves your machine.

Examples:
  # Sign a transfer offline
  qauctl tx sign --from QAU... --to QAU... --value 10 --chain-id 1668 --nonce 0

  # Sign and send in one step (fetches nonce from RPC)
  qauctl tx sign --from 0xdF6F... --to 0xcdf5... --value 10 --chain-id 1668 --rpc http://localhost:8545 --send

  # Send a signed transaction
  qauctl tx send <hex-encoded-tx> --rpc https://rpc.quantaureum.com`,
	}

	cmd.AddCommand(newTxSignCmd())
	cmd.AddCommand(newTxSendCmd())

	return cmd
}

func newTxSignCmd() *cobra.Command {
	var (
		fromAddr     string
		toAddr       string
		value        string
		gasLimit     string
		gasPrice     string
		nonce        string
		data         string
		chainID      uint64
		passwordFile string
		autoSend     bool
	)

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a transaction offline",
		Long: `Sign a transaction using a local key from the keystore.

The signed transaction is output as hex (protobuf-encoded) to stdout.
Use 'qauctl tx send <hex>' to broadcast it to the network.

If --rpc is provided, nonce will be fetched automatically. Otherwise,
--nonce must be specified manually.

Examples:
  # Sign a 10 QAU transfer with auto nonce
  qauctl tx sign --from 0xdF6F... --to 0xcdf5... --value 10 --chain-id 1668 --rpc http://localhost:8545

  # Sign with manual nonce (fully offline)
  qauctl tx sign --from QAU... --to QAU... --value 10 --chain-id 1668 --nonce 5

  # Sign a contract call (release())
  qauctl tx sign --from 0xdF6F... --to 0xContract --data 0x15e4167e --chain-id 1668 --rpc http://localhost:8545`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pwd, err := resolvePassword(passwordFile, "Enter keystore password: ", false)
			if err != nil {
				return err
			}
			defer crypto.ZeroBytesSecure(pwd)
			return signTx(fromAddr, toAddr, value, gasLimit, gasPrice, nonce, data, chainID, pwd, autoSend)
		},
	}

	cmd.Flags().StringVar(&fromAddr, "from", "", "Sender address (QAU... or 0x...)")
	cmd.Flags().StringVar(&toAddr, "to", "", "Recipient address (QAU... or 0x...)")
	cmd.Flags().StringVar(&value, "value", "0", "Amount to send in QAU (e.g. 10 = 10 QAU = 10^19 wei)")
	cmd.Flags().StringVar(&gasLimit, "gas-limit", "21000", "Gas limit")
	cmd.Flags().StringVar(&gasPrice, "gas-price", "1", "Gas price in wei")
	cmd.Flags().StringVar(&nonce, "nonce", "", "Nonce (auto-fetched if --rpc is set)")
	cmd.Flags().StringVar(&data, "data", "", "Transaction data (hex, for contract calls)")
	cmd.Flags().Uint64Var(&chainID, "chain-id", 1668, "Chain ID (mainnet=1668, testnet=1669)")
	// AUDIT (2026) KEYS-12: Use --password-file instead of --password
	// (passwords on the command line are visible in ps/proc/shell history).
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read password from file (alternatives: QAU_KEYSTORE_PASSWORD env var or interactive prompt)")
	cmd.Flags().BoolVar(&autoSend, "send", false, "Also broadcast the signed transaction")

	return cmd
}

func newTxSendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send <hex-encoded-tx>",
		Short: "Send a signed transaction to the network",
		Long: `Send a signed transaction (hex-encoded protobuf) to the network via eth_sendRawTransaction.

Example:
  qauctl tx send 0a01080a... --rpc https://rpc.quantaureum.com`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return sendTx(args[0])
		},
	}

	return cmd
}

// signTx signs a transaction using a local key and outputs the hex-encoded signed transaction.
// AUDIT (2026) KEYS-12: password is now []byte (wiped by caller via defer).
func signTx(fromAddr, toAddr, valueStr, gasLimitStr, gasPriceStr, nonceStr, dataHex string, chainID uint64, password []byte, autoSend bool) error {
	// Parse from address
	from, err := parseAnyAddress(fromAddr)
	if err != nil {
		return fmt.Errorf("invalid --from address: %w", err)
	}

	// Parse to address
	var to *types.Address
	if toAddr != "" {
		t, err := parseAnyAddress(toAddr)
		if err != nil {
			return fmt.Errorf("invalid --to address: %w", err)
		}
		to = &t
	}

	// Parse value (accept QAU as decimal or wei as hex 0x...)
	valueWei, err := parseAmount(valueStr)
	if err != nil {
		return fmt.Errorf("invalid --value: %w", err)
	}

	// Parse gas limit
	gasLimit, err := parseUint64(gasLimitStr)
	if err != nil {
		return fmt.Errorf("invalid --gas-limit: %w", err)
	}

	// Parse gas price
	gasPriceWei, err := parseBigInt(gasPriceStr)
	if err != nil {
		return fmt.Errorf("invalid --gas-price: %w", err)
	}

	// Parse nonce
	var nonceVal uint64
	if nonceStr != "" {
		nonceVal, err = parseUint64(nonceStr)
		if err != nil {
			return fmt.Errorf("invalid --nonce: %w", err)
		}
	} else {
		// Auto-fetch nonce from RPC (use original hex string for RPC)
		n, err := fetchNonce(addressToHex(from))
		if err != nil {
			return fmt.Errorf("failed to fetch nonce (use --nonce for offline signing): %w", err)
		}
		nonceVal = n
	}

	// Parse data
	var txData []byte
	if dataHex != "" {
		dataHex = strings.TrimPrefix(dataHex, "0x")
		txData, err = hex.DecodeString(dataHex)
		if err != nil {
			return fmt.Errorf("invalid --data hex: %w", err)
		}
	}

	// Build transaction
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    nonceVal,
		From:     from,
		To:       to,
		Value:    valueWei,
		GasLimit: gasLimit,
		GasPrice: gasPriceWei,
		Data:     txData,
		ChainID:  chainID,
	}

	if txData != nil && len(txData) > 0 {
		tx.Type = encoding.TxTypeContract
	}

	// Load private key from keystore
	privateKey, err := loadKeyFromKeystore(from, password)
	if err != nil {
		return fmt.Errorf("failed to load key: %w", err)
	}
	defer privateKey.Destroy()

	// Get public key
	pubKeyBytes := privateKey.PublicKeyBytes()
	if pubKeyBytes == nil {
		return fmt.Errorf("failed to derive public key")
	}

	// Compute signing hash
	signingHash, err := tx.SigningHash()
	if err != nil {
		return fmt.Errorf("compute signing hash: %w", err)
	}

	// Sign
	signature, err := crypto.Sign(privateKey, signingHash[:])
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Set signature and public key on transaction
	tx.Signature = signature
	tx.PublicKey = pubKeyBytes

	// Marshal to protobuf
	txBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %w", err)
	}

	// Output hex
	txHex := hex.EncodeToString(txBytes)
	txHash := tx.Hash()

	fmt.Printf("Transaction signed successfully!\n")
	fmt.Printf("  From:      %s\n", from.String())
	if to != nil {
		fmt.Printf("  To:        %s\n", to.String())
	}
	fmt.Printf("  Value:     %s wei\n", valueWei.String())
	fmt.Printf("  Gas Limit: %d\n", gasLimit)
	fmt.Printf("  Gas Price: %s wei\n", gasPriceWei.String())
	fmt.Printf("  Nonce:     %d\n", nonceVal)
	fmt.Printf("  Chain ID:  %d\n", chainID)
	fmt.Printf("  Tx Hash:   %s\n", txHash.String())
	fmt.Printf("\nSigned Transaction (hex):\n%s\n", txHex)

	if autoSend {
		fmt.Println()
		return sendRawTxHex(txHex)
	}

	return nil
}

// sendTx sends a signed transaction hex to the network.
func sendTx(txHex string) error {
	txHex = strings.TrimSpace(txHex)
	if txHex == "" {
		return fmt.Errorf("transaction hex is empty")
	}

	return sendRawTxHex(txHex)
}

// sendRawTxHex sends a hex-encoded signed transaction via eth_sendRawTransaction.
func sendRawTxHex(txHex string) error {
	// Ensure 0x prefix for the RPC call
	if !strings.HasPrefix(txHex, "0x") {
		txHex = "0x" + txHex
	}

	result, err := rpcCall("eth_sendRawTransaction", []any{txHex})
	if err != nil {
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("Transaction broadcast successfully!\n")
	fmt.Printf("  Tx Hash: %s\n", txHash)
	fmt.Printf("  Track with: qauctl status tx %s\n", txHash)

	return nil
}

// loadKeyFromKeystore loads and decrypts a private key from the keystore.
// AUDIT (2026) KEYS-12: password is []byte; caller wipes via defer.
func loadKeyFromKeystore(addr types.Address, password []byte) (*crypto.PrivateKey, error) {
	addrStr := addr.String()
	keyPath, err := findKeyFile(addrStr)
	if err != nil {
		return nil, fmt.Errorf("key not found in keystore for %s: %w", addrStr, err)
	}

	privateKey, err := loadKeyFile(keyPath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	return privateKey, nil
}

// fetchNonce fetches the current nonce for an address via RPC.
func fetchNonce(addrHex string) (uint64, error) {
	result, err := rpcCall("eth_getTransactionCount", []any{addrHex, "latest"})
	if err != nil {
		return 0, err
	}

	var nonceHex string
	if err := json.Unmarshal(result, &nonceHex); err != nil {
		return 0, fmt.Errorf("failed to parse nonce: %w", err)
	}

	return parseUint64(nonceHex)
}

// addressToHex converts a types.Address to 0x-prefixed hex string for RPC calls.
func addressToHex(addr types.Address) string {
	return fmt.Sprintf("0x%x", addr[:])
}

// parseAnyAddress parses an address in either 0x hex or QAU base32 format.
func parseAnyAddress(s string) (types.Address, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return types.Address{}, fmt.Errorf("empty address")
	}

	// Try QAU prefix format first
	if strings.HasPrefix(s, types.AddressPrefix) {
		return types.ParseAddress(s)
	}

	// Try 0x hex format
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	b, err := hex.DecodeString(s)
	if err != nil {
		return types.Address{}, fmt.Errorf("invalid hex address: %w", err)
	}
	if len(b) != types.AddressLength {
		return types.Address{}, fmt.Errorf("hex address must be %d bytes, got %d", types.AddressLength, len(b))
	}
	var addr types.Address
	copy(addr[:], b)
	return addr, nil
}

// qauDecimals is the number of decimal places in 1 QAU (10^18 wei = 1 QAU).
const qauDecimals = 18

// qauWeiPerUnit is 10^18 — the number of wei in 1 QAU.
var qauWeiPerUnit = new(big.Int).Exp(big.NewInt(10), big.NewInt(qauDecimals), nil)

// parseAmount parses an amount string as either decimal QAU or hex wei.
//
// AUDIT (2026) KEYS-13 FIX: Previously used big.Float for decimal-to-wei
// conversion, which loses precision for 18-decimal QAU values
// (big.NewFloat(1e18) is inexact, and big.Float.Int truncates toward zero).
// Also, big.Int.SetString's second return value (ok) was discarded, so invalid
// input silently became 0 (e.g. "abc" → 0 wei → unintended zero-value
// transfer). Now uses pure integer math via decimalQauToWei and validates
// SetString's ok flag everywhere.
func parseAmount(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return new(big.Int), nil
	}

	// If 0x prefix, treat as hex wei (no scaling).
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
		val := new(big.Int)
		if _, ok := val.SetString(s, 16); !ok {
			return nil, fmt.Errorf("invalid hex amount: %q", s)
		}
		return val, nil
	}

	// Treat as decimal QAU → convert to wei (× 10^18) using integer math.
	return decimalQauToWei(s)
}

// decimalQauToWei converts a decimal QAU string (e.g. "0.5", "10.25", "123")
// to wei using pure integer math. Rejects negative values and values with
// more than 18 fractional digits (sub-wei precision is not representable).
func decimalQauToWei(s string) (*big.Int, error) {
	if s == "" {
		return nil, fmt.Errorf("empty amount")
	}
	if s[0] == '-' {
		return nil, fmt.Errorf("negative amount: %q", s)
	}

	if !strings.ContainsRune(s, '.') {
		wei := new(big.Int)
		if _, ok := wei.SetString(s, 10); !ok {
			return nil, fmt.Errorf("invalid integer amount: %q", s)
		}
		return wei.Mul(wei, qauWeiPerUnit), nil
	}

	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid decimal amount: %q", s)
	}
	intPart, fracPart := parts[0], parts[1]
	if intPart == "" && fracPart == "" {
		return nil, fmt.Errorf("invalid decimal amount: %q", s)
	}
	if len(fracPart) > qauDecimals {
		return nil, fmt.Errorf("too many fractional digits (%d > %d): %q",
			len(fracPart), qauDecimals, s)
	}

	// Pad fractional part to exactly qauDecimals digits with trailing zeros.
	// "0.5" → frac="5" → padded="500000000000000000" (18 digits).
	paddedFrac := fracPart + strings.Repeat("0", qauDecimals-len(fracPart))

	// Concatenate integer+fractional as a single integer (already in wei units).
	combined := intPart + paddedFrac
	combined = strings.TrimLeft(combined, "0")
	if combined == "" {
		return new(big.Int), nil
	}

	wei := new(big.Int)
	if _, ok := wei.SetString(combined, 10); !ok {
		return nil, fmt.Errorf("invalid decimal amount: %q", s)
	}
	return wei, nil
}

// parseUint64 parses a string as uint64 (supports 0x hex and decimal).
//
// AUDIT (2026) KEYS-13 FIX: Check SetString return value (ok) to reject
// invalid input rather than silently treating it as 0. Also bounds-check via
// IsUint64 to avoid uint64 wraparound on overflow.
func parseUint64(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
		val := new(big.Int)
		if _, ok := val.SetString(s, 16); !ok {
			return 0, fmt.Errorf("invalid hex uint64: %q", s)
		}
		if !val.IsUint64() {
			return 0, fmt.Errorf("hex uint64 out of range: %q", s)
		}
		return val.Uint64(), nil
	}
	val := new(big.Int)
	if _, ok := val.SetString(s, 10); !ok {
		return 0, fmt.Errorf("invalid decimal uint64: %q", s)
	}
	if !val.IsUint64() {
		return 0, fmt.Errorf("decimal uint64 out of range: %q", s)
	}
	return val.Uint64(), nil
}

// parseBigInt parses a string as *big.Int (supports 0x hex and decimal).
//
// AUDIT (2026) KEYS-13 FIX: Check SetString return value (ok) to reject
// invalid input rather than silently treating it as 0.
func parseBigInt(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
		val := new(big.Int)
		if _, ok := val.SetString(s, 16); !ok {
			return nil, fmt.Errorf("invalid hex big.Int: %q", s)
		}
		return val, nil
	}
	val := new(big.Int)
	if _, ok := val.SetString(s, 10); !ok {
		return nil, fmt.Errorf("invalid decimal big.Int: %q", s)
	}
	return val, nil
}
