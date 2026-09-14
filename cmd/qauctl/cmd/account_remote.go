// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the qauctl management tool.
package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/quantaureum/qau/crypto"
	"github.com/spf13/cobra"
)

func newAccountRemoteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account-remote",
		Short: "Manage accounts on a remote node via RPC",
		Long: `Import and unlock accounts on a remote Quantaureum node via JSON-RPC.

Private key content is read from local files and sent directly to the node's
personal_importRawKey RPC method. The key content is never displayed in output.

SECURITY: Commands that transmit private keys or passwords (import, unlock)
require HTTPS unless --insecure is set. Localhost (127.0.0.1 / ::1) is exempt.

Passwords are never accepted on the command line. Use --password-file,
the QAU_KEYSTORE_PASSWORD environment variable, or interactive prompt.

Example:
  qauctl account-remote import /path/to/key.txt https://node.example.com:8545 --password-file /path/to/pass.txt
  qauctl account-remote unlock 0x08036632ada4ff720fbb5e4b8e226358280954cb https://node.example.com:8545
  qauctl account-remote list https://node.example.com:8545`,
	}

	cmd.AddCommand(newAccountRemoteImportCmd())
	cmd.AddCommand(newAccountRemoteUnlockCmd())
	cmd.AddCommand(newAccountRemoteListCmd())

	return cmd
}

func newAccountRemoteImportCmd() *cobra.Command {
	var passwordFile string

	cmd := &cobra.Command{
		Use:   "import <key-file> <rpc-url>",
		Short: "Import an account to a remote node",
		Long: `Read a private key file locally and import it to a remote node via RPC.

The key file can be in dilithium3:hex... format. The private key content
is sent directly to the node and never displayed in the output.

IMPORTANT: Remember the password you use here — you'll need it to unlock the account later.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// R40-DEPLOY FIX (2026-08-10): Make the positional <rpc-url>
			// argument actually take effect. Without this, only the global
			// --rpc flag is honored (the per-subcommand positional arg is
			// documented but ignored), forcing operators to pass both
			// "<rpc-url> dummy" + --rpc <url>. The global --rpc flag still
			// wins when explicitly set, preserving backward compatibility.
			if args[1] != "" && !cmd.Flags().Changed("rpc") {
				rpcAddr = args[1]
			}
			pwd, err := resolvePassword(passwordFile, "Enter password for key encryption: ", true)
			if err != nil {
				return err
			}
			defer crypto.ZeroBytesSecure(pwd)
			return importAccountRemote(args[0], args[1], pwd)
		},
	}

	// AUDIT (2026) KEYS-12: Use --password-file instead of --password
	// (passwords on the command line are visible in ps/proc/shell history).
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read password from file (alternatives: QAU_KEYSTORE_PASSWORD env var or interactive prompt)")

	return cmd
}

func newAccountRemoteUnlockCmd() *cobra.Command {
	var passwordFile string
	var duration int

	cmd := &cobra.Command{
		Use:   "unlock <address> <rpc-url>",
		Short: "Unlock an account on a remote node",
		Long: `Unlock an account on a remote node via RPC.

The password must match the one used when importing the account.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// R40-DEPLOY FIX (2026-08-10): Make the positional <rpc-url>
			// argument actually take effect. The global --rpc flag still
			// wins when explicitly set, preserving backward compatibility.
			if args[1] != "" && !cmd.Flags().Changed("rpc") {
				rpcAddr = args[1]
			}
			pwd, err := resolvePassword(passwordFile, "Enter password to unlock account: ", false)
			if err != nil {
				return err
			}
			defer crypto.ZeroBytesSecure(pwd)
			return unlockAccountRemote(args[0], args[1], pwd, duration)
		},
	}

	// AUDIT (2026) KEYS-12: Use --password-file instead of --password.
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read password from file (alternatives: QAU_KEYSTORE_PASSWORD env var or interactive prompt)")
	cmd.Flags().IntVarP(&duration, "duration", "d", 3600, "Unlock duration in seconds")

	return cmd
}

func newAccountRemoteListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list <rpc-url>",
		Short: "List accounts on a remote node",
		Long:  "List all accounts in the keystore of a remote node via RPC.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// R40-DEPLOY FIX (2026-08-10): Make the positional <rpc-url>
			// argument actually take effect. The global --rpc flag still
			// wins when explicitly set, preserving backward compatibility.
			if args[0] != "" && !cmd.Flags().Changed("rpc") {
				rpcAddr = args[0]
			}
			return listAccountsRemote(args[0])
		},
	}

	return cmd
}

// validateSensitiveRPCURL enforces HTTPS for RPC calls that transmit private
// keys or passwords. Localhost and loopback addresses are exempt. Non-HTTPS
// URLs are rejected unless --insecure is explicitly set.
// AUDIT (2026) HIGH-14: prevent plaintext key/password transmission.
func validateSensitiveRPCURL(rawURL string) error {
	if insecureRPC {
		return nil // operator explicitly opted in
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid RPC URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "https" {
		return nil
	}
	if scheme != "http" {
		return fmt.Errorf("unsupported RPC URL scheme %q (use https://)", scheme)
	}
	// http:// is allowed only for loopback addresses.
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return nil
	}
	return fmt.Errorf("refusing to send private key/password over plaintext http://%s — use https:// or pass --insecure", host)
}

// importAccountRemote reads a local key file and imports it to a remote node via RPC.
// AUDIT (2026) KEYS-12: password is now []byte (wiped by caller via defer).
func importAccountRemote(keyFile, rpcURL string, password []byte) error {
	// AUDIT (2026) HIGH-14: enforce HTTPS for private key transmission.
	if err := validateSensitiveRPCURL(rpcAddr); err != nil {
		return err
	}

	// Read key file
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	content := strings.TrimSpace(string(data))

	// Validate key format and derive address (for verification only)
	var address string
	if strings.HasPrefix(content, "dilithium3:") || strings.HasPrefix(content, "DILITHIUM3:") {
		hexStr := strings.TrimPrefix(content, "dilithium3:")
		hexStr = strings.TrimPrefix(hexStr, "DILITHIUM3:")
		hexStr = strings.TrimSpace(hexStr)

		parts := strings.SplitN(hexStr, ":", 2)
		privKeyHex := strings.TrimSpace(parts[0])

		keyBytes, err := hex.DecodeString(privKeyHex)
		if err != nil {
			return fmt.Errorf("invalid hex in key file: %w", err)
		}

		if len(keyBytes) != crypto.Dilithium3PrivateKeySize {
			return fmt.Errorf("invalid private key size: got %d bytes, expected %d", len(keyBytes), crypto.Dilithium3PrivateKeySize)
		}

		if len(parts) == 2 {
			pubKeyHex := strings.TrimSpace(parts[1])
			pubKeyBytes, err := hex.DecodeString(pubKeyHex)
			if err != nil {
				return fmt.Errorf("invalid hex in public key: %w", err)
			}
			if len(pubKeyBytes) != crypto.Dilithium3PublicKeySize {
				return fmt.Errorf("invalid public key size: got %d bytes, expected %d", len(pubKeyBytes), crypto.Dilithium3PublicKeySize)
			}
		}

		privKey, err := crypto.PrivateKeyFromBytes(keyBytes)
		if err != nil {
			return fmt.Errorf("invalid private key: %w", err)
		}

		pubKey := privKey.PublicKey()
		address = fmt.Sprintf("0x%x", pubKey.Address())
	} else {
		return fmt.Errorf("unsupported key format (expected dilithium3:hex...)")
	}

	// Call personal_importRawKey RPC
	// NOTE: JSON-RPC requires string; the []byte is converted here and the
	// caller wipes the original bytes via defer.
	result, err := rpcCall("personal_importRawKey", []any{content, string(password)})
	if err != nil {
		return fmt.Errorf("RPC call failed: %w", err)
	}

	var importedAddr string
	if err := json.Unmarshal(result, &importedAddr); err != nil {
		return fmt.Errorf("failed to parse RPC response: %w", err)
	}

	fmt.Println("Account imported successfully!")
	fmt.Printf("  Local address:   %s\n", address)
	fmt.Printf("  Imported address: %s\n", importedAddr)

	if !strings.EqualFold(address, importedAddr) {
		fmt.Println("  WARNING: Addresses do not match! Verify the key file.")
	}

	return nil
}

// unlockAccountRemote unlocks an account on a remote node via RPC.
// AUDIT (2026) KEYS-12: password is now []byte (wiped by caller via defer).
func unlockAccountRemote(address, rpcURL string, password []byte, duration int) error {
	// AUDIT (2026) HIGH-14: enforce HTTPS for password transmission.
	if err := validateSensitiveRPCURL(rpcAddr); err != nil {
		return err
	}

	result, err := rpcCall("personal_unlockAccount", []any{address, string(password), duration})
	if err != nil {
		return fmt.Errorf("RPC call failed: %w", err)
	}

	var success bool
	if err := json.Unmarshal(result, &success); err != nil {
		return fmt.Errorf("failed to parse RPC response: %w", err)
	}

	if success {
		fmt.Printf("Account %s unlocked for %d seconds\n", address, duration)
	} else {
		fmt.Printf("Failed to unlock account %s (wrong password or account not found)\n", address)
	}

	return nil
}

// listAccountsRemote lists accounts on a remote node via RPC.
func listAccountsRemote(rpcURL string) error {
	result, err := rpcCall("personal_listAccounts", nil)
	if err != nil {
		return fmt.Errorf("RPC call failed: %w", err)
	}

	var accounts []string
	if err := json.Unmarshal(result, &accounts); err != nil {
		return fmt.Errorf("failed to parse RPC response: %w", err)
	}

	fmt.Printf("Accounts on remote node:\n")
	for i, addr := range accounts {
		fmt.Printf("  [%d] %s\n", i+1, addr)
	}

	if len(accounts) == 0 {
		fmt.Println("  (no accounts)")
	}

	return nil
}
