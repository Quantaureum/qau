// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the qauctl management tool.
package cmd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quantaureum/qau/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const minPasswordLength = 8

func newKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage cryptographic keys",
		Long:  "Generate, import, export, and manage Dilithium3 cryptographic keys.",
	}

	cmd.AddCommand(newKeyGenerateCmd())
	cmd.AddCommand(newKeyListCmd())
	cmd.AddCommand(newKeyImportCmd())
	cmd.AddCommand(newKeyExportCmd())
	cmd.AddCommand(newKeyInspectCmd())

	return cmd
}

func newKeyGenerateCmd() *cobra.Command {
	var passwordFile string
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new key pair",
		Long:  "Generate a new Dilithium3 key pair and save it encrypted.",
		RunE: func(cmd *cobra.Command, args []string) error {
			pwd, err := resolvePassword(passwordFile, "Enter password for key encryption: ", true)
			if err != nil {
				return err
			}
			defer crypto.ZeroBytesSecure(pwd)
			return generateKey(pwd)
		},
	}
	// AUDIT (2026) KEYS-12: Use --password-file instead of --password
	// (passwords on the command line are visible in ps/proc/shell history).
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read password from file (alternatives: QAU_KEYSTORE_PASSWORD env var or interactive prompt)")
	return cmd
}

func newKeyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all keys",
		Long:  "List all keys in the keystore.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listKeys()
		},
	}
}

func newKeyImportCmd() *cobra.Command {
	var passwordFile string
	cmd := &cobra.Command{
		Use:   "import <private-key-hex>",
		Short: "Import a private key",
		Long:  "Import a private key from hex format and save it encrypted.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pwd, err := resolvePassword(passwordFile, "Enter password for key encryption: ", true)
			if err != nil {
				return err
			}
			defer crypto.ZeroBytesSecure(pwd)
			return importKey(args[0], pwd)
		},
	}
	// AUDIT (2026) KEYS-12: Use --password-file instead of --password.
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read password from file (alternatives: QAU_KEYSTORE_PASSWORD env var or interactive prompt)")
	return cmd
}

func newKeyExportCmd() *cobra.Command {
	var passwordFile string
	cmd := &cobra.Command{
		Use:   "export <address>",
		Short: "Export a private key",
		Long:  "Export a private key in hex format.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pwd, err := resolvePassword(passwordFile, "Enter password to decrypt key: ", false)
			if err != nil {
				return err
			}
			defer crypto.ZeroBytesSecure(pwd)
			return exportKey(args[0], pwd)
		},
	}
	// AUDIT (2026) KEYS-12: Use --password-file instead of --password.
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read password from file (alternatives: QAU_KEYSTORE_PASSWORD env var or interactive prompt)")
	return cmd
}

func newKeyInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <address>",
		Short: "Inspect a key file",
		Long:  "Display information about a key file without decrypting.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return inspectKey(args[0])
		},
	}
}

func getKeystorePath() string {
	return filepath.Join(dataDir, "keystore")
}

func promptPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd())) // #nosec G115 -- stdin fd is always a small positive int
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	return password, nil
}

// resolvePassword resolves a password from --password-file, QAU_KEYSTORE_PASSWORD
// environment variable, or interactive prompt. The caller MUST wipe the
// returned []byte using crypto.ZeroBytesSecure.
//
// AUDIT (2026) KEYS-12: Removed --password CLI flag (visible in ps/proc/
// shell history). Password is now resolved from:
//  1. --password-file (reads from file; recommend file mode 0600)
//  2. QAU_KEYSTORE_PASSWORD environment variable
//  3. Interactive terminal prompt (not echoed)
//
// When confirm is true, the password is confirmed by entering it twice
// (only applies to the interactive prompt path).
func resolvePassword(passwordFile string, prompt string, confirm bool) ([]byte, error) {
	if passwordFile != "" {
		data, err := os.ReadFile(passwordFile) // #nosec G304 -- operator-supplied path
		if err != nil {
			return nil, fmt.Errorf("failed to read password file: %w", err)
		}
		return bytes.TrimRight(data, "\r\n"), nil
	}

	if envPwd := os.Getenv("QAU_KEYSTORE_PASSWORD"); envPwd != "" {
		return []byte(envPwd), nil
	}

	pwd, err := promptPassword(prompt)
	if err != nil {
		return nil, err
	}

	if confirm {
		confirmPwd, err := promptPassword("Confirm password: ")
		if err != nil {
			crypto.ZeroBytesSecure(pwd)
			return nil, err
		}
		matched := bytes.Equal(pwd, confirmPwd)
		crypto.ZeroBytesSecure(confirmPwd)
		if !matched {
			crypto.ZeroBytesSecure(pwd)
			return nil, fmt.Errorf("passwords do not match")
		}
	}

	return pwd, nil
}

func generateKey(password []byte) error {
	defer crypto.ZeroBytesSecure(password)

	if len(password) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minPasswordLength)
	}

	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	if err := saveKeyFile(keyPair.Private, password); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	fmt.Println("Key generated successfully!")
	fmt.Printf("  Address: %s\n", keyPair.Public.Address().String())
	fmt.Printf("  Keystore: %s\n", getKeystorePath())

	return nil
}

func listKeys() error {
	keystorePath := getKeystorePath()

	entries, err := os.ReadDir(keystorePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No keys found. Keystore is empty.")
			return nil
		}
		return fmt.Errorf("failed to read keystore: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No keys found. Keystore is empty.")
		return nil
	}

	fmt.Printf("Keys in keystore (%s):\n", keystorePath)
	fmt.Println("================================")

	for i, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		keyPath := filepath.Join(keystorePath, entry.Name())
		data, err := os.ReadFile(keyPath) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
		if err != nil {
			continue
		}

		var keyFile crypto.KeyFile
		if err := json.Unmarshal(data, &keyFile); err != nil {
			continue
		}

		fmt.Printf("[%d] %s\n", i+1, keyFile.Address)
	}

	return nil
}

func importKey(privateKeyHex string, password []byte) error {
	privateKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return fmt.Errorf("invalid hex format: %w", err)
	}
	defer crypto.ZeroBytesSecure(privateKeyBytes)

	privateKey, err := crypto.PrivateKeyFromBytes(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	defer privateKey.Zeroize()

	defer crypto.ZeroBytesSecure(password)

	if len(password) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minPasswordLength)
	}

	if err := saveKeyFile(privateKey, password); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	fmt.Println("Key imported successfully!")
	fmt.Printf("  Address: %s\n", privateKey.PublicKey().Address().String())

	return nil
}

func exportKey(addressStr string, password []byte) error {
	keyPath, err := findKeyFile(addressStr)
	if err != nil {
		return err
	}

	defer crypto.ZeroBytesSecure(password)

	privateKey, err := loadKeyFile(keyPath, password)
	if err != nil {
		return fmt.Errorf("failed to decrypt key: %w", err)
	}
	defer privateKey.Zeroize()

	privateKeyBytes := privateKey.Bytes()
	defer crypto.ZeroBytesSecure(privateKeyBytes)

	// SECURITY (audit P2-R3-03): Do not output any private key material to STDOUT.
	// Even truncated keys leak information. Only show the key size and output file path.
	fmt.Printf("Private Key: [REDACTED - %d bytes, use --output-file to save full key]\n", len(privateKeyBytes))

	return nil
}

func inspectKey(addressStr string) error {
	keyPath, err := findKeyFile(addressStr)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(keyPath) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	var keyFile crypto.KeyFile
	if err := json.Unmarshal(data, &keyFile); err != nil {
		return fmt.Errorf("failed to parse key file: %w", err)
	}

	fmt.Println("Key File Information:")
	fmt.Println("=====================")
	fmt.Printf("  Path:    %s\n", keyPath)
	fmt.Printf("  Version: %d\n", keyFile.Version)
	fmt.Printf("  Address: %s\n", keyFile.Address)
	fmt.Printf("  Cipher:  %s\n", keyFile.Crypto.Cipher)
	fmt.Printf("  KDF:     %s\n", keyFile.Crypto.KDF)

	return nil
}

func findKeyFile(addressStr string) (string, error) {
	keystorePath := getKeystorePath()

	entries, err := os.ReadDir(keystorePath)
	if err != nil {
		return "", fmt.Errorf("failed to read keystore: %w", err)
	}

	addressStr = strings.ToLower(addressStr)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		keyPath := filepath.Join(keystorePath, entry.Name())
		data, err := os.ReadFile(keyPath) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
		if err != nil {
			continue
		}

		var keyFile crypto.KeyFile
		if err := json.Unmarshal(data, &keyFile); err != nil {
			continue
		}

		if strings.ToLower(keyFile.Address) == addressStr {
			return keyPath, nil
		}
	}

	return "", fmt.Errorf("key not found for address: %s", addressStr)
}

func saveKeyFile(privateKey *crypto.PrivateKey, password []byte) error {
	keyFile, err := crypto.EncryptKeyBytes(privateKey, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %w", err)
	}

	data, err := keyFile.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal key file: %w", err)
	}

	keystorePath := getKeystorePath()
	if err := os.MkdirAll(keystorePath, 0700); err != nil {
		return fmt.Errorf("failed to create keystore directory: %w", err)
	}

	filename := fmt.Sprintf("%s.json", strings.ToLower(keyFile.Address))
	keyPath := filepath.Join(keystorePath, filename)

	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

func loadKeyFile(keyPath string, password []byte) (*crypto.PrivateKey, error) {
	data, err := os.ReadFile(keyPath) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	keyFile, err := crypto.KeyFileFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key file: %w", err)
	}

	privateKey, err := crypto.DecryptKeyBytes(keyFile, password)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
	}

	return privateKey, nil
}
