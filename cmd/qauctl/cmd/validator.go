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
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func newValidatorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validator",
		Short: "Manage validator keys and deployment",
		Long:  "Deploy validator keys to remote servers, check validator status, and manage validator configuration.",
	}

	cmd.AddCommand(newValidatorDeployCmd())
	cmd.AddCommand(newValidatorCheckCmd())
	cmd.AddCommand(newValidatorInfoCmd())

	return cmd
}

// validatorDeploy deploys a validator private key to a remote server via SSH.
// The key file is read locally and transferred to the server — private key content
// is never printed to stdout/stderr.
func newValidatorDeployCmd() *cobra.Command {
	var (
		sshKeyFile string
		sshUser    string
		remotePath string
		restart    bool
		backup     bool
	)

	cmd := &cobra.Command{
		Use:   "deploy <key-file> <server-ip>",
		Short: "Deploy validator key to a remote server",
		Long: `Deploy a validator private key file to a remote server via SSH.

The key file is read locally and written to the remote server's validator.key path.
Private key content is never displayed in the output.

This is the recommended way to set up validator keys after a chain reset,
ensuring the validator address matches the genesis configuration.

Example:
  qauctl validator deploy /path/to/validator1.key validator.example.invalid \
    --ssh-key ~/.ssh/id_ed25519 \
    --remote-path /var/lib/quantaureum/validator.key \
    --restart`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return deployValidatorKey(args[0], args[1], sshKeyFile, sshUser, remotePath, restart, backup)
		},
	}

	cmd.Flags().StringVar(&sshKeyFile, "ssh-key", "", "SSH private key file path")
	cmd.Flags().StringVar(&sshUser, "ssh-user", "root", "SSH username")
	cmd.Flags().StringVar(&remotePath, "remote-path", "/var/lib/quantaureum/validator.key", "Remote validator key path")
	cmd.Flags().BoolVar(&restart, "restart", false, "Restart quantaureum service after deployment")
	cmd.Flags().BoolVar(&backup, "backup", true, "Backup existing validator key before replacing")

	return cmd
}

func newValidatorCheckCmd() *cobra.Command {
	var (
		sshKeyFile string
		sshUser    string
	)

	cmd := &cobra.Command{
		Use:   "check <server-ip>",
		Short: "Check validator status on a remote server",
		Long: `Check the validator key and status on a remote server.

Displays the validator address (derived from public key) and whether it matches
the genesis configuration. Private key content is never displayed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return checkValidatorStatus(args[0], sshKeyFile, sshUser)
		},
	}

	cmd.Flags().StringVar(&sshKeyFile, "ssh-key", "", "SSH private key file path")
	cmd.Flags().StringVar(&sshUser, "ssh-user", "root", "SSH username")

	return cmd
}

func newValidatorInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info <key-file>",
		Short: "Show address from a local validator key file",
		Long: `Read a validator key file and display the derived address.
Private key content is never displayed — only the public address.

Supports both plaintext (dilithium3:hex...) and encrypted JSON formats.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return showValidatorInfo(args[0])
		},
	}

	return cmd
}

// deployValidatorKey reads a local key file and deploys it to a remote server via SSH.
func deployValidatorKey(keyFile, serverIP, sshKeyFile, sshUser, remotePath string, restart, backup bool) error {
	// 1. Read and validate the local key file
	_, address, err := readAndValidateKeyFile(keyFile)
	if err != nil {
		return err
	}

	fmt.Printf("Key file: %s\n", keyFile)
	fmt.Printf("Derived address: 0x%x\n", address)
	fmt.Printf("Target server: %s\n", serverIP)
	fmt.Printf("Remote path: %s\n", remotePath)

	// 2. Connect via SSH
	client, err := sshConnect(serverIP, sshUser, sshKeyFile)
	if err != nil {
		return fmt.Errorf("SSH connection failed: %w", err)
	}
	defer client.Close()

	// 3. Backup existing key if requested
	if backup {
		backupPath := remotePath + ".bak"
		cmd := fmt.Sprintf("cp %s %s 2>/dev/null || true", remotePath, backupPath)
		if err := sshRun(client, cmd); err != nil {
			fmt.Printf("Warning: backup failed: %v\n", err)
		} else {
			fmt.Printf("Backed up existing key to %s\n", backupPath)
		}
	}

	// 4. Write key file to remote server via SFTP-like approach (using cat)
	// Write the original file content (not the parsed key)
	origData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to re-read key file: %w", err)
	}

	// Use dd to write the file content to avoid shell escaping issues
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}

	session.Stdin = bytes.NewReader(origData)
	err = session.Run(fmt.Sprintf("cat > %s && chmod 600 %s", remotePath, remotePath))
	session.Close()

	if err != nil {
		return fmt.Errorf("failed to write key to remote server: %w", err)
	}
	fmt.Printf("Validator key deployed to %s:%s\n", serverIP, remotePath)

	// 5. Restart service if requested
	if restart {
		fmt.Println("Restarting quantaureum service...")
		if err := sshRun(client, "systemctl restart quantaureum"); err != nil {
			return fmt.Errorf("failed to restart service: %w", err)
		}
		fmt.Println("Service restarted. Waiting 5 seconds for startup...")
		time.Sleep(5 * time.Second)

		// Verify the new address
		fmt.Println("Verifying validator address...")
		logOutput, err := sshOutput(client, "journalctl -u quantaureum -n 20 --no-pager 2>/dev/null | grep 'myAddr' | tail -1")
		if err == nil && logOutput != "" {
			fmt.Printf("Server log: %s\n", strings.TrimSpace(logOutput))
		}
	}

	fmt.Println("\nDeployment complete!")
	fmt.Printf("  Server:    %s\n", serverIP)
	fmt.Printf("  Address:   0x%x\n", address)
	fmt.Printf("  Key path:  %s\n", remotePath)

	return nil
}

// checkValidatorStatus checks the validator status on a remote server.
func checkValidatorStatus(serverIP, sshKeyFile, sshUser string) error {
	client, err := sshConnect(serverIP, sshUser, sshKeyFile)
	if err != nil {
		return fmt.Errorf("SSH connection failed: %w", err)
	}
	defer client.Close()

	fmt.Printf("Checking validator status on %s...\n\n", serverIP)

	// 1. Check if validator.key exists
	keyExists, _ := sshOutput(client, "test -f /var/lib/quantaureum/validator.key && echo 'YES' || echo 'NO'")
	fmt.Printf("Validator key file: %s\n", strings.TrimSpace(keyExists))

	// 2. Get validator address from key file
	keyInfo, _ := sshOutput(client, "head -c 200 /var/lib/quantaureum/validator.key 2>/dev/null")
	if strings.Contains(keyInfo, "dilithium3:") {
		fmt.Println("Key format: plaintext (dilithium3:hex...)")
	} else if strings.Contains(keyInfo, `"version"`) {
		fmt.Println("Key format: encrypted JSON")
	} else {
		fmt.Println("Key format: unknown")
	}

	// 3. Check service status
	serviceStatus, _ := sshOutput(client, "systemctl is-active quantaureum 2>/dev/null")
	fmt.Printf("Service status: %s\n", strings.TrimSpace(serviceStatus))

	// 4. Check myAddr from logs
	myAddr, _ := sshOutput(client, "journalctl -u quantaureum -n 50 --no-pager 2>/dev/null | grep 'myAddr' | tail -1")
	if myAddr != "" {
		fmt.Printf("Validator myAddr: %s\n", strings.TrimSpace(myAddr))
	}

	// 5. Check block height
	healthInfo, _ := sshOutput(client, "curl -s http://127.0.0.1:8080/health 2>/dev/null")
	if healthInfo != "" {
		fmt.Printf("Health: %s\n", strings.TrimSpace(healthInfo))
	}

	// 6. Check isProposer
	proposerInfo, _ := sshOutput(client, "journalctl -u quantaureum -n 50 --no-pager 2>/dev/null | grep 'isProposer' | tail -1")
	if proposerInfo != "" {
		fmt.Printf("Proposer status: %s\n", strings.TrimSpace(proposerInfo))
	}

	return nil
}

// showValidatorInfo reads a local key file and shows the derived address.
func showValidatorInfo(keyFile string) error {
	_, address, err := readAndValidateKeyFile(keyFile)
	if err != nil {
		return err
	}

	fmt.Printf("Key file:  %s\n", keyFile)
	fmt.Printf("Address:   0x%x\n", address)
	fmt.Println("Private key content is never displayed by this tool.")

	return nil
}

// readAndValidateKeyFile reads a key file and returns the raw data and derived address.
// It supports both plaintext (dilithium3:hex...) and encrypted JSON formats.
func readAndValidateKeyFile(keyFile string) ([]byte, [20]byte, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, [20]byte{}, fmt.Errorf("failed to read key file: %w", err)
	}

	content := strings.TrimSpace(string(data))
	var address [20]byte

	// Detect optional `dilithium3:` prefix used by mixed-format key files
	// (some servers store encrypted JSON keystore prefixed with `dilithium3:`).
	stripped := content
	hasDilPrefix := strings.HasPrefix(stripped, "dilithium3:") || strings.HasPrefix(stripped, "DILITHIUM3:")
	if hasDilPrefix {
		stripped = strings.TrimPrefix(stripped, "dilithium3:")
		stripped = strings.TrimPrefix(stripped, "DILITHIUM3:")
		stripped = strings.TrimSpace(stripped)
	}

	// Branch 1: remaining content is an encrypted JSON keystore (possibly after stripping `dilithium3:` prefix).
	// JSON keystore objects always start with `{`. This also handles the
	// `dilithium3:{...}` mixed format produced by some server-side key writers.
	if strings.HasPrefix(stripped, "{") || strings.Contains(content, `"version"`) {
		// Encrypted JSON format — we cannot derive address without password.
		// Just show the address from the JSON.
		var keyFileObj struct {
			Address string `json:"address"`
		}
		if err := parseJSON(stripped, &keyFileObj); err != nil {
			return nil, [20]byte{}, fmt.Errorf("invalid encrypted key file format: %w", err)
		}
		if keyFileObj.Address == "" {
			return nil, [20]byte{}, fmt.Errorf("encrypted key file does not contain address field")
		}

		// Parse address. Support three encodings found in the wild:
		//   1. QAU base32 form, e.g. "QAUCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIR"
		//   2. Ethereum-style hex form, e.g. "0x9528fec867f70e4307f8032cec7cfac6bf42f17c"
		//   3. Bare hex form, e.g. "9528fec867f70e4307f8032cec7cfac6bf42f17c"
		// types.ParseAddressWithFallback tries QAU base32 first, then 0x hex.
		addr, err := types.ParseAddressWithFallback(keyFileObj.Address)
		if err != nil {
			return nil, [20]byte{}, fmt.Errorf("invalid address in key file: %w", err)
		}
		copy(address[:], addr[:])
		// address is now populated from JSON keystore; data (raw file bytes)
		// is still returned so callers can reach the encrypted blob if needed.
	} else if hasDilPrefix {
		// Branch 2: plaintext dilithium3:hex[<sep>hex] format (private [+ public]).
		// `stripped` already had its `dilithium3:` prefix removed above.

		// SECURITY (audit P2-R3-04): Plaintext key format is deprecated.
		// Prefer encrypted JSON keystore format. Plaintext keys on disk
		// are vulnerable to theft via disk imaging or backup access.
		fmt.Println("WARNING: Using plaintext key format (dilithium3:hex). Consider migrating to encrypted JSON keystore.")

		privKeyHex, pubKeyHex, splitErr := splitDilithium3KeyHex(stripped)
		if splitErr != nil {
			return nil, [20]byte{}, splitErr
		}

		keyBytes, err := hex.DecodeString(privKeyHex)
		if err != nil {
			return nil, [20]byte{}, fmt.Errorf("invalid hex in key file: %w", err)
		}

		if len(keyBytes) != crypto.Dilithium3PrivateKeySize {
			return nil, [20]byte{}, fmt.Errorf("invalid private key size: got %d bytes, expected %d", len(keyBytes), crypto.Dilithium3PrivateKeySize)
		}

		if pubKeyHex != "" {
			pubKeyBytes, err := hex.DecodeString(pubKeyHex)
			if err != nil {
				return nil, [20]byte{}, fmt.Errorf("invalid hex in public key: %w", err)
			}
			if len(pubKeyBytes) != crypto.Dilithium3PublicKeySize {
				return nil, [20]byte{}, fmt.Errorf("invalid public key size: got %d bytes, expected %d", len(pubKeyBytes), crypto.Dilithium3PublicKeySize)
			}
		}

		privKey, err := crypto.PrivateKeyFromBytes(keyBytes)
		if err != nil {
			return nil, [20]byte{}, fmt.Errorf("invalid private key: %w", err)
		}

		pubKey := privKey.PublicKey()
		addr := pubKey.Address()
		copy(address[:], addr[:])
	} else {
		return nil, [20]byte{}, fmt.Errorf("unrecognized key file format (expected dilithium3:hex... or encrypted JSON)")
	}

	return data, address, nil
}

// filterHexRunes drops every rune that is not a hexadecimal digit.
func filterHexRunes(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, s)
}

// splitDilithium3KeyHex splits the hex payload of a plaintext `dilithium3:` key
// file into its private and public key hex halves. pubHex is "" when the file
// only carries a private key.
//
// R92-KEYSEP: the separator found in the wild is inconsistent —
//
//	':'   older server-side key writers (qauctl's original assumption)
//	'+'   the documented keystore format (crypto/generate.go:27, AGENTS.md)
//	none  node-written validator.key (priv||pub concatenated)
//
// The node accepts all three because parseValidatorPrivateKeyFile filters the
// payload down to hex characters before decoding, and personal_importRawKey does
// the same in extractDilithium3PrivateKey. qauctl however split on ':' only, so
// the documented '+' form was rejected with
//
//	invalid hex in key file: encoding/hex: invalid byte: U+002B '+'
//
// Filtering to hex first and splitting by known lengths makes qauctl
// separator-agnostic like the rest of the codebase.
func splitDilithium3KeyHex(payload string) (privHex, pubHex string, err error) {
	hexOnly := filterHexRunes(payload)
	privLen := crypto.Dilithium3PrivateKeySize * 2
	pubLen := crypto.Dilithium3PublicKeySize * 2

	switch len(hexOnly) {
	case privLen:
		return hexOnly, "", nil
	case privLen + pubLen:
		return hexOnly[:privLen], hexOnly[privLen:], nil
	default:
		return "", "", fmt.Errorf(
			"unexpected key hex length %d: expected %d (private key only) or %d (private+public)",
			len(hexOnly), privLen, privLen+pubLen)
	}
}

// parseJSON parses JSON string into a struct.
func parseJSON(s string, v any) error {
	return json.Unmarshal([]byte(s), v)
}

// --- SSH helpers ---

func sshConnect(serverIP, sshUser, sshKeyFile string) (*ssh.Client, error) {
	if sshKeyFile == "" {
		return nil, fmt.Errorf("SSH key file is required (--ssh-key)")
	}

	keyData, err := os.ReadFile(sshKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH key file: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH key: %w", err)
	}

	// audit fix (CRITICAL): verify SSH host keys via known_hosts, not InsecureIgnoreHostKey
	// audit fix (MEDIUM/R2): hard-fail when known_hosts is unavailable; no insecure fallback
	var hostKeyCallback ssh.HostKeyCallback
	homeDir, hdErr := os.UserHomeDir()
	if hdErr != nil {
		return nil, fmt.Errorf("failed to get home directory: %w; cannot locate known_hosts", hdErr)
	}
	knownHostsPath := filepath.Join(homeDir, ".ssh", "known_hosts")
	cb, khErr := knownhosts.New(knownHostsPath)
	if khErr != nil {
		return nil, fmt.Errorf("failed to read known_hosts (%s): %w; connect to the server manually with ssh first to establish host key", knownHostsPath, khErr)
	}
	hostKeyCallback = cb

	config := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}

	client, err := ssh.Dial("tcp", serverIP+":22", config)
	if err != nil {
		return nil, fmt.Errorf("SSH dial failed: %w", err)
	}

	return client, nil
}

func sshRun(client *ssh.Client, cmd string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	return session.Run(cmd)
}

func sshOutput(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var buf bytes.Buffer
	session.Stdout = &buf
	err = session.Run(cmd)
	return buf.String(), err
}
