// Quantaureum Node source, version 1.0.0.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/node"
)

func splitBootnodes(bootnodes string) []string {
	var result []string
	for _, b := range strings.Split(bootnodes, ",") {
		trimmed := strings.TrimSpace(b)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func applyFlagOverrides(cfg *node.Config, cli *CLI) {
	if *cli.NetworkName != "" {
		cfg.Network = *cli.NetworkName
		node.ResolveNetworkConfig(cfg)
	}

	if *cli.DataDir != "" && *cli.DataDir != "./data" {
		cfg.DataDir = *cli.DataDir
	}
	if *cli.NodeName != "" {
		cfg.Name = *cli.NodeName
	}
	if *cli.ListenAddr != "" && *cli.ListenAddr != ":9000" {
		cfg.ListenAddr = *cli.ListenAddr
	}
	if *cli.MaxPeers != 50 {
		cfg.MaxPeers = *cli.MaxPeers
	}

	cfg.RPCEnabled = *cli.RPCEnabled
	if *cli.RPCAddr != "" && *cli.RPCAddr != ":8545" {
		cfg.RPCAddr = *cli.RPCAddr
	}

	cfg.WSEnabled = *cli.WSEnabled
	if *cli.WSAddr != "" && *cli.WSAddr != ":8546" {
		cfg.WSAddr = *cli.WSAddr
	}

	cfg.FrontendEnabled = *cli.FrontendEnabled
	if *cli.FrontendAddr != "" && *cli.FrontendAddr != ":8088" {
		cfg.FrontendAddr = *cli.FrontendAddr
	}

	cfg.HealthEnabled = *cli.HealthEnabled
	if *cli.HealthAddr != "" && *cli.HealthAddr != ":8080" {
		cfg.HealthAddr = *cli.HealthAddr
	}

	cfg.MetricsEnabled = *cli.MetricsEnabled
	if *cli.MetricsAddr != "" && *cli.MetricsAddr != ":9090" {
		cfg.MetricsAddr = *cli.MetricsAddr
	}

	if *cli.GenesisFile != "" {
		cfg.GenesisFile = *cli.GenesisFile
	}
	if *cli.NetworkID != 0 {
		cfg.NetworkID = *cli.NetworkID
	}
	if *cli.Bootnodes != "" {
		peers := splitBootnodes(*cli.Bootnodes)
		cfg.BootstrapPeers = peers
	}

	// P2P Discovery overrides
	cfg.EnableDHT = *cli.Discovery
	if *cli.NodeDB != "" {
		cfg.NodeDBPath = *cli.NodeDB
	}

	if *cli.ValidatorEnabled {
		cfg.ValidatorEnabled = true
		cfg.BlockProducer = true
	}
	if *cli.ValidatorKey != "" {
		cfg.ValidatorKey = *cli.ValidatorKey
	}

	// Validator key password resolution (EIP-2335 style, same priority as Ethereum):
	// 1. --validator-password-file flag (most secure, recommended for production)
	// 2. QAU_VALIDATOR_KEY_PASSWORD environment variable
	// 3. validatorKeyPassword in config JSON (least secure, not recommended)
	//
	// SECURITY (AUDIT-FULL ROUND1 2026-08-14 SV-09): Environment variables
	// are visible in /proc/self/environ, process listings, and container
	// orchestration APIs. Prefer --validator-password-file for production
	// deployments. The env var fallback is retained for backward compatibility.
	if *cli.ValidatorPasswordFile != "" {
		cfg.ValidatorPasswordFile = *cli.ValidatorPasswordFile
		data, err := os.ReadFile(*cli.ValidatorPasswordFile) // #nosec G304 -- path from CLI flag, operator-controlled
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to read validator password file %s: %v\n", *cli.ValidatorPasswordFile, err)
			os.Exit(1)
		}
		pwd := strings.TrimSpace(string(data))
		if pwd == "" {
			fmt.Fprintf(os.Stderr, "ERROR: Validator password file %s is empty\n", *cli.ValidatorPasswordFile)
			os.Exit(1)
		}
		cfg.ValidatorKeyPassword = pwd
	} else if pwd := os.Getenv("QAU_VALIDATOR_KEY_PASSWORD"); pwd != "" {
		cfg.ValidatorKeyPassword = pwd
	}

	if *cli.MineGasLimit != 30000000 {
		cfg.MaxGasLimit = *cli.MineGasLimit
	}

	if *cli.DevMode {
		cfg.DevMode = true
		cfg.DevBlocks = true
		cfg.BlockProducer = true
		cfg.DevAutoUnlockAccounts = true
		if cfg.BlockInterval == 0 {
			cfg.BlockInterval = *cli.BlockInterval
		}
	}
	if *cli.DevBlocks {
		cfg.DevBlocks = true
	}
	if *cli.DevAutoUnlock {
		cfg.DevAutoUnlockAccounts = true
	}
	if *cli.AllowInsecureUnlock {
		cfg.AllowInsecureUnlock = true
	}

	if *cli.CacheSize != 512 {
		cfg.CacheSize = *cli.CacheSize
	}

	cfg.ParallelExecution.Enabled = *cli.ParallelEnabled
	if *cli.ParallelWorkers != 0 {
		cfg.ParallelExecution.NumWorkers = *cli.ParallelWorkers
	}

	cfg.PruningConfig.Enabled = *cli.PruneEnabled
	if *cli.PruneBlocks != 1000 {
		cfg.PruningConfig.RetentionBlocks = *cli.PruneBlocks
	}

	// ETHEREUM-PARITY SYNC (2026-08-13): --sync.mode (snap|full).
	switch strings.ToLower(strings.TrimSpace(*cli.SyncMode)) {
	case "", "snap", "fast":
		cfg.SyncMode = "snap"
	case "full":
		cfg.SyncMode = "full"
	default:
		fmt.Fprintf(os.Stderr, "ERROR: invalid --sync.mode %q: valid values are snap, full\n", *cli.SyncMode)
		os.Exit(1)
	}

	if *cli.LogLevel != "" {
		cfg.LogLevel = *cli.LogLevel
	}
	if *cli.LogFormat != "" {
		cfg.LogFormat = *cli.LogFormat
	}

	cfg.KeyRotation.Enabled = *cli.KeyRotation

	// R7-M2 FIX: rpccorsdomain was parsed but never wired into AllowedOrigins,
	// giving operators a false sense that --rpccorsdomain restricts CORS. Wire
	// it now and reject "*" explicitly so the operator never silently widens
	// CORS to the entire internet.
	if *cli.RPCCors != "" {
		for _, o := range strings.Split(*cli.RPCCors, ",") {
			o = strings.TrimSpace(o)
			if o == "" || o == "*" {
				continue // never widen CORS to "*"
			}
			cfg.AllowedOrigins = append(cfg.AllowedOrigins, o)
		}
	}
	if *cli.WSOrigins != "" && *cli.WSOrigins != "*" {
		cfg.AllowedOrigins = append(cfg.AllowedOrigins, strings.Split(*cli.WSOrigins, ",")...)
	}

	if *cli.TLSEnabled {
		cfg.RPCTLSCertFile = *cli.TLSCert
		cfg.RPCTLSKeyFile = *cli.TLSKey
	}
}

func validateConsensusConfig() error {
	if err := consensus.ValidateGenesisTimeForProduction(); err != nil {
		return fmt.Errorf("genesis time validation failed: %w", err)
	}
	if consensus.GetAttestationNetworkID() == 0 {
		return fmt.Errorf("attestation network ID not configured")
	}
	return nil
}

// LoadConfig loads the node configuration from file and applies CLI flag overrides.
// Returns the final merged configuration or an error.
func LoadConfig(cli *CLI) (*node.Config, error) {
	var cfg *node.Config
	var err error

	configFile := *cli.ConfigPath
	if configFile == "" {
		if _, statErr := os.Stat("config.json"); statErr == nil {
			configFile = "config.json"
		}
	}

	if configFile != "" {
		cfg, err = node.LoadConfig(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config from %s: %w", configFile, err)
		}
		fmt.Printf("Loaded configuration from: %s\n", configFile)
	} else {
		cfg = node.DefaultConfig()
		fmt.Println("Using default configuration")
	}

	applyFlagOverrides(cfg, cli)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	genesis, genErr := node.LoadGenesisForConfig(cfg)
	if genErr != nil {
		return nil, genErr
	}
	if genesis != nil {
		if err := consensus.SetGenesisTime(int64(genesis.Timestamp)); err != nil {
			return nil, fmt.Errorf("failed to set genesis time: %w", err)
		}
	}
	consensus.SetAttestationNetworkID(cfg.NetworkID)

	if !cfg.DevMode && cfg.NetworkID != 0 {
		if err := validateConsensusConfig(); err != nil {
			return nil, fmt.Errorf("consensus validation failed: %w\nFor development, use --dev flag. For production, ensure genesis is properly configured.", err)
		}
	}

	return cfg, nil
}

// ValidateMainnetGenesis checks that genesis time is configured for mainnet nodes.
func ValidateMainnetGenesis(cfg *node.Config) error {
	if !cfg.DevMode && cfg.NetworkID == node.MainnetNetworkID {
		if !consensus.IsGenesisTimeConfigured() {
			return fmt.Errorf("CRITICAL: Genesis time not properly configured for mainnet")
		}
	}
	return nil
}
