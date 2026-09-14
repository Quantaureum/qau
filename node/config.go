// Quantaureum Node source, version 1.0.0.
// Package node provides the main node implementation for Quantaureum.
package node

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/core"
	"github.com/quantaureum/qau/params"
)

// networkBootnodes holds the canonical bootnode enode URLs for each named
// network. These are the public, long-lived endpoints a fresh node dials
// when no --bootnodes flag or config entry is provided (same role as
// go-ethereum's params/bootnodes.go MainnetBootnodes). Entries MUST be
// neutral host identifiers (dedicated seed endpoints), never internal
// topology names.
var networkBootnodes = map[string][]string{
	NetworkMainnet: params.MainnetBootnodes,
	NetworkTestnet: params.TestnetBootnodes,
	NetworkDev:     nil,
}

// Network names
const (
	NetworkDev     = "dev"
	NetworkTestnet = "testnet"
	NetworkMainnet = "mainnet"
)

// Config holds the node configuration
type Config struct {
	// Node identity
	Name    string `json:"name"`
	NodeID  string `json:"nodeId"`
	DataDir string `json:"dataDir"`

	// Network selection: "dev", "testnet", "mainnet", or "" (custom)
	Network string `json:"network"`

	// Network
	NetworkID      uint64   `json:"networkId"`
	ListenAddr     string   `json:"listenAddr"`
	BootstrapPeers []string `json:"bootstrapPeers"`
	MaxPeers       int      `json:"maxPeers"`
	NodeKeyPath    string   `json:"nodeKeyPath"`
	ExternalIP     string   `json:"externalIP"`

	// P2P Discovery
	EnableDHT  bool   `json:"enableDHT"`  // Enable Kademlia DHT peer discovery (like Ethereum discv4)
	NodeDBPath string `json:"nodeDBPath"` // Path to persist discovered nodes for reconnection on restart

	// P2P whitelist
	TrustedPeers  []string `json:"trustedPeers"`
	WhitelistOnly bool     `json:"whitelistOnly"`

	// RPC
	RPCEnabled     bool `json:"rpcEnabled"`
	RPCAuthEnabled bool `json:"rpcAuthEnabled"`
	// RPCForceDisableAuth disables RPC auth ONLY for loopback-only
	// deployments. AUDIT (2026) H-01: if any listener (RPC/WS/GraphQL)
	// is bound to a non-loopback address, the node ignores this flag and
	// forces authentication ON (see Start() in node.go).
	RPCForceDisableAuth bool `json:"rpcForceDisableAuth"`
	// RPCTrustedProxies lists the reverse proxies (IP or CIDR) whose
	// X-Forwarded-For header may be trusted for client-IP attribution.
	// R90-PROXY-IP: required when a TLS-terminating proxy fronts the node,
	// otherwise per-IP rate limiting and the auth brute-force lockout all key
	// off the proxy's own loopback address. Empty (default) trusts nothing.
	// Overridable at runtime with QAU_RPC_TRUSTED_PROXIES.
	RPCTrustedProxies []string `json:"rpcTrustedProxies"`
	RPCAddr           string   `json:"rpcAddr"`
	RPCTLSCertFile    string   `json:"rpcTLSCertFile"` // audit-fix R5-M1: TLS cert for RPC server
	RPCTLSKeyFile     string   `json:"rpcTLSKeyFile"`  // audit-fix R5-M1: TLS key for RPC server
	WSEnabled         bool     `json:"wsEnabled"`
	WSAddr            string   `json:"wsAddr"`
	// RPC-H2 FIX (2026-07-19): WebSocket TLS support. When both files are
	// set, the WS listener becomes wss:// instead of plaintext ws://.
	// If unset, the WS server stays plaintext — only safe behind a reverse
	// proxy that terminates TLS (e.g. Caddy in front of 127.0.0.1:8546).
	WSTLSCertFile      string `json:"wsTLSCertFile"`
	WSTLSKeyFile       string `json:"wsTLSKeyFile"`
	LightClientEnabled bool   `json:"lightClientEnabled"`

	// Metrics
	MetricsEnabled bool   `json:"metricsEnabled"`
	MetricsAddr    string `json:"metricsAddr"`
	MetricsPath    string `json:"metricsPath"`

	// Frontend HTTP API
	FrontendEnabled bool   `json:"frontendEnabled"`
	FrontendAddr    string `json:"frontendAddr"`

	// Health Check
	HealthEnabled bool   `json:"healthEnabled"`
	HealthAddr    string `json:"healthAddr"`

	// Consensus
	ValidatorEnabled bool   `json:"validatorEnabled"`
	ValidatorKey     string `json:"validatorKey"`
	// L-6 FIX: Prefer environment variable QAU_VALIDATOR_KEY_PASSWORD over this field.
	// Storing passwords in JSON config files is insecure — they may be committed to VCS,
	// leaked via log output, or read by other users on shared systems.
	// Password resolution priority (same as Ethereum EIP-2335):
	// 1. --validator-password-file CLI flag (most secure, recommended for production)
	// 2. QAU_VALIDATOR_KEY_PASSWORD environment variable
	// 3. validatorKeyPassword in this config (least secure, not recommended)
	// AUDIT-FULL SV-09 FIX (2026-08-15): the in-memory field stays so the
	// consensus subsystem (block_producer.go, node.go) can read the resolved
	// password, but the JSON tag is now `json:"-"` so the plaintext never
	// round-trips through config.json. Operators must use the password-file
	// path (ValidatorPasswordFile) or the environment variable; a plaintext
	// `validatorKeyPassword` key in JSON is silently ignored on load and
	// never written on save, removing the "committed to VCS" and "read by
	// other users on shared systems" vectors flagged in SV-09.
	ValidatorKeyPassword  string `json:"-"`
	ValidatorPasswordFile string `json:"validatorPasswordFile,omitempty"` // Path to password file (EIP-2335 style)

	// Performance
	CacheSize   int    `json:"cacheSize"` // MB
	MaxGasLimit uint64 `json:"maxGasLimit"`

	// Optimization Settings
	ParallelExecution ParallelExecutionConfig `json:"parallelExecution"`
	CacheConfig       CacheOptConfig          `json:"cacheConfig"`
	PruningConfig     PruningOptConfig        `json:"pruningConfig"`

	// Logging
	LogLevel  string `json:"logLevel"`
	LogFormat string `json:"logFormat"` // "json" or "text"

	// ETHEREUM-PARITY SYNC (2026-08-13): sync mode selection (--sync.mode).
	// "" or "snap" = default fast path (store blocks during sync, rebuild
	// state afterwards, snap sync for large gaps); "full" = re-execute every
	// block during sync (geth --syncmode=full equivalent).
	SyncMode string `json:"syncMode"`

	// Genesis
	GenesisFile string `json:"genesisFile"`
	// ExpectedGenesisHash is the expected hash of the genesis configuration.
	// If non-empty, the node verifies at startup that the loaded genesis
	// produces this hash and refuses to start on mismatch.
	// This prevents chain splits caused by conflicting genesis files.
	// AUDIT (2026) HIGH-04 (NODE-01)
	ExpectedGenesisHash string `json:"expectedGenesisHash"`

	// High Availability
	ShutdownTimeout int `json:"shutdownTimeout"` // seconds

	// Development mode
	DevMode bool `json:"devMode"` // Enable development mode with auto block production

	// R102/R103-WEIGHTED-CONSENSUS CUTOVER (2026-08-30): epoch at which the
	// stake-weighted proposer election AND the committee partition activate.
	// 0 / unset = never (legacy shuffle). MUST be identical on every node of
	// the network — proposer election is cross-verified ("invalid block
	// proposer"), so a divergent value forks the chain at the cutover epoch.
	WeightedConsensusCutoverEpoch uint64 `json:"weightedConsensusCutoverEpoch,omitempty"`
	DevBlocks                     bool   `json:"devBlocks"`     // Enable block production in dev mode (replaces QAU_DEV_MODE_BLOCKS env var)
	BlockInterval                 int    `json:"blockInterval"` // Block production interval in seconds (dev mode only)
	BlockProducer                 bool   `json:"blockProducer"` // Enable block production (default true in dev mode, set false for sync-only nodes)
	SyncOnlyMode                  bool   `json:"syncOnlyMode"`  // If true, only sync blocks from peers, don't produce
	// audit-fix M-2: DevAutoUnlockAccounts requires explicit opt-in for auto-unlock in dev mode
	// Even when DevMode is true, accounts are NOT auto-unlocked unless this is explicitly set
	DevAutoUnlockAccounts bool `json:"devAutoUnlockAccounts"`

	// Allow insecure unlock: bypass TLS requirement for personal_* RPC methods
	// Ethereum-compatible: equivalent to geth's --allow-insecure-unlock
	AllowInsecureUnlock bool `json:"allowInsecureUnlock"`

	// RPCUserAllowlist optionally restricts who may call the state-mutating
	// staking and DeFi RPC methods (qau_stake, qau_unstake, qau_claimRewards,
	// qau_compoundRewards, qau_updateCommission and the DeFi mutators).
	//
	// R74-STAKE-ALLOWLIST: empty (the default) means permissionless — any
	// caller that produces a valid Dilithium3 staking/DeFi signature for the
	// address it operates on is accepted, which is what a public L1 needs.
	// When set, the listed addresses are the only ones accepted and everyone
	// else is rejected fail-closed. Overridable at runtime with
	// QAU_RPC_USER_ALLOWLIST (comma-separated). See node/rpc_user_allowlist.go.
	RPCUserAllowlist []string `json:"rpcUserAllowlist"`

	// CORS
	AllowedOrigins []string `json:"allowedOrigins"` // audit-fix L-1: restrict CORS origins (empty = no CORS)

	// Key Rotation
	KeyRotation KeyRotationConfig `json:"keyRotation"`

	// TLS Certificate Rotation
	TLSCertRotation TLSCertRotationConfig `json:"tlsCertRotation"`

	// Memory limits for resource management
	MemoryLimitMB         int `json:"memoryLimitMB"`
	MaxConcurrentRequests int `json:"maxConcurrentRequests"`
	RequestTimeout        int `json:"requestTimeout"`
	RequestsPerSecond     int `json:"requestsPerSecond"`

	// R107-LOCAL-FANOUT (2026-09-04): per-IP rate-limit tuning. Previously only
	// the *global* limit (requestsPerSecond) was configurable, while the per-IP
	// bucket, burst, violation threshold and ban duration were hardcoded in
	// rpc.DefaultRateLimitConfig(). A co-located service on the node (e.g. the
	// explorer front-end talking to 127.0.0.1:8545) therefore had no way to get
	// more headroom, and once it tripped the ban the only recovery was a process
	// restart. Zero / empty values keep the rpc defaults.
	//
	// RateLimitExemptIPs is opt-in on purpose — see rpc.RateLimitConfig.ExemptIPs
	// for why loopback must NOT be exempt by default on proxied deployments.
	PerIPRequestsPerSecond       int      `json:"perIpRequestsPerSecond"`
	RateLimitBurstSize           int      `json:"rateLimitBurstSize"`
	RateLimitViolationsBeforeBan int      `json:"rateLimitViolationsBeforeBan"`
	RateLimitBanDurationSeconds  int      `json:"rateLimitBanDurationSeconds"`
	RateLimitExemptIPs           []string `json:"rateLimitExemptIPs"`

	// Alerting Configuration
	AlertingConfig AlertingNodeConfig `json:"alerting"`

	// Danksharding / DA Committee Configuration (P1-5: loaded from config file)
	Danksharding DankshardingNodeConfig `json:"danksharding"`

	// Cross-chain Bridge Configuration (P0-3: loaded from config file)
	Bridge BridgeNodeConfig `json:"bridge"`

	// Sharding Configuration (P1-6: loaded from config file)
	// P1-6 (2026-07-14): Sharding parameters for the ShardManager. The
	// subsystem is enabled via QAU_ENABLE_SHARDING=1 env var (consistent
	// with Bridge/Rollup); these fields tune operation once enabled.
	Sharding ShardingNodeConfig `json:"sharding"`

	// TSS (Threshold Signature Scheme) Configuration
	TSSThreshold       int    `json:"tssThreshold"`
	TSSTotalShares     int    `json:"tssTotalShares"`
	TSSGroupKeyFile    string `json:"tssGroupKeyFile"`
	TSSKeyShareFile    string `json:"tssKeyShareFile"`
	TSSDistributedMode bool   `json:"tssDistributedMode"` // Enable distributed (multi-party) TSS signing over P2P. Default: false (local mode)
	// TSSDistributedDKG enables runtime distributed DKG (multi-party DKG over
	// P2P) at node startup. Default: false (OFF) — when off, node behavior is
	// identical to previous releases (single-process simulated DKG). When on,
	// a DKGCoordinator injects a real DistributedDKGRunner + P2P DKGTransport
	// into the TSSManager so GenerateKeyShares() takes the multi-party
	// distributed path. Hard guard: permanently disabled on mainnet
	// (NetworkID==1668) by Validate().
	TSSDistributedDKG bool `json:"tssDistributedDKG"`

	// Economics Configuration
	// FIX: FeeDistributionInterval was hardcoded to 100 blocks.
	// Now configurable via node config. 0 means use default (100).
	FeeDistributionInterval uint64 `json:"feeDistributionInterval"`

	// Upgrade / Fork Scheduling Configuration
	// NODE-FIX: Previously the entire upgrade/ package (ForkManager +
	// MigrationManager) was implemented but never wired into the node startup
	// path — hard forks could not be scheduled and database migrations did
	// not run. This config allows operators to enable/disable the subsystem
	// and supply a custom chain config file containing the fork schedule.
	Upgrade UpgradeNodeConfig `json:"upgrade"`

	// sourcePath records the file path this config was loaded from. It is
	// unexported (never serialized) and is used solely by config hot-reload
	// (audit-fix M6-3) to know which file to re-read on SIGHUP / file change.
	sourcePath string
}

// UpgradeNodeConfig holds upgrade/fork scheduling configuration.
// NODE-FIX: See Upgrade field on Config.
type UpgradeNodeConfig struct {
	// Enabled controls whether the ForkManager is initialized and
	// migrations are run at startup. When false, the node uses
	// genesis-only consensus rules (no fork scheduling).
	// Defaults to true — operators must explicitly disable to opt out.
	Enabled bool `json:"enabled"`

	// ChainConfigFile is an optional path to a JSON file containing
	// a ChainConfig (fork schedule). When empty, the node uses the
	// built-in default for its NetworkID (mainnet/testnet/devnet).
	ChainConfigFile string `json:"chainConfigFile"`

	// RunMigrations controls whether pending database migrations run
	// at startup. Defaults to true. Set to false to skip migrations
	// (e.g., for read-only snapshot nodes).
	RunMigrations bool `json:"runMigrations"`
}

// DefaultUpgradeNodeConfig returns the default upgrade configuration.
// NODE-FIX: Enabled=true and RunMigrations=true by default so that
// the fork scheduling and migration subsystem is active out of the box.
func DefaultUpgradeNodeConfig() UpgradeNodeConfig {
	return UpgradeNodeConfig{
		Enabled:       true,
		RunMigrations: true,
	}
}

// AlertingNodeConfig holds alerting system configuration
type AlertingNodeConfig struct {
	Enabled    bool   `json:"enabled"`    // Enable alerting system
	ConfigFile string `json:"configFile"` // Path to alerting config file (default: configs/alerting.json)
}

// DankshardingNodeConfig holds DA committee / danksharding configuration.
// P1-5 (2026-07-14): Previously DankshardingConfig was constructed with zero
// values during node initialization, meaning Enabled=false and no way to
// activate the DA committee at runtime. Now loaded from the node config
// file's "danksharding" section, allowing operators to enable/disable DA
// and tune committee parameters without recompiling.
type DankshardingNodeConfig struct {
	// Enabled controls whether the DankshardingEngine is active. When false,
	// the node skips DA committee participation and blob processing.
	// Mainnet should set this to true; testnet/devnet may set false during
	// early operation when the validator count is below DACommitteeSize.
	Enabled bool `json:"enabled"`
	// Experimental marks the DA subsystem as experimental. When true, a
	// warning is logged at startup. Set to false for production mainnet.
	Experimental bool `json:"experimental"`
	// WarningMessage is a custom warning shown when Experimental=true.
	// If empty, a default warning is used.
	WarningMessage string `json:"warningMessage"`
	// CommitteeSize overrides the default DA committee size (512). 0 = use
	// the consensus.DACommitteeSize constant. Useful for testnet/devnet
	// with fewer validators.
	CommitteeSize int `json:"committeeSize"`
	// SubnetCount overrides the default DA subnet count (32). 0 = use
	// the consensus.DACommitteeSubnetCount constant.
	SubnetCount int `json:"subnetCount"`
}

// DefaultDankshardingNodeConfig returns the default DA configuration.
// P1-5 (2026-07-14): Disabled by default — operators must explicitly opt in
// via the config file's "danksharding" section. This is fail-closed: if the
// section is missing or "enabled" is false, the DA subsystem stays dormant.
func DefaultDankshardingNodeConfig() DankshardingNodeConfig {
	return DankshardingNodeConfig{
		Enabled:      false,
		Experimental: true,
	}
}

// ToDankshardingConfig converts the node-level DA config to the core engine
// config. P1-5 (2026-07-14): This bridges the JSON-loaded configuration to
// the DankshardingEngine constructor parameter.
func (c DankshardingNodeConfig) ToDankshardingConfig() core.DankshardingConfig {
	return core.DankshardingConfig{
		Enabled:        c.Enabled,
		Experimental:   c.Experimental,
		WarningMessage: c.WarningMessage,
	}
}

// ToDACommitteeConfig converts the node-level DA config to the consensus
// committee config. P1-5 (2026-07-14): CommitteeSize>0 overrides the default
// 512-validator committee size, allowing testnet/devnet to run with smaller
// committees.
func (c DankshardingNodeConfig) ToDACommitteeConfig() consensus.DACommitteeConfig {
	return consensus.DACommitteeConfig{
		Enabled: c.Enabled,
		Size:    c.CommitteeSize,
	}
}

// ShardingNodeConfig holds sharding configuration for the node.
// P1-6 (2026-07-14): Previously sharding parameters were hardcoded or
// absent. Now loaded from the config file's "sharding" section.
//
// The subsystem is enabled by the QAU_ENABLE_SHARDING=1 env var (see
// initSharding in node.go). These fields tune operation once enabled and
// are safe to hot-reload at runtime — they only affect future shard
// creation and block production, not running shards.
type ShardingNodeConfig struct {
	// MaxCount is the maximum number of shards the manager will accept.
	// P1-4 (validator assignment) and P1-2 (block production) consult this
	// before creating new shards. 0 = use default (64).
	MaxCount int `json:"maxCount"`

	// BlockSize is the maximum serialized size of a shard block in bytes.
	// ProposeBlock (P1-2) rejects blocks exceeding this limit. 0 = default (1MB).
	BlockSize int `json:"blockSize"`

	// Interval is the shard block production interval in seconds. P1-2's
	// production loop uses this as the slot duration. 0 = default (12s, same
	// as the main chain block time).
	Interval int `json:"interval"`

	// MinValidators is the minimum number of validators required to create
	// and activate a shard. CreateShard (P1-2/P1-4) rejects lists shorter
	// than this. 0 = default (3, matching the mainnet validator count).
	MinValidators int `json:"minValidators"`

	// SlotResolverMode controls how shard block heights map to main-chain
	// slots for proposer election verification. Valid values:
	//   "" / "1:1" — shard height N → main slot N (default)
	//   "linear"   — slot = height * MaxCount + shardID (dense packing)
	// Future modes may be added. Unknown values fall back to 1:1.
	SlotResolverMode string `json:"slotResolverMode"`
}

// DefaultShardingNodeConfig returns the default sharding configuration.
// P1-6 (2026-07-14): Disabled by default — sharding is enabled via the
// QAU_ENABLE_SHARDING=1 env var. These defaults match the doc-recommended
// values (02-shard-manager.md §P1-6): maxCount=64, blockSize=1MB,
// interval=12s, minValidators=3.
func DefaultShardingNodeConfig() ShardingNodeConfig {
	return ShardingNodeConfig{
		MaxCount:         64,
		BlockSize:        1 << 20, // 1 MB
		Interval:         12,      // 12 seconds (matches main chain block time)
		MinValidators:    3,
		SlotResolverMode: "", // 1:1 mapping
	}
}

// EffectiveMaxCount returns MaxCount, falling back to the default (64) when 0.
func (c ShardingNodeConfig) EffectiveMaxCount() int {
	if c.MaxCount > 0 {
		return c.MaxCount
	}
	return 64
}

// EffectiveBlockSize returns BlockSize, falling back to the default (1MB) when 0.
func (c ShardingNodeConfig) EffectiveBlockSize() int {
	if c.BlockSize > 0 {
		return c.BlockSize
	}
	return 1 << 20
}

// EffectiveInterval returns Interval, falling back to the default (12s) when 0.
func (c ShardingNodeConfig) EffectiveInterval() int {
	if c.Interval > 0 {
		return c.Interval
	}
	return 12
}

// EffectiveMinValidators returns MinValidators, falling back to the default (3) when 0.
func (c ShardingNodeConfig) EffectiveMinValidators() int {
	if c.MinValidators > 0 {
		return c.MinValidators
	}
	return 3
}

// BridgeNodeConfig holds cross-chain bridge configuration for the node.
// P0-3 FIX (2026-07-13): Previously initBridge() used DefaultBridgeConfig()
// with an empty NodeURLs map, resulting in zero adapters registered.
// Now loaded from the node config file's "bridge" section.
type BridgeNodeConfig struct {
	// NodeURLs maps chain IDs to their respective node RPC URLs.
	// Example: {"quantaureum": "http://localhost:8545", "ethereum": "http://localhost:8546"}
	NodeURLs map[string]string `json:"nodeUrls"`
	// BridgeContractAddresses maps chain IDs to bridge contract addresses.
	BridgeContractAddresses map[string]string `json:"bridgeContractAddresses"`
	// GasLimit is the default gas limit for cross-chain calls.
	GasLimit uint64 `json:"gasLimit"`
	// ConfirmationsRequired is the number of confirmations required on source chain.
	ConfirmationsRequired int `json:"confirmationsRequired"`
	// MessageExpiration is the default message expiration time in seconds.
	MessageExpiration int64 `json:"messageExpiration"`
	// PollingInterval is the interval for polling source chain events, in seconds.
	PollingInterval int `json:"pollingInterval"`
	// MaxRetries is the maximum number of retries for message processing.
	MaxRetries int `json:"maxRetries"`
	// InitializerAddress is the address authorized to set the governance address
	// for the first time on Quantaureum chain adapters.
	InitializerAddress string `json:"initializerAddress"`

	// P0-4 FIX (2026-07-13): Trusted public keys for verifying cross-chain messages.
	// These are hex-encoded Dilithium3 public keys (1952 bytes = 3904 hex chars).
	// When set, they are injected into the respective adapter at startup via
	// SetTrustedPublicKeyBytes / SetTrustedRelayerPublicKeyBytes, enabling
	// VerifyMessage to validate message signatures without requiring a governance
	// vote. Leave empty to disable verification (adapter will reject all messages
	// with "no trusted key configured" until governance sets keys via vote).
	ValidatorPublicKeyHex string `json:"validatorPublicKeyHex"` // Quantaureum adapter trusted key
	RelayerPublicKeyHex   string `json:"relayerPublicKeyHex"`   // Ethereum/external adapter trusted key

	// P1-3 FIX (2026-07-13): Governance address to set on all chain adapters
	// at startup. Required before event signatures can be registered. The
	// initializer address (above) must also be set — it authorizes the first
	// governance address assignment. After this initial setup, only the
	// governance address itself can rotate it or register event signatures.
	GovernanceAddress string `json:"governanceAddress"`

	// R41-BRIDGE-07 (2026-08-03) FIX: OperatorAdminAddress is the address
	// authorized to call SetAuthorizedOperatorsAuthorized on the bridge's
	// AssetLockManager, i.e. the trust root that backs
	// `qau_bridgeRefundFailedLock`'s operator allowlist. When empty, the
	// AssetLockManager starts fail-closed (no operators can be injected →
	// qau_bridgeRefundFailedLock rejects every caller). For most
	// deployments this should equal `GovernanceAddress` (the same
	// governance/multisig that rotates the adapter governance address also
	// rotates the bridge operator set). Wire this in the node config JSON
	// (`bridge.operatorAdminAddress`) or via the
	// `QAU_BRIDGE_OPERATOR_ADMIN_ADDRESS` env var override (see
	// node/node.go initBridge parsing).
	OperatorAdminAddress string `json:"operatorAdminAddress"`

	// P1-1 FIX (2026-07-13): HTTP listen address for the BridgeAPI server.
	// When non-empty, a standalone HTTP server is started exposing the 7
	// bridge endpoints (/api/v1/bridge/*). Bind to 127.0.0.1:8547 for
	// local-only access, or 0.0.0.0:8547 for external access (behind a
	// reverse proxy with TLS). Leave empty to disable the HTTP API (the
	// 3 read-only RPC methods remain available via the node's JSON-RPC port).
	BridgeAPIAddr string `json:"bridgeApiAddr"`

	// P1-1 FIX (2026-07-13): API key for authenticating BridgeAPI requests.
	// Required when BridgeAPIAddr is set. Requests must include
	// "X-API-Key: <key>" header. The key is hashed (SHA-256) internally;
	// do NOT commit the real key to version control — use env var
	// QAU_BRIDGE_API_KEY instead.
	BridgeAPIKey string `json:"bridgeApiKey"`
}

// KeyRotationConfig holds key rotation configuration
type KeyRotationConfig struct {
	Enabled          bool   `json:"enabled"`
	KeyDir           string `json:"keyDir"`
	RotationInterval int    `json:"rotationInterval"` // days
	MaxKeyAge        int    `json:"maxKeyAge"`        // days
	BackupEnabled    bool   `json:"backupEnabled"`
	BackupDir        string `json:"backupDir"`
}

// TLSCertRotationConfig holds TLS certificate rotation configuration
type TLSCertRotationConfig struct {
	Enabled          bool   `json:"enabled"`
	CertDir          string `json:"certDir"`
	Organization     string `json:"organization"`
	CommonName       string `json:"commonName"`
	ValidityDuration int    `json:"validityDuration"` // days
	RenewalThreshold int    `json:"renewalThreshold"` // days
	BackupEnabled    bool   `json:"backupEnabled"`
	BackupDir        string `json:"backupDir"`
}

// ParallelExecutionConfig holds parallel execution settings.
type ParallelExecutionConfig struct {
	Enabled    bool `json:"enabled"`
	NumWorkers int  `json:"numWorkers"`
	MaxRetries int  `json:"maxRetries"`
}

// CacheOptConfig holds cache optimization settings.
type CacheOptConfig struct {
	L1MaxSize   int   `json:"l1MaxSize"`
	L1MaxMemory int64 `json:"l1MaxMemory"` // bytes
	L2MaxSize   int   `json:"l2MaxSize"`
	L2MaxMemory int64 `json:"l2MaxMemory"` // bytes
	TTLSeconds  int   `json:"ttlSeconds"`
}

// PruningOptConfig holds state pruning settings.
type PruningOptConfig struct {
	Enabled         bool `json:"enabled"`
	RetentionBlocks int  `json:"retentionBlocks"`
	BatchSize       int  `json:"batchSize"`
}

// Network IDs
const (
	MainnetNetworkID = 1668 // Quantaureum Mainnet
	TestnetNetworkID = 1669 // Quantaureum Testnet
	DevnetNetworkID  = 1333 // Development network
)

// DefaultConfig returns the default node configuration (Production mode)
func DefaultConfig() *Config {
	return &Config{
		Name:            "qau-node",
		NodeID:          "node-1",
		DataDir:         "./data",
		NetworkID:       MainnetNetworkID, // Production: 1668
		ListenAddr:      "127.0.0.1:9000", // FIX: bind to localhost by default; use 0.0.0.0:9000 + ExternalIP for production
		MaxPeers:        50,
		EnableDHT:       true, // Enable DHT discovery by default (like Ethereum discv4)
		NodeDBPath:      "",   // Empty = auto-derive from DataDir
		RPCEnabled:      true,
		RPCAuthEnabled:  true,
		RPCAddr:         "127.0.0.1:8545", // bind loopback by default; use 0.0.0.0 only behind a reverse proxy with TLS
		WSEnabled:       true,
		WSAddr:          "127.0.0.1:8546",
		MetricsEnabled:  true,
		MetricsAddr:     "127.0.0.1:9090", // MED-003 FIX: bind to localhost only; 0.0.0.0 would expose metrics publicly
		MetricsPath:     "/metrics",
		FrontendEnabled: true,
		FrontendAddr:    "127.0.0.1:8088",
		HealthEnabled:   true,
		HealthAddr:      "127.0.0.1:8080",
		CacheSize:       512,
		MaxGasLimit:     30000000,
		LogLevel:        "info",
		LogFormat:       "json",
		// AUDIT (2026) NODE-04: GenesisFile defaults to empty so that
		// ResolveNetworkConfig can select the correct genesis file based on
		// the Network field (dev/testnet/mainnet). A non-empty default like
		// "genesis.json" caused ResolveNetworkConfig's `if GenesisFile == ""`
		// check to always be skipped, loading an unexpected ./genesis.json
		// from the current working directory instead of the network-specific
		// file. This led to different genesis being loaded depending on CWD.
		GenesisFile:     "",
		ShutdownTimeout: 30,
		ParallelExecution: ParallelExecutionConfig{
			// CRIT-1/CRIT-2 (R8 2026-07-19 FIX): Default to disabled. The
			// parallel QVM executor has known consensus-safety holes
			// (MVMemory Version.Value not populated → write-conflict
			// detection incomplete; validateTransaction missing codeKey
			// check → CREATE/SELFDESTRUCT code changes not conflict-detected).
			// Until CRIT-1 and CRIT-2 are fully fixed, parallel execution
			// must NOT be enabled in production — it can cause different
			// validators to compute different states, leading to consensus
			// divergence. Tests/devnets may explicitly set Enabled=true to
			// exercise the parallel path; initOptimizations() additionally
			// hard-blocks enabling when QAU_PRODUCTION=1 regardless of this
			// config value.
			Enabled:    false,
			NumWorkers: 0, // 0 means use runtime.NumCPU()
			MaxRetries: 5,
		},
		CacheConfig: CacheOptConfig{
			L1MaxSize:   1024,
			L1MaxMemory: 64 * 1024 * 1024, // 64 MB
			L2MaxSize:   8192,
			L2MaxMemory: 256 * 1024 * 1024, // 256 MB
			TTLSeconds:  300,               // 5 minutes
		},
		PruningConfig: PruningOptConfig{
			Enabled:         true,
			RetentionBlocks: 1000,
			BatchSize:       100,
		},
		KeyRotation: KeyRotationConfig{
			Enabled:          true,
			KeyDir:           "./keys",
			RotationInterval: 30, // 30 days
			MaxKeyAge:        90, // 90 days
			BackupEnabled:    true,
			BackupDir:        "./keys/backup",
		},
		TLSCertRotation: TLSCertRotationConfig{
			Enabled:          true,
			CertDir:          "./certs",
			Organization:     "Quantaureum",
			CommonName:       "node.quantaureum.local",
			ValidityDuration: 365, // 1 year
			RenewalThreshold: 30,  // 30 days before expiry
			BackupEnabled:    true,
			BackupDir:        "./certs/backup",
		},
		AlertingConfig: AlertingNodeConfig{
			Enabled: true,
			// P3-NODE-03 FIX (R30, 2026-07-27): resolve alerting config path
			// from QAU_ALERTING_CONFIG_FILE env var so the node does not
			// depend on CWD. Falls back to "configs/alerting.json" for
			// backward compatibility.
			ConfigFile: resolvePathEnv("QAU_ALERTING_CONFIG_FILE", "configs/alerting.json"),
		},
		// P1-5 (2026-07-14): DA disabled by default. Operators must explicitly
		// set "danksharding": {"enabled": true} in the config file to activate.
		Danksharding: DefaultDankshardingNodeConfig(),
		// P1-6 (2026-07-14): Sharding defaults (maxCount=64, blockSize=1MB,
		// interval=12s, minValidators=3). Subsystem enabled via QAU_ENABLE_SHARDING=1.
		Sharding: DefaultShardingNodeConfig(),
		// TSS-/ (2026-07-16): TSS threshold/totalShares are NOT
		// set in DefaultConfig() because the default NetworkID is mainnet,
		// and mainnet requires pre-generated shares (tssKeyShareFile) plus
		// distributed mode for multi-share configs. Setting non-zero TSS
		// defaults here would make DefaultConfig() an invalid mainnet config.
		// Operators must explicitly configure TSS in their config file.
		// DevConfig() and TestnetConfig() set TSS defaults for testing
		// (trusted dealer DKG is allowed on non-mainnet networks).
		// NODE-FIX: Enable fork scheduling + migrations by default.
		Upgrade: DefaultUpgradeNodeConfig(),
	}
}

// resolvePathEnv resolves a filesystem path from an environment variable,
// falling back to the provided default when the variable is empty.
//
// P3-NODE-03 FIX (R30, 2026-07-27): previously several default paths
// (configs/alerting.json, genesis/*.json) were hardcoded as relative
// paths, making the node depend on the current working directory at
// startup. This broke systemd deployments that set WorkingDirectory to
// a non-default location and caused confusing "file not found" errors.
// Operators can now override these paths via env vars (e.g.
// QAU_ALERTING_CONFIG_FILE, QAU_GENESIS_FILE) without changing config
// files or CLI flags. The default fallback preserves backward compat.
func resolvePathEnv(envVar, defaultPath string) string {
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return defaultPath
}

// DevConfig returns the development node configuration
func DevConfig() *Config {
	cfg := DefaultConfig()
	cfg.NetworkID = DevnetNetworkID
	cfg.LogLevel = "debug"
	cfg.DevMode = true
	cfg.BlockInterval = 3 // 3 seconds
	// audit-fix M-2: explicitly enable auto-unlock for dev mode since DevConfig is for local testing only
	cfg.DevAutoUnlockAccounts = true
	// TSS-/ (2026-07-16): Devnet allows trusted dealer DKG and
	// local mode multi-share for development convenience (hard guards are
	// mainnet-only). These defaults let dev nodes exercise the TSS path
	// without requiring an offline key ceremony.
	cfg.TSSThreshold = 2
	cfg.TSSTotalShares = 3
	return cfg
}

// TestnetConfig returns the testnet node configuration
func TestnetConfig() *Config {
	cfg := DefaultConfig()
	cfg.NetworkID = TestnetNetworkID
	// TSS-/ (2026-07-16): Testnet allows trusted dealer DKG and
	// local mode multi-share for testing (hard guards are mainnet-only).
	cfg.TSSThreshold = 3
	cfg.TSSTotalShares = 4
	cfg.TSSDistributedMode = false
	return cfg
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- config path from CLI flags, validated by caller
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	ResolveNetworkConfig(cfg)

	// Password resolution priority (EIP-2335 style, same as Ethereum):
	// 1. Password file (validatorPasswordFile in config, or --validator-password-file CLI flag)
	// 2. Environment variable QAU_VALIDATOR_KEY_PASSWORD
	// 3. validatorKeyPassword in config (least secure)
	// Note: CLI flag overrides are applied later in applyFlagOverrides().
	if cfg.ValidatorPasswordFile != "" {
		data, err := os.ReadFile(cfg.ValidatorPasswordFile) // #nosec G304 -- path from config, operator-controlled
		if err != nil {
			return nil, fmt.Errorf("failed to read validator password file %s: %w", cfg.ValidatorPasswordFile, err)
		}
		pwd := strings.TrimSpace(string(data))
		if pwd == "" {
			return nil, fmt.Errorf("validator password file %s is empty", cfg.ValidatorPasswordFile)
		}
		cfg.ValidatorKeyPassword = pwd
	} else if envPass := os.Getenv("QAU_VALIDATOR_KEY_PASSWORD"); envPass != "" {
		cfg.ValidatorKeyPassword = envPass
	}

	// HIGH-012 FIX: QAU_VALIDATOR_KEY env var takes precedence for the key path itself.
	if envKey := os.Getenv("QAU_VALIDATOR_KEY"); envKey != "" {
		cfg.ValidatorKey = envKey
	}

	// audit-fix M6-3: remember the source path so the node can hot-reload
	// from the same file (unexported field, never serialized).
	cfg.sourcePath = path

	return cfg, nil
}

// ResolveNetworkConfig resolves network-specific settings from the Network field.
// Named public networks use their production settings, while the dev preset
// enables local development behavior. Explicit genesis files still take precedence.
func ResolveNetworkConfig(cfg *Config) {
	if cfg == nil {
		return
	}
	if preset, ok := NetworkPresetByName(cfg.Network); ok {
		cfg.Network = preset.Name
		if len(cfg.BootstrapPeers) == 0 && len(preset.DefaultBootnodes) > 0 {
			cfg.BootstrapPeers = append([]string(nil), preset.DefaultBootnodes...)
		}
	}
	if cfg.GenesisFile == "" {
		// An explicit file always wins. The environment variable is an operator
		// override; named public networks do not require a runtime JSON file.
		if path := os.Getenv("QAU_GENESIS_FILE"); path != "" {
			cfg.GenesisFile = path
		}
	}

	switch cfg.Network {
	case NetworkDev:
		applyPresetNetworkID(cfg, DevnetNetworkID)
		cfg.DevMode = true
		cfg.DevBlocks = true
		if cfg.BlockInterval == 0 {
			cfg.BlockInterval = 3
		}
		cfg.DevAutoUnlockAccounts = true
		cfg.LogLevel = "debug"
	case NetworkTestnet:
		applyPresetNetworkID(cfg, TestnetNetworkID)
		// Public testnet follows the same consensus path as mainnet. DevMode
		// injects development accounts and bypasses signature verification,
		// so it is reserved for the local dev preset only.
		if cfg.BlockInterval == 0 {
			cfg.BlockInterval = 12
		}
		if cfg.LogLevel == "" {
			cfg.LogLevel = "debug"
		}
		if cfg.ExpectedGenesisHash == "" {
			cfg.ExpectedGenesisHash = TestnetGenesisHash
		}
	case NetworkMainnet:
		applyPresetNetworkID(cfg, MainnetNetworkID)
		if cfg.ExpectedGenesisHash == "" {
			cfg.ExpectedGenesisHash = MainnetGenesisHash
		}
	}
	// Fallback to the canonical network bootnodes when the operator did not
	// supply any bootstrap peers (flag or config). Explicit peers always win;
	// this only fills the zero value, mirroring go-ethereum's behaviour.
	if len(cfg.BootstrapPeers) == 0 {
		cfg.BootstrapPeers = networkBootnodes[string(cfg.Network)]
	}
}

func applyPresetNetworkID(cfg *Config, networkID uint64) {
	// DefaultConfig starts with the mainnet ID. Preserve any other explicit ID
	// so Config.Validate can report the disagreement instead of hiding it.
	if cfg.NetworkID == 0 || cfg.NetworkID == MainnetNetworkID {
		cfg.NetworkID = networkID
	}
}

// SaveConfig saves configuration to a file
func (c *Config) SaveConfig(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil { // #nosec G301
		return err
	}

	// audit-fix L-1: use 0600 since config may contain sensitive settings
	return os.WriteFile(path, data, 0600)
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Network != "" {
		preset, ok := NetworkPresetByName(c.Network)
		if !ok {
			return fmt.Errorf("unknown network %q (valid values: dev, testnet, mainnet)", c.Network)
		}
		if c.NetworkID != 0 && c.NetworkID != preset.NetworkID {
			return fmt.Errorf("network %q requires networkId %d, got %d", preset.Name, preset.NetworkID, c.NetworkID)
		}
	}

	if preset, ok := NetworkPresetByName(c.Network); ok && preset.HasBuiltInGenesis {
		if c.DevMode {
			return fmt.Errorf("devMode must not be enabled on %s (networkId=%d)", preset.Name, c.NetworkID)
		}
		if c.DevBlocks {
			return fmt.Errorf("devBlocks must not be enabled on %s (networkId=%d)", preset.Name, c.NetworkID)
		}
	}

	// AUDIT (2026) DA-FIX (CRITICAL): Mainnet hard guard for DA.
	// The current DAS implementation uses hash placeholders for KZG
	// commitments and opening proofs (encoding/blob_tx.go:KZGCommitmentFromBlob,
	// ComputeBlobKZGProof, VerifyBlobKZGProof; encoding/erasure_code.go:
	// ComputeCellProof, VerifyCellProof). These are NOT real polynomial
	// commitments — any cell can be paired with a forged proof that passes
	// verification. This destroys the DAS reliability guarantee.
	//
	// Until a real post-quantum polynomial commitment scheme (STARK/FRI or
	// lattice-based) with correct opening proofs and batch verification is
	// implemented, Danksharding/DA committee MUST NOT be enabled on mainnet.
	// This is a code-level hard guard (fail-closed) — not just documentation.
	if c.Danksharding.Enabled && c.NetworkID == MainnetNetworkID {
		return fmt.Errorf("danksharding/DA committee must not be enabled on mainnet (networkId=%d): "+
			"KZG commitments and opening proofs are hash placeholders, not real polynomial commitments "+
			"(DA-). Disable danksharding.enabled in config or wait for post-quantum polynomial "+
			"commitment implementation", c.NetworkID)
	}

	// Task 5 (TSSDistributedDKG): mainnet hard guard — runtime distributed
	// DKG is permanently disabled on mainnet. Even multi-party DKG exchanges
	// sensitive Shamir material over P2P; mainnet validators MUST import
	// pre-generated encrypted shares (tssKeyShareFile) from an offline key
	// ceremony. The switch defaults to OFF; enabling it on mainnet is a
	// code-level fail-closed error, not just documentation.
	if c.NetworkID == MainnetNetworkID && c.TSSDistributedDKG {
		return fmt.Errorf("tssDistributedDKG must not be enabled on mainnet (networkId=%d): "+
			"runtime distributed DKG is permanently disabled on mainnet; validators must import "+
			"pre-generated encrypted shares (tssKeyShareFile) from an offline key ceremony",
			c.NetworkID)
	}

	// AUDIT (2026) TSS-FIX (HIGH, supersedes TSS-): Mainnet
	// hard guard against ANY runtime DKG at startup.
	//
	// TSS- GenerateKeyShares() now uses distributed DKG by default
	// (qtd.GenerateDKGDistributedSimulated — renamed by TSS- because
	// the function is a single-process simulation, not a real distributed
	// DKG). No single seed captures the full key, CombinedSeed is nil, and
	// aggregated s1/s2/t0 are zeroized before return. The legacy
	// trusted-dealer path (mode3.NewKeyFromSeed in a single process) is
	// opt-in only via GenerateKeySharesTrustedDealer() and requires
	// QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1.
	//
	// TSS- (2026-07-17): The "distributed" path below is functionally a
	// trusted dealer without a seed — the calling process holds all shares
	// and can reconstruct the full key. The real P2P closure path is
	// qtd.DistributedDKGRunner: implemented by qtd.NewRealDistributedDKGRunner
	// (dkg_distributed.go, Feldman VSS commitments) and wired at node startup
	// via wireDKGCoordinator() (tss_dkg_coordinator.go) when the
	// TSSDistributedDKG switch is ON (non-mainnet only). When the switch is
	// OFF (default), no runner is injected and GenerateKeyShares() falls back
	// to the single-process simulated path described above.
	//
	// However, MAINNET STILL MUST NOT RUN ANY RUNTIME DKG. Even the
	// simulated distributed DKG in a single process briefly aggregates
	// s1/s2/t0 in memory before Shamir-splitting — an attacker controlling
	// the host during the call could dump those transient secrets. Mainnet
	// validators MUST import pre-generated shares via TSSKeyShareFile
	// (produced offline in a controlled key ceremony on an air-gapped host).
	// This is a code-level hard guard (fail-closed) — not just documentation.
	//
	// Detection: when TSSKeyShareFile is empty/unset AND TSSGroupKeyFile is
	// also empty/unset, the node has no pre-generated key material and would
	// fall through to GenerateKeyShares() at startup (node.go:2334).
	// We block this on mainnet. (TSSKeyShareFile alone is sufficient because
	// it contains both the shares and the group public key; TSSGroupKeyFile
	// is an optional separate group-public-key file.)
	if c.NetworkID == MainnetNetworkID &&
		c.TSSKeyShareFile == "" &&
		c.TSSGroupKeyFile == "" &&
		(c.TSSTotalShares > 0 || c.TSSThreshold > 0) {
		return fmt.Errorf("TSS- mainnet (networkId=%d) must not run any runtime DKG at startup: "+
			"even distributed DKG briefly aggregates s1/s2/t0 in single-process memory before "+
			"Shamir-splitting. Set tssKeyShareFile in config to point to pre-generated encrypted "+
			"shares produced by an offline key ceremony on an air-gapped host. For threshold=1 "+
			"ceremonies use QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1; for threshold>=2 use distributed "+
			"DKG on the air-gapped host.",
			c.NetworkID)
	}

	// AUDIT (2026) TSS-FIX (HIGH): Mainnet hard guard against
	// single-node-all-shares local mode. When TSSDistributedMode=false AND
	// TotalShares > 1, the node loads ALL threshold shares into a single
	// TSSManager and signs via SignWithRetry (in-process aggregation). This
	// is cryptographically equivalent to single-key signing — it provides
	// NO threshold security. An attacker controlling the host obtains all
	// shares and can produce valid group signatures without threshold
	// cooperation.
	//
	// On mainnet, multi-share threshold signing MUST use TSSDistributedMode=true
	// (P2P multi-party signing). The single-share degenerate case
	// (TotalShares == 1) is permitted because it is honest about being
	// single-signer.
	//
	// Test networks and dev nets may use local mode for development
	// convenience by setting QAU_ALLOW_UNSAFE_LOCAL_TSS=1 in the environment.
	// This mirrors the QAU_ENABLE_DISTRIBUTED_TSS / QAU_ALLOW_UNSAFE_DISTRIBUTED_TSS
	// two-key gate pattern used for the distributed TSS kill-switch.
	if c.NetworkID == MainnetNetworkID &&
		!c.TSSDistributedMode &&
		c.TSSTotalShares > 1 {
		// Allow explicit operator override ONLY when they acknowledge the risk.
		// This is a defense-in-depth escape hatch, not a production setting.
		if os.Getenv("QAU_ALLOW_UNSAFE_LOCAL_TSS") != "1" {
			return fmt.Errorf("TSS- mainnet (networkId=%d) must not run TSS in local "+
				"single-node-all-shares mode with tssTotalShares=%d > 1: this provides no "+
				"threshold security (equivalent to single-key signing). Set tssDistributedMode=true "+
				"in config for P2P multi-party threshold signing, or set tssTotalShares=1 if "+
				"single-signer mode is intentional. For non-mainnet testing, set QAU_ALLOW_UNSAFE_LOCAL_TSS=1.",
				c.NetworkID, c.TSSTotalShares)
		}
		// Operator explicitly acknowledged the risk — log at WARN level via
		// the standard logger at startup. The node.go init path also emits
		// a loud warning.
	}

	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	// P3-NODE-02 FIX (R29, 2026-07-26): Resolve relative DataDir to an
	// absolute path so that all derived paths (NodeDBPath, KeyDir, CertDir,
	// keystore, etc.) no longer depend on the current working directory.
	// Previously, if a systemd service restarted with a different CWD
	// (e.g., after a package upgrade), the node would silently start
	// writing to a different ./data directory — causing data loss,
	// missing validator keys, or loading an unrelated chain state.
	// Absolute path resolution here is the single source of truth; all
	// downstream code uses filepath.Join on DataDir.
	if abs, err := filepath.Abs(c.DataDir); err == nil {
		c.DataDir = abs
	}
	if c.NetworkID == 0 {
		c.NetworkID = MainnetNetworkID
	}
	if c.MaxPeers <= 0 {
		c.MaxPeers = 50
	}

	// P2P-R11-M04 (2026-07-20): Reject the CORS wildcard "*" on mainnet and
	// testnet. A wildcard on a production network allows any website to issue
	// credentialed cross-origin requests to the RPC — a CSRF risk. The
	// runtime path (rpc/server.go:setCORSHeaders) already replaces "*" with
	// `mainnetDefaultOrigins` on mainnet, but that silent substitution is a
	// safety net, not a contract: an operator who configures "*" expecting
	// "allow everything" would not realize their config is being ignored,
	// and the same protection does NOT apply on testnet. Fail closed at
	// config-validation time so the misconfiguration is caught at startup
	// rather than silently papered over.
	//
	// Devnet (NetworkID=1333) is exempted because local development often
	// uses arbitrary ports (localhost:3000, localhost:5173, etc.) and
	// requiring explicit enumeration there would harm DX without adding
	// real security (devnet tokens have no value and the network is
	// isolated from mainnet state).
	if c.NetworkID != DevnetNetworkID {
		for _, o := range c.AllowedOrigins {
			if o == "*" {
				return fmt.Errorf("allowedOrigins must not contain \"*\" on networkId=%d "+
					"(mainnet/testnet): wildcard CORS allows any website credentialed cross-origin access "+
					"to the RPC (CSRF risk). Explicitly list trusted origins instead (e.g. "+
					"https://quantaureum.com). Devnet (networkId=%d) is exempt for local development",
					c.NetworkID, DevnetNetworkID)
			}
		}
	}

	// Auto-derive NodeDBPath from DataDir if not set
	if c.NodeDBPath == "" && c.DataDir != "" {
		c.NodeDBPath = filepath.Join(c.DataDir, "nodes")
	}
	if c.CacheSize <= 0 {
		c.CacheSize = 512
	}
	if c.MaxGasLimit == 0 {
		c.MaxGasLimit = 30000000
	}

	// Validate Key Rotation
	if c.KeyRotation.KeyDir == "" {
		c.KeyRotation.KeyDir = filepath.Join(c.DataDir, "keys")
	}
	if c.KeyRotation.RotationInterval <= 0 {
		c.KeyRotation.RotationInterval = 30 // 30 days
	}
	if c.KeyRotation.MaxKeyAge <= 0 {
		c.KeyRotation.MaxKeyAge = 90 // 90 days
	}
	if c.KeyRotation.BackupEnabled && c.KeyRotation.BackupDir == "" {
		c.KeyRotation.BackupDir = filepath.Join(c.KeyRotation.KeyDir, "backup")
	}

	// Validate TLS Certificate Rotation
	if c.TLSCertRotation.CertDir == "" {
		c.TLSCertRotation.CertDir = filepath.Join(c.DataDir, "certs")
	}
	if c.TLSCertRotation.Organization == "" {
		c.TLSCertRotation.Organization = "Quantaureum"
	}
	if c.TLSCertRotation.CommonName == "" {
		c.TLSCertRotation.CommonName = "node.quantaureum.local"
	}
	if c.TLSCertRotation.ValidityDuration <= 0 {
		c.TLSCertRotation.ValidityDuration = 365 // 1 year
	}
	if c.TLSCertRotation.RenewalThreshold <= 0 {
		c.TLSCertRotation.RenewalThreshold = 30 // 30 days before expiry
	}
	if c.TLSCertRotation.BackupEnabled && c.TLSCertRotation.BackupDir == "" {
		c.TLSCertRotation.BackupDir = filepath.Join(c.TLSCertRotation.CertDir, "backup")
	}

	// P3-NODE-02 FIX (R29, 2026-07-26): Resolve any remaining relative
	// paths to absolute. DefaultConfig() ships paths like "./keys",
	// "./certs", "./keys/backup" — these are CWD-dependent. After the
	// DataDir is made absolute above, we re-anchor relative KeyDir /
	// CertDir / BackupDir paths against the (now absolute) DataDir so
	// the node no longer depends on CWD for any runtime path.
	c.KeyRotation.KeyDir = resolveRelativeToDataDir(c.DataDir, c.KeyRotation.KeyDir)
	if c.KeyRotation.BackupEnabled {
		c.KeyRotation.BackupDir = resolveRelativeToDataDir(c.DataDir, c.KeyRotation.BackupDir)
	}
	c.TLSCertRotation.CertDir = resolveRelativeToDataDir(c.DataDir, c.TLSCertRotation.CertDir)
	if c.TLSCertRotation.BackupEnabled {
		c.TLSCertRotation.BackupDir = resolveRelativeToDataDir(c.DataDir, c.TLSCertRotation.BackupDir)
	}

	return nil
}

// resolveRelativeToDataDir returns target if it is already absolute or
// empty; otherwise it joins target onto baseDir (which must already be
// absolute after P3-NODE-02 fix). Used to re-anchor CWD-relative default
// paths like "./keys" to <DataDir>/keys. P3-NODE-02 FIX (R29).
func resolveRelativeToDataDir(baseDir, target string) string {
	if target == "" {
		return target
	}
	if filepath.IsAbs(target) {
		return target
	}
	// target is relative (e.g. "./keys", "keys", "./certs/backup")
	// Strip any leading "./" for clean join.
	return filepath.Join(baseDir, target)
}
