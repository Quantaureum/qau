// Quantaureum Node source, version 1.0.0.
// Package config provides CLI flag definitions and configuration loading
// for the Quantaureum node daemon.
package config

import "flag"

// CLI holds all parsed command-line flag values.
type CLI struct {
	ConfigPath  *string
	DataDir     *string
	GenesisFile *string
	ShowVersion *bool

	NetworkName *string
	NetworkID   *uint64
	ListenAddr  *string
	MaxPeers    *int
	NodeName    *string
	Bootnodes   *string

	Discovery *bool
	NodeDB    *string

	RPCEnabled *bool
	RPCAddr    *string
	RPCAPI     *string
	RPCCors    *string
	RPCVhosts  *string

	WSEnabled *bool
	WSAddr    *string
	WSAPI     *string
	WSOrigins *string

	GraphqlEnabled *bool
	GraphqlAddr    *string

	FrontendEnabled *bool
	FrontendAddr    *string
	HealthEnabled   *bool
	HealthAddr      *string
	MetricsEnabled  *bool
	MetricsAddr     *string

	ValidatorEnabled      *bool
	ValidatorKey          *string
	ValidatorPasswordFile *string
	MineGasLimit          *uint64

	DevMode             *bool
	DevBlocks           *bool
	BlockInterval       *int
	DevAutoUnlock       *bool
	AllowInsecureUnlock *bool

	CacheSize       *int
	ParallelEnabled *bool
	ParallelWorkers *int
	PruneEnabled    *bool
	PruneBlocks     *int
	SyncMode        *string

	LogLevel  *string
	LogFormat *string
	Verbosity *int

	KeyRotation *bool
	TLSEnabled  *bool
	TLSCert     *string
	TLSKey      *string
}

// DefineFlags registers all CLI flags and returns a populated CLI struct after
// flag.Parse() has been called.
func DefineFlags() *CLI {
	c := &CLI{}

	c.ConfigPath = flag.String("config", "", "Path to configuration file")
	c.DataDir = flag.String("datadir", "./data", "Data directory for the node")
	c.GenesisFile = flag.String("genesis", "", "Path to genesis file")
	c.ShowVersion = flag.Bool("version", false, "Show version information")

	c.NetworkName = flag.String("network", "", "Network to connect to (dev, testnet, mainnet)")
	c.NetworkID = flag.Uint64("networkid", 0, "Network ID (1668=mainnet, 1669=testnet, 1333=devnet)")
	c.ListenAddr = flag.String("listen", ":9000", "P2P listen address")
	c.MaxPeers = flag.Int("maxpeers", 50, "Maximum number of network peers")
	c.NodeName = flag.String("nodename", "", "Custom node name for identification")
	c.Bootnodes = flag.String("bootnodes", "", "Comma separated enode URLs for P2P discovery bootstrap")
	c.Discovery = flag.Bool("discovery", true, "Enable Kademlia DHT peer discovery (like Ethereum discv4)")
	c.NodeDB = flag.String("nodedb", "", "Path to node database for persisting discovered peers (empty = auto-derive from datadir)")

	c.RPCEnabled = flag.Bool("rpc", true, "Enable HTTP-RPC server")
	c.RPCAddr = flag.String("rpcaddr", ":8545", "HTTP-RPC server listening address")
	c.RPCAPI = flag.String("rpcapi", "qau,net,web3", "API modules to expose via HTTP-RPC")
	c.RPCCors = flag.String("rpccorsdomain", "", "Comma separated list of domains for CORS (browser enforced)")
	c.RPCVhosts = flag.String("rpcvhosts", "localhost", "Comma separated list of virtual hostnames for RPC")

	c.WSEnabled = flag.Bool("ws", true, "Enable WebSocket-RPC server")
	c.WSAddr = flag.String("wsaddr", ":8546", "WebSocket-RPC server listening address")
	c.WSAPI = flag.String("wsapi", "qau,net,web3", "API modules to expose via WebSocket-RPC")
	// R7-C4 FIX: wsorigins default was "*", which is a cross-site WebSocket
	// hijacking (CSWSH) footgun. Empty default makes the WS server fall back to
	// localhost-only, which is safe for dev tools. Operators who want remote
	// access must opt in explicitly with --wsorigins https://app.example.com.
	c.WSOrigins = flag.String("wsorigins", "", "Origins from which to accept websockets requests (empty = localhost only)")

	c.GraphqlEnabled = flag.Bool("graphql", false, "Enable GraphQL server")
	c.GraphqlAddr = flag.String("graphqladdr", ":8547", "GraphQL server listening address")

	c.FrontendEnabled = flag.Bool("frontend", true, "Enable web frontend")
	c.FrontendAddr = flag.String("frontendaddr", ":8088", "Frontend HTTP server address")
	c.HealthEnabled = flag.Bool("health", true, "Enable health check server")
	c.HealthAddr = flag.String("healthaddr", ":8080", "Health check server address")
	c.MetricsEnabled = flag.Bool("metrics", false, "Enable Prometheus metrics collection")
	c.MetricsAddr = flag.String("metricsaddr", ":9090", "Prometheus metrics server address")

	c.ValidatorEnabled = flag.Bool("validator", false, "Enable validator mode")
	c.ValidatorKey = flag.String("validatorkey", "", "Path to validator key file")
	c.ValidatorPasswordFile = flag.String("validator-password-file", "", "Path to file containing validator key password (EIP-2335 compatible, like Ethereum)")
	c.MineGasLimit = flag.Uint64("gaslimit", 30000000, "Target gas limit for mined blocks")

	c.DevMode = flag.Bool("dev", false, "Enable development mode with auto block production")
	c.DevBlocks = flag.Bool("dev-blocks", false, "Enable block production in dev mode")
	c.BlockInterval = flag.Int("blockinterval", 3, "Block production interval in seconds (dev mode only)")
	c.DevAutoUnlock = flag.Bool("dev-auto-unlock", false, "Auto-unlock dev accounts (use with --dev only, NOT for production)")
	c.AllowInsecureUnlock = flag.Bool("allow-insecure-unlock", false, "Allow personal_* RPC methods over plaintext HTTP (Ethereum-compatible, development only)")

	c.CacheSize = flag.Int("cache", 512, "Megabytes of memory allocated to internal caching")
	c.ParallelEnabled = flag.Bool("parallel", true, "Enable parallel transaction execution (Block-STM)")
	c.ParallelWorkers = flag.Int("parallel.workers", 0, "Number of parallel workers (0=auto detect CPU cores)")
	c.PruneEnabled = flag.Bool("prune", true, "Enable state pruning")
	c.PruneBlocks = flag.Int("prune.blocks", 1000, "Number of recent blocks to retain state for")
	c.SyncMode = flag.String("sync.mode", "snap", "Blockchain sync mode: snap (default, fast) or full (re-execute every block)")

	c.LogLevel = flag.String("loglevel", "", "Log level (trace, debug, info, warn, error, fatal)")
	c.LogFormat = flag.String("logformat", "", "Log format (json, text)")
	c.Verbosity = flag.Int("verbosity", 3, "Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=trace")

	c.KeyRotation = flag.Bool("keyrotation", true, "Enable automatic key rotation")
	c.TLSEnabled = flag.Bool("tls", false, "Enable TLS for RPC connections")
	c.TLSCert = flag.String("tlscert", "", "Path to TLS certificate file")
	c.TLSKey = flag.String("tlskey", "", "Path to TLS key file")

	flag.Parse()
	return c
}
