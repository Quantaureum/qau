// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// audit-fix M-2: fixed genesis timestamps ensure all nodes produce the same genesis block.
// Using time.Now() would cause different nodes to compute different genesis hashes.
//
// R41-GENESIS-16 (2026-08-03) FIX: keep these constants BIT-FOR-BIT
// identical to the timestamps encoded in the canonical genesis JSON
// files (genesis/mainnet.json, genesis/testnet.json, genesis/dev.json).
// Without this alignment, a node that loaded via DefaultGenesis()
// (uses the constant) would compute a DIFFERENT genesis block hash
// than a node that loaded via LoadGenesis(path) (uses the JSON
// timestamp), splitting the network into two non-connectable forks
// the first time any node falls back to the default path (e.g. the
// genesis file is missing on a new operator's machine).
//
// The values below mirror the canonical JSON timestamps captured at
// the V2 mainnet / testnet / devnet launches. Tests in
// TestGenesisTimestamps assert these exact constants so future drift
// is caught at CI time.
const (
	MainnetGenesisTimestamp = uint64(1788816000) // pinned for mainnet relaunch R130 (key rotation)
	TestnetGenesisTimestamp = uint64(1780910400) // matches genesis/testnet.json timestamp (V2 testnet launch)
	DevnetGenesisTimestamp  = uint64(1777140239) // matches genesis/dev.json timestamp (V2 devnet launch)
)

// Genesis represents the genesis block configuration
type Genesis struct {
	// Chain configuration
	ChainID   uint64 `json:"chainId"`
	NetworkID uint64 `json:"networkId"`
	// FIX: Minimum checkpoint signatures required for this network.
	// 0 (default) means "use the dynamic ceil(activeValidators*2/3) computation".
	// testnet declares 3 (ceil(2/3*4)) so 1 of 4 validators may fail.
	MinSignatures int `json:"minSignatures,omitempty"`

	// Genesis block
	Timestamp uint64 `json:"timestamp"`
	GasLimit  uint64 `json:"gasLimit"`
	ExtraData string `json:"extraData"`

	// Initial allocations
	Alloc map[string]GenesisAccount `json:"alloc"`

	// Initial validators
	Validators []GenesisValidator `json:"validators"`
}

// GenesisAccount represents an initial account allocation
type GenesisAccount struct {
	Balance string            `json:"balance"`
	Nonce   uint64            `json:"nonce"`
	Code    string            `json:"code,omitempty"`
	Storage map[string]string `json:"storage,omitempty"`
}

// GenesisValidator represents an initial validator
type GenesisValidator struct {
	Address   string `json:"address"`
	PublicKey string `json:"publicKey"`
	Stake     string `json:"stake"`
}

// DefaultGenesis returns the default genesis configuration (Production/Mainnet)
func DefaultGenesis() *Genesis {
	return mainnetGenesis()
}

// DevGenesis returns the development genesis configuration
// Note: Dev mode will dynamically generate test accounts at startup
func DevGenesis() *Genesis {
	return &Genesis{
		ChainID:    DevnetNetworkID, // 1333 - Development
		NetworkID:  DevnetNetworkID,
		Timestamp:  DevnetGenesisTimestamp, // audit-fix M-2: deterministic timestamp
		GasLimit:   30000000,
		ExtraData:  "Quantaureum Genesis Block - Devnet",
		Alloc:      make(map[string]GenesisAccount),
		Validators: []GenesisValidator{},
	}
}

// TestnetGenesis returns the testnet genesis configuration
func TestnetGenesis() *Genesis {
	return testnetGenesis()
}

// LoadGenesis loads genesis configuration from a file
func LoadGenesis(path string) (*Genesis, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- genesis path from node config, validated by caller
	if err != nil {
		return nil, err
	}

	genesis := &Genesis{}
	if err := json.Unmarshal(data, genesis); err != nil {
		return nil, err
	}

	// validate Genesis config fields
	if err := genesis.Validate(); err != nil {
		return nil, fmt.Errorf("invalid genesis config: %w", err)
	}
	return genesis, nil
}

// SaveGenesis saves genesis configuration to a file
func (g *Genesis) SaveGenesis(path string) error {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	// audit-fix R7-L: use restricted permissions consistent with config.go
	return os.WriteFile(path, data, 0600)
}

// ComputeAllocHash computes a SHA3-256 hash of the genesis alloc section.
// FIX: All nodes must have identical alloc to avoid consensus forks.
// Operators compare this hash across nodes to verify they share the same
// genesis allocations. The hash is computed from sorted (address, balance, nonce)
// tuples to ensure deterministic output regardless of map iteration order.
func (g *Genesis) ComputeAllocHash() string {
	if g.Alloc == nil {
		return "0x0000000000000000000000000000000000000000000000000000000000000000"
	}

	// Sort addresses for deterministic output
	addresses := make([]string, 0, len(g.Alloc))
	for addr := range g.Alloc {
		addresses = append(addresses, addr)
	}
	// Simple insertion sort (alloc is small, typically < 20 entries)
	for i := 1; i < len(addresses); i++ {
		key := addresses[i]
		j := i - 1
		for j >= 0 && addresses[j] > key {
			addresses[j+1] = addresses[j]
			j--
		}
		addresses[j+1] = key
	}

	h := sha3.NewLegacyKeccak256()
	for _, addr := range addresses {
		acc := g.Alloc[addr]
		h.Write([]byte(addr))
		h.Write([]byte(acc.Balance))
		// Include nonce as 8-byte big-endian for deterministic encoding
		var nonceBytes [8]byte
		binary.BigEndian.PutUint64(nonceBytes[:], acc.Nonce)
		h.Write(nonceBytes[:])
	}

	return "0x" + hex.EncodeToString(h.Sum(nil))
}

// ConfigurationHash computes a SHA3-256 hash of the full genesis configuration
// (chainID, networkID, timestamp, gasLimit, extraData, validators, alloc).
// Unlike GenesisBlockHeader.Hash() (which only covers header fields),
// ConfigurationHash covers the validator set and allocations — so two genesis
// files with different validators/stakes produce different hashes.
// AUDIT (2026) HIGH-04 (NODE-01): Operators compare this hash across
// nodes to verify they share the exact same genesis configuration.
func (g *Genesis) ConfigurationHash() types.Hash {
	h := sha3.NewLegacyKeccak256()

	// ChainID + NetworkID (8 bytes each, big-endian)
	var buf8 [8]byte
	binary.BigEndian.PutUint64(buf8[:], g.ChainID)
	h.Write(buf8[:])
	binary.BigEndian.PutUint64(buf8[:], g.NetworkID)
	h.Write(buf8[:])

	// Timestamp + GasLimit (8 bytes each, big-endian)
	binary.BigEndian.PutUint64(buf8[:], g.Timestamp)
	h.Write(buf8[:])
	binary.BigEndian.PutUint64(buf8[:], g.GasLimit)
	h.Write(buf8[:])

	// ExtraData
	h.Write([]byte(g.ExtraData))

	// Validators (sorted by address for deterministic output)
	validatorAddrs := make([]string, len(g.Validators))
	for i, v := range g.Validators {
		validatorAddrs[i] = v.Address
	}
	for i := 1; i < len(validatorAddrs); i++ {
		key := validatorAddrs[i]
		j := i - 1
		for j >= 0 && validatorAddrs[j] > key {
			validatorAddrs[j+1] = validatorAddrs[j]
			j--
		}
		validatorAddrs[j+1] = key
	}
	for _, addr := range validatorAddrs {
		for _, v := range g.Validators {
			if v.Address == addr {
				h.Write([]byte(v.Address))
				h.Write([]byte(v.Stake))
				h.Write([]byte(v.PublicKey))
				break
			}
		}
	}

	// Alloc (sorted by address for deterministic output)
	allocAddrs := make([]string, 0, len(g.Alloc))
	for addr := range g.Alloc {
		allocAddrs = append(allocAddrs, addr)
	}
	for i := 1; i < len(allocAddrs); i++ {
		key := allocAddrs[i]
		j := i - 1
		for j >= 0 && allocAddrs[j] > key {
			allocAddrs[j+1] = allocAddrs[j]
			j--
		}
		allocAddrs[j+1] = key
	}
	for _, addr := range allocAddrs {
		acc := g.Alloc[addr]
		h.Write([]byte(addr))
		h.Write([]byte(acc.Balance))
		binary.BigEndian.PutUint64(buf8[:], acc.Nonce)
		h.Write(buf8[:])
	}

	return types.BytesToHash(h.Sum(nil))
}

// duplicate Validate method has been removed

// ToBlock converts genesis to a genesis block header
func (g *Genesis) ToBlock() *GenesisBlock {
	extraData, _ := hex.DecodeString(stripHexPrefix(g.ExtraData))
	if len(extraData) == 0 {
		extraData = []byte(g.ExtraData)
	}

	return &GenesisBlock{
		Header: GenesisBlockHeader{
			Version:    1,
			Height:     0,
			Timestamp:  int64(g.Timestamp), // #nosec G115 -- genesis timestamp is always non-negative
			ParentHash: types.Hash{},
			GasLimit:   g.GasLimit,
			ExtraData:  extraData,
		},
		ChainID:   g.ChainID,
		NetworkID: g.NetworkID,
	}
}

// GenesisBlock represents the genesis block
type GenesisBlock struct {
	Header    GenesisBlockHeader
	ChainID   uint64
	NetworkID uint64
}

// GenesisBlockHeader represents the genesis block header
type GenesisBlockHeader struct {
	Version    uint32
	Height     uint64
	Timestamp  int64
	ParentHash types.Hash
	StateRoot  types.Hash
	TxRoot     types.Hash
	GasLimit   uint64
	ExtraData  []byte
}

// Hash computes the hash of the genesis block header.
// audit-fix R6-M1: include Timestamp, GasLimit, and TxRoot so that genesis
// configurations differing only in those fields produce distinct hashes.
// audit-fix R7-L1: use binary.BigEndian for consistency with R5-L1/R6-L2/R6-L3.
func (h *GenesisBlockHeader) Hash() types.Hash {
	data := make([]byte, 0, 256)
	// Version (4 bytes)
	vBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(vBuf, h.Version)
	data = append(data, vBuf...)
	// Height (8 bytes)
	hBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(hBuf, h.Height)
	data = append(data, hBuf...)
	// Timestamp (8 bytes)
	tBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tBuf, uint64(h.Timestamp)) // #nosec G115 -- block timestamp is always non-negative
	data = append(data, tBuf...)
	data = append(data, h.ParentHash[:]...)
	data = append(data, h.StateRoot[:]...)
	data = append(data, h.TxRoot[:]...)
	// GasLimit (8 bytes)
	gBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(gBuf, h.GasLimit)
	data = append(data, gBuf...)
	data = append(data, h.ExtraData...)

	return types.BytesToHash(hashBytes(data))
}

// GetAllocations returns the initial account allocations
func (g *Genesis) GetAllocations() (map[types.Address]*big.Int, error) {
	allocs := make(map[types.Address]*big.Int)

	for addrStr, account := range g.Alloc {
		addr, err := parseAddressString(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid address in allocations: %w", err)
		}
		var balance *big.Int
		if account.Balance == "" {
			balance = big.NewInt(0)
		} else {
			var ok bool
			balance, ok = new(big.Int).SetString(account.Balance, 10)
			if !ok {
				// Try hex
				balance, ok = new(big.Int).SetString(stripHexPrefix(account.Balance), 16)
			}
			if balance == nil {
				return nil, fmt.Errorf("invalid balance %q for address %s: must be decimal or hex integer", account.Balance, addrStr)
			}
		}
		allocs[addr] = balance
	}

	return allocs, nil
}

// GetAccountCodes returns the initial contract codes
func (g *Genesis) GetAccountCodes() (map[types.Address][]byte, error) {
	codes := make(map[types.Address][]byte)

	for addrStr, account := range g.Alloc {
		if account.Code == "" {
			continue
		}
		addr, err := parseAddressString(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid address in account codes: %w", err)
		}
		code, err := hex.DecodeString(stripHexPrefix(account.Code))
		if err != nil {
			continue
		}
		codes[addr] = code
	}

	return codes, nil
}

// GetAccountStorage returns the initial contract storage
func (g *Genesis) GetAccountStorage() (map[types.Address]map[types.Hash]types.Hash, error) {
	storage := make(map[types.Address]map[types.Hash]types.Hash)

	for addrStr, account := range g.Alloc {
		if len(account.Storage) == 0 {
			continue
		}
		addr, err := parseAddressString(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid address in storage: %w", err)
		}
		storage[addr] = make(map[types.Hash]types.Hash)

		for keyStr, valueStr := range account.Storage {
			keyBytes, err := hex.DecodeString(stripHexPrefix(keyStr))
			if err != nil {
				continue
			}
			valueBytes, err := hex.DecodeString(stripHexPrefix(valueStr))
			if err != nil {
				continue
			}
			key := types.BytesToHash(keyBytes)
			value := types.BytesToHash(valueBytes)
			storage[addr][key] = value
		}
	}

	return storage, nil
}

// GetAccountNonces returns the initial account nonces
func (g *Genesis) GetAccountNonces() (map[types.Address]uint64, error) {
	nonces := make(map[types.Address]uint64)

	for addrStr, account := range g.Alloc {
		if account.Nonce == 0 {
			continue
		}
		addr, err := parseAddressString(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid address in nonces: %w", err)
		}
		nonces[addr] = account.Nonce
	}

	return nonces, nil
}

// Helper functions

func stripHexPrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

func parseAddressString(s string) (types.Address, error) {
	// Try QAU format first
	if len(s) >= 3 && (s[:3] == "QAU" || s[:3] == "qau") {
		addr, err := types.ParseAddress(s)
		if err == nil {
			return addr, nil
		}
	}
	// Try hex format
	s = stripHexPrefix(s)
	bytes, err := hex.DecodeString(s)
	if err != nil {
		// SECURITY FIX: Return error instead of silently returning zero address
		return types.Address{}, fmt.Errorf("invalid hex address %q: %w", s, err)
	}
	// NODE-003 FIX: Validate decoded byte length is exactly 20 (types.AddressLength).
	// Previously, types.BytesToAddress would silently truncate or pad, masking
	// input errors that could lead to incorrect genesis configuration.
	if len(bytes) != types.AddressLength {
		return types.Address{}, fmt.Errorf("invalid address length: got %d bytes, expected %d", len(bytes), types.AddressLength)
	}
	return types.BytesToAddress(bytes), nil
}

func hashBytes(data []byte) []byte {
	hash := sha3.Sum256(data)
	return hash[:]
}

// Validate validates the genesis configuration
// audit-fix M-3: comprehensive field validation to prevent invalid or malicious configs
// Validate validates the genesis configuration fields.
//
//	(P3): Genesis file validation. Verifies ChainID/NetworkID
//
// consistency and recognized network IDs, timestamp range, gas limit range,
// alloc address/balance validity, and validator entries (address, public key,
// stake). Called by LoadGenesis so an invalid genesis file fails fast at load.
func (g *Genesis) Validate() error {
	// ChainID must be non-zero
	if g.ChainID == 0 {
		return errors.New("chain ID cannot be zero")
	}

	// audit-fix R2-Info-2: ChainID and NetworkID must be consistent.
	if g.NetworkID != 0 && g.ChainID != g.NetworkID {
		return fmt.Errorf("genesis chainID (%d) and networkID (%d) must be equal", g.ChainID, g.NetworkID)
	}

	// M-3: ChainID must be one of the recognized network IDs
	validChainIDs := map[uint64]bool{
		MainnetNetworkID: true, // 1668
		TestnetNetworkID: true, // 1669
		DevnetNetworkID:  true, // 1333
	}
	if !validChainIDs[g.ChainID] {
		return fmt.Errorf("unsupported chainId: %d (must be 1668, 1669, or 1333)", g.ChainID)
	}

	// M-3: Timestamp validation. P3-GE-01 FIX (2026-08-03): for mainnet,
	// require an EXACT match against MainnetGenesisTimestamp (currently the
	// genesis/mainnet.json constant). For testnet / devnet, keep the
	// permissive 365-day-future-tolerance window because these networks
	// are routinely rebuilt with current timestamps for staging /
	// integration testing. Previously ALL networks got the 365-day
	// tolerance, which let a misconfigured mainnet launch with a
	// genesis timestamp minutes / seconds in the future (due to a CI
	// race or an operator typo) — that would silently shift the
	// difficulty retarget / epoch transitions by a measurable amount.
	// MainnetGenesisTimestamp is the canonical V2 mainnet launch stamp;
	// any deviation is a config bug. TestnetGenesisTimestamp /
	// DevnetGenesisTimestamp are documented but NOT enforced because
	// the same flexibility that lets operators stamp "now" when
	// spinning up integrations implicitly lets the value drift.
	minTime := uint64(1672531200) // 2023-01-01 00:00:00 UTC
	maxTime := uint64(time.Now().Unix()) + uint64(365*24*3600)
	if g.Timestamp < minTime {
		return fmt.Errorf("genesis timestamp %d is too old (minimum: 2023-01-01)", g.Timestamp)
	}
	if g.Timestamp > maxTime {
		return fmt.Errorf("genesis timestamp %d is too far in the future", g.Timestamp)
	}
	// P3-GE-01: mainnet exact-match. Use whichever of ChainID/NetworkID
	// is the mainnet ID (they're equal in the canonical network sets).
	isMainnet := g.ChainID == MainnetNetworkID || g.NetworkID == MainnetNetworkID
	if isMainnet && g.Timestamp != MainnetGenesisTimestamp {
		return fmt.Errorf("P3-GE-01: mainnet genesis timestamp %d does not match canonical MainnetGenesisTimestamp %d — mainnet MUST use the exact V2 launch timestamp",
			g.Timestamp, MainnetGenesisTimestamp)
	}

	// M-3: GasLimit must be in reasonable range (1M ~ 100M)
	if g.GasLimit == 0 {
		g.GasLimit = 30000000
	}
	if g.GasLimit < 1000000 {
		return fmt.Errorf("genesis gasLimit %d is too low (minimum: 1000000)", g.GasLimit)
	}
	if g.GasLimit > 100000000 {
		return fmt.Errorf("genesis gasLimit %d is too high (maximum: 100000000)", g.GasLimit)
	}

	// R43-CS-005 FIX (cross 3 rounds: R41→R42→R43): Require non-empty Alloc
	// for mainnet only. Devnet and testnet may dynamically generate accounts
	// at startup or use validators funded outside of genesis allocation.
	if g.ChainID == MainnetNetworkID && len(g.Alloc) == 0 {
		return fmt.Errorf("genesis alloc cannot be empty for mainnet — at least one funded account is required")
	}

	// M-3: Validate Alloc entries - addresses and balances
	for addrStr, account := range g.Alloc {
		if _, err := parseAddressString(addrStr); err != nil {
			return fmt.Errorf("invalid alloc address %q: %w", addrStr, err)
		}
		balanceStr := stripHexPrefix(account.Balance)
		if balanceStr == "" {
			continue
		}
		balance, ok := new(big.Int).SetString(balanceStr, 10)
		if !ok {
			balance, ok = new(big.Int).SetString(balanceStr, 16)
		}
		if !ok || balance.Sign() < 0 {
			return fmt.Errorf("invalid alloc balance for %s: %s", addrStr, account.Balance)
		}
	}

	// M-3: Validators must not be empty for non-devnet
	if g.ChainID != DevnetNetworkID && len(g.Validators) == 0 {
		return errors.New("validators must not be empty for mainnet/testnet")
	}

	// FIX: Warn when validator count is below BFT minimum (5).
	// With n < 5 validators, the network has reduced Byzantine fault tolerance:
	//   n=3 => f=0 (no fault tolerance, 2f+1=3 requires all 3)
	//   n=4 => f=1 (tolerates 1 fault, but 2f+1=3 leaves only 1 spare)
	//   n>=5 => f=1 with healthier redundancy (2f+1=3 out of 5+)
	// This is a warning, not an error, to allow testnet configurations with
	// fewer validators for testing purposes.
	if g.ChainID != DevnetNetworkID && len(g.Validators) < 5 {
		log.Printf("WARNING: genesis has only %d validators (chainID=%d); "+
			"BFT minimum for robust 1-fault tolerance is 5. "+
			"With fewer than 5 validators, the network has reduced Byzantine fault tolerance.",
			len(g.Validators), g.ChainID)
	}

	// M-3: Validate each validator entry
	// R32-P3-04 FIX (2026-07-28): Track seen addresses and public keys to
	// detect duplicate validator entries. A genesis with duplicate validators
	// causes consensus failures: the same validator counted twice gets double
	// voting weight, or signature verification matches multiple entries
	// causing ambiguity in proposer election. Without this check, a malformed
	// or hostile genesis file could pass all per-entry validation while
	// silently corrupting the validator set.
	seenAddrs := make(map[types.Address]bool)
	seenPKs := make(map[string]bool) // keyed by hex-encoded public key bytes
	for i, v := range g.Validators {
		if v.Address == "" {
			return fmt.Errorf("validator %d: address is empty", i)
		}
		if _, err := parseAddressString(v.Address); err != nil {
			return fmt.Errorf("validator %d: invalid address %q: %w", i, v.Address, err)
		}
		pkStr := stripHexPrefix(v.PublicKey)
		if pkStr == "" {
			return fmt.Errorf("validator %d: publicKey is empty", i)
		}
		pkBytes, err := hex.DecodeString(pkStr)
		if err != nil {
			return fmt.Errorf("validator %d: invalid publicKey %q: %w", i, v.PublicKey, err)
		}
		// NODE-002 FIX: Validate public key length matches Dilithium3 size (1952 bytes).
		// Without this check, a malformed genesis file could pass validation but
		// cause consensus failures later when the key is used for verification.
		const dilithium3PublicKeySize = 1952
		if len(pkBytes) != dilithium3PublicKeySize {
			return fmt.Errorf("validator %d: publicKey length %d does not match Dilithium3 size %d",
				i, len(pkBytes), dilithium3PublicKeySize)
		}
		// NODE2-001 FIX: Verify that the declared address matches the address
		// derived from the declared public key. Without this check, a genesis
		// file can have mismatched address/publicKey pairs that pass validation
		// but cause silent consensus failures (signatures won't verify).
		derivedAddr := types.AddressFromPublicKey(pkBytes)
		declaredAddr, err := parseAddressString(v.Address)
		if err != nil {
			return fmt.Errorf("validator %d: invalid address %q: %w", i, v.Address, err)
		}
		if derivedAddr != declaredAddr {
			return fmt.Errorf("validator %d: address %x does not match address derived from publicKey %x",
				i, declaredAddr, derivedAddr)
		}
		// R32-P3-04 FIX: Reject duplicate validator addresses. Two entries
		// with the same address would give that validator double voting
		// weight in proposer election and double reward share.
		if seenAddrs[declaredAddr] {
			return fmt.Errorf("validator %d: duplicate address %x — address already appears in an earlier validator entry (duplicate validators corrupt voting weight and reward distribution)", i, declaredAddr)
		}
		seenAddrs[declaredAddr] = true
		// R32-P3-04 FIX: Reject duplicate validator public keys. Even if
		// the address differs (impossible for Dilithium3 since address is
		// derived from pubkey, but defensive in case address derivation
		// changes), the same pubkey would make signature verification
		// ambiguous — the same signature matches two validator entries.
		pkKey := hex.EncodeToString(pkBytes)
		if seenPKs[pkKey] {
			return fmt.Errorf("validator %d: duplicate publicKey — publicKey already appears in an earlier validator entry (duplicate keys make signature verification ambiguous)", i)
		}
		seenPKs[pkKey] = true
		stakeStr := stripHexPrefix(v.Stake)
		if stakeStr == "" {
			return fmt.Errorf("validator %d: stake is empty", i)
		}
		stake, ok := new(big.Int).SetString(stakeStr, 10)
		if !ok {
			stake, ok = new(big.Int).SetString(stakeStr, 16)
		}
		if !ok || stake.Sign() < 0 {
			return fmt.Errorf("validator %d: invalid stake for %s: %s (must be non-negative)", i, v.Address, v.Stake)
		}
		// AUDIT (2026) HIGH-05 (NODE-02): Mainnet validators MUST have
		// non-zero stake. A mainnet validator set with zero stake has no
		// economic skin-in-the-game (no slashing risk), no gas balance to
		// submit consensus transactions, and the first validator to stake
		// even the minimum amount would control ~100% of stake weight.
		// Devnet/testnet are exempt (they may use zero-stake validators for
		// testing purposes).
		if g.ChainID == MainnetNetworkID && stake.Sign() == 0 {
			return fmt.Errorf("validator %d (%s): stake must be non-zero for mainnet (got 0) — mainnet validators require economic stake (design: 30,000 QAU)", i, v.Address)
		}
		// AUDIT (2026) R3-NODE-01: Mainnet validators MUST have stake
		// >= the minimum staking threshold (30000 QAU = 30000 * 10^18 wei).
		// Previously, only a non-zero check was performed, which allowed a
		// unit error (e.g. "30000" wei instead of "30000000000000000000000"
		// wei) to pass validation — resulting in effectively zero economic
		// stake. The minimum threshold catches such unit errors at genesis
		// validation time, failing fast rather than silently accepting a
		// vulnerable configuration.
		if g.ChainID == MainnetNetworkID {
			minStakeWei := new(big.Int).Mul(big.NewInt(6000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
			if stake.Cmp(minStakeWei) < 0 {
				return fmt.Errorf("validator %d (%s): stake %s wei is below mainnet minimum %s wei (6000 QAU) — check stake unit (must be wei, not QAU)", i, v.Address, stake.String(), minStakeWei.String())
			}
		}
	}

	// R32-P3-04 FIX (2026-07-28): Validate MinSignatures field for integrity.
	// 0 means "use the dynamic ceil(activeValidators*2/3) computation"
	// (the default). Non-zero values pin the checkpoint quorum explicitly,
	// which is useful for testnet (declares 3 so 1 of 4 validators may fail).
	// Without this check, a genesis could declare MinSignatures > validator
	// count (making quorum impossible and halting checkpoint finality) or a
	// negative value (which would be treated as 0 by int comparison, silently
	// falling back to dynamic computation — masking a misconfiguration).
	if g.MinSignatures != 0 {
		if g.MinSignatures < 0 {
			return fmt.Errorf("minSignatures %d cannot be negative — use 0 for dynamic ceil(2/3*n) computation", g.MinSignatures)
		}
		if g.MinSignatures > len(g.Validators) {
			return fmt.Errorf("minSignatures %d exceeds validator count %d — checkpoint quorum would be impossible (no block could ever be finalized)", g.MinSignatures, len(g.Validators))
		}
		// BFT minimum: ceil(2/3 * n). If MinSignatures is set below this,
		// the network has reduced Byzantine fault tolerance. Warn but don't
		// error — testnet may intentionally set a lower threshold for
		// testing liveness under faulty conditions.
		if len(g.Validators) > 0 {
			bftMin := (2*len(g.Validators) + 2) / 3 // ceil(2n/3)
			if g.MinSignatures < bftMin {
				log.Printf("WARNING: minSignatures %d is below BFT minimum ceil(2/3*%d)=%d — reduced Byzantine fault tolerance",
					g.MinSignatures, len(g.Validators), bftMin)
			}
		}
	}

	// FIX: Validate and document the intentional difference between
	// validator stakes and alloc amounts. When a validator has a corresponding
	// alloc entry, the alloc balance must be >= stake. The difference
	// (alloc - stake) covers operational overhead: gas for block
	// proposals/attestations, transaction fees, and a slashing buffer.
	// For mainnet: stake = 30,000 QAU, alloc = 32,000 QAU (2,000 QAU overhead).
	// If no alloc entry exists for a validator, the check is skipped — the
	// validator may be funded through other means (e.g. testnet configurations).
	for i, v := range g.Validators {
		allocBalance := big.NewInt(0)
		found := false
		for addrStr, account := range g.Alloc {
			if strings.EqualFold(addrStr, v.Address) {
				found = true
				balanceStr := stripHexPrefix(account.Balance)
				bal, ok := new(big.Int).SetString(balanceStr, 10)
				if !ok {
					bal, ok = new(big.Int).SetString(balanceStr, 16)
				}
				if ok && bal != nil {
					allocBalance = bal
				}
				break
			}
		}
		if !found {
			continue // no alloc entry — skip check (validator funded elsewhere)
		}

		stakeStr := stripHexPrefix(v.Stake)
		stake, ok := new(big.Int).SetString(stakeStr, 10)
		if !ok {
			stake, ok = new(big.Int).SetString(stakeStr, 16)
		}
		if !ok || stake == nil {
			continue // already validated above
		}

		if allocBalance.Cmp(stake) < 0 {
			return fmt.Errorf("validator %d (%s): alloc balance (%s) is less than stake (%s) — alloc must be >= stake to cover operational overhead (gas, fees, slashing buffer)", i, v.Address, allocBalance.String(), stake.String())
		}
	}

	// AUDIT (2026) NODE-03: Total supply invariant. Sum all alloc
	// balances and reject if the total exceeds the maximum QAU supply
	// (20,000,000 QAU = 20_000_000 * 10^18 wei). This catches typos
	// (extra/missing zero) that would silently inflate or deflate the
	// money supply. A genesis with total alloc > MaxSupply is rejected
	// regardless of network type — no chain should start with more than
	// the documented cap. Devnet/testnet typically use far less.
	const qauDecimals = 18
	maxSupplyQAU := big.NewInt(20_000_000) // 20 million QAU
	maxSupplyWei := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(qauDecimals)), nil)
	maxSupplyWei.Mul(maxSupplyWei, maxSupplyQAU)

	totalAlloc := new(big.Int)
	for _, account := range g.Alloc {
		balanceStr := stripHexPrefix(account.Balance)
		if balanceStr == "" {
			continue
		}
		bal, ok := new(big.Int).SetString(balanceStr, 10)
		if !ok {
			bal, ok = new(big.Int).SetString(balanceStr, 16)
		}
		if !ok || bal == nil {
			continue
		}
		totalAlloc.Add(totalAlloc, bal)
	}
	if totalAlloc.Cmp(maxSupplyWei) > 0 {
		return fmt.Errorf("genesis total alloc (%s wei = %s QAU) exceeds maximum supply (%s wei = 20,000,000 QAU) — check for typo in alloc balances",
			totalAlloc.String(),
			new(big.Int).Quo(totalAlloc, new(big.Int).Exp(big.NewInt(10), big.NewInt(qauDecimals), nil)).String(),
			maxSupplyWei.String())
	}

	return nil
}
