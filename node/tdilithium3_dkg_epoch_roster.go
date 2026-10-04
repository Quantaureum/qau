// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/quantaureum/qau/consensus"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
)

// Finalized-epoch validator roster snapshot (Dilithium3 v1 CNF-RSS design,
// "Finalized-Epoch Validator Snapshot", option 2 — the no-fork path).
//
// Round 0 of the DKG commits one identity roster: the ordered validator
// addresses and Dilithium3 identity keys of the committee. That commitment is
// only useful if every participating node derives the identical roster for the
// session epoch and can derive it again after a restart. The node's live
// ValidatorSet cannot supply this — it is mutable in-memory state whose
// membership changes carry no epoch tag.
//
// This file captures the roster while processing blocks: once per epoch the
// node records the active validator set (address + Dilithium3 identity key,
// canonically ordered) together with the epoch's anchor block hash — the
// boundary block itself, or, when the boundary slot was missed, the parent of
// the epoch's first canonical block (the R101 rule) — and a digest over
// (chain id, genesis hash, epoch, anchor hash, entries). The record is
// persisted to a bounded sidecar so a restarted node serves the same value.
//
// This is not evidence. It gives no arbitration: a node that captured a wrong
// roster cannot prove it wrong to a peer without replaying. It only guarantees
// that disagreement fails closed at Round 0 instead of silently continuing.
//
// The snapshot is deterministic only while every validator-set mutation is
// block-derived. Any time-driven, RPC-driven, or local-policy mutation breaks
// that without any visible error, so the invariant is enforced where it can be
// (see errConsensusStakeMutationNotBlockDerived in adapters.go).

const (
	tdilithium3DKGEpochRosterFileVersion = 1
	tdilithium3DKGEpochRosterFileName    = "tdilithium3_epoch_roster.json"

	// tdilithium3DKGEpochRosterEpochBudget bounds the sidecar by epoch count.
	tdilithium3DKGEpochRosterEpochBudget = 64
	// tdilithium3DKGEpochRosterEntryBudget bounds the sidecar by total roster
	// entries across all kept epochs, so a chain with a very large validator
	// set cannot make the file unbounded either.
	tdilithium3DKGEpochRosterEntryBudget = 4096

	tdilithium3DKGEpochRosterDomain = "QAU-TDILITHIUM3-V1-FINALIZED-EPOCH-ROSTER"
)

// errTDilithium3DKGEpochRosterUnavailable is the named fail-closed error for
// every missing, unfinalized, mismatched, or out-of-window roster request. It
// never degrades to the live validator set.
var errTDilithium3DKGEpochRosterUnavailable = errors.New("Dilithium3 DKG finalized-epoch validator roster unavailable")

// tdilithium3DKGEpochRosterEntry is one committee/validator identity: the
// validator address and its legacy Dilithium3 identity public key.
type tdilithium3DKGEpochRosterEntry struct {
	Address   types.Address
	PublicKey []byte
}

// tdilithium3DKGEpochRoster is the captured roster of one epoch.
type tdilithium3DKGEpochRoster struct {
	Epoch        uint64
	BoundaryHash types.Hash
	Entries      []tdilithium3DKGEpochRosterEntry
	Digest       [32]byte
}

type tdilithium3DKGEpochRosterEntryJSON struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}

type tdilithium3DKGEpochRosterRecordJSON struct {
	Epoch        uint64                               `json:"epoch"`
	BoundaryHash string                               `json:"boundary_hash"`
	Digest       string                               `json:"digest"`
	Entries      []tdilithium3DKGEpochRosterEntryJSON `json:"entries"`
}

type tdilithium3DKGEpochRosterFileJSON struct {
	Version            int                                   `json:"version"`
	ChainID            uint64                                `json:"chain_id"`
	GenesisHash        string                                `json:"genesis_hash"`
	BootstrapEpoch     uint64                                `json:"bootstrap_epoch"`
	BootstrapEpochSet  bool                                  `json:"bootstrap_epoch_set"`
	LastFinalizedEpoch uint64                                `json:"last_finalized_epoch"`
	Epochs             []tdilithium3DKGEpochRosterRecordJSON `json:"epochs"`
}

// tdilithium3DKGEpochRosterStore is the bounded, atomically persisted sidecar
// behind the snapshot. It is chain-bound: a file whose chain id or genesis hash
// differs from the running chain is refused rather than reused.
type tdilithium3DKGEpochRosterStore struct {
	mu           sync.Mutex
	path         string
	chainID      uint64
	genesis      types.Hash
	loaded       bool
	bootstrap    uint64
	bootstrapSet bool
	finalized    uint64
	epochs       map[uint64]*tdilithium3DKGEpochRoster
}

func newTDilithium3DKGEpochRosterStore(path string, chainID uint64, genesis types.Hash) *tdilithium3DKGEpochRosterStore {
	return &tdilithium3DKGEpochRosterStore{
		path: path, chainID: chainID, genesis: genesis,
		epochs: make(map[uint64]*tdilithium3DKGEpochRoster),
	}
}

// tdilithium3DKGEpochRosterDigest is the canonical digest of one captured
// roster. The chain id and genesis hash are committed so the same epoch and
// boundary hash on another chain cannot produce the same digest.
func tdilithium3DKGEpochRosterDigest(chainID uint64, genesis types.Hash, epoch uint64, boundary types.Hash, entries []tdilithium3DKGEpochRosterEntry) [32]byte {
	hash := sha3.New256()
	hash.Write([]byte(tdilithium3DKGEpochRosterDomain))
	var field [8]byte
	binary.BigEndian.PutUint64(field[:], chainID)
	hash.Write(field[:])
	hash.Write(genesis[:])
	binary.BigEndian.PutUint64(field[:], epoch)
	hash.Write(field[:])
	hash.Write(boundary[:])
	binary.BigEndian.PutUint64(field[:], uint64(len(entries)))
	hash.Write(field[:])
	for _, entry := range entries {
		hash.Write(entry.Address[:])
		binary.BigEndian.PutUint64(field[:], uint64(len(entry.PublicKey)))
		hash.Write(field[:])
		hash.Write(entry.PublicKey)
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

// tdilithium3DKGActiveRosterEntries projects a live validator set into the
// canonical ordered roster. It is fail-closed: an inactive validator, a missing
// or unparsable identity key, or a duplicate address yields an error instead of
// a partial roster.
func tdilithium3DKGActiveRosterEntries(validators []*consensus.Validator) ([]tdilithium3DKGEpochRosterEntry, error) {
	entries := make([]tdilithium3DKGEpochRosterEntry, 0, len(validators))
	seen := make(map[types.Address]bool, len(validators))
	for _, validator := range validators {
		if validator == nil || !validator.Active {
			continue
		}
		if validator.Address == (types.Address{}) {
			return nil, fmt.Errorf("active validator has an empty address")
		}
		if seen[validator.Address] {
			return nil, fmt.Errorf("active validator %s appears twice", validator.Address.String())
		}
		if len(validator.PublicKeyBytes) != qcrypto.Dilithium3PublicKeySize {
			return nil, fmt.Errorf("active validator %s has no usable Dilithium3 identity key", validator.Address.String())
		}
		if _, err := qcrypto.PublicKeyFromBytes(validator.PublicKeyBytes); err != nil {
			return nil, fmt.Errorf("active validator %s has an invalid Dilithium3 identity key: %w", validator.Address.String(), err)
		}
		seen[validator.Address] = true
		entries = append(entries, tdilithium3DKGEpochRosterEntry{
			Address:   validator.Address,
			PublicKey: append([]byte(nil), validator.PublicKeyBytes...),
		})
	}
	// Canonical order is ascending address order, independent of the validator
	// set's insertion order, so two nodes that processed the same blocks digest
	// the same bytes.
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].Address[:], entries[j].Address[:]) < 0
	})
	return entries, nil
}

// loadLocked reads and verifies the sidecar. A missing file is an empty store.
// A file for another chain, an unsupported version, or a record whose digest
// does not match its own contents is refused, never repaired.
func (s *tdilithium3DKGEpochRosterStore) loadLocked() error {
	if s.loaded {
		return nil
	}
	blob, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.loaded = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: read %s: %v", errTDilithium3DKGEpochRosterUnavailable, s.path, err)
	}
	var file tdilithium3DKGEpochRosterFileJSON
	if err := json.Unmarshal(blob, &file); err != nil {
		return fmt.Errorf("%w: parse %s: %v", errTDilithium3DKGEpochRosterUnavailable, s.path, err)
	}
	if file.Version != tdilithium3DKGEpochRosterFileVersion {
		return fmt.Errorf("%w: unsupported sidecar version %d", errTDilithium3DKGEpochRosterUnavailable, file.Version)
	}
	if file.ChainID != s.chainID {
		return fmt.Errorf("%w: sidecar chain id %d does not match %d", errTDilithium3DKGEpochRosterUnavailable, file.ChainID, s.chainID)
	}
	genesis, err := parseTDilithium3DKGRosterHash(file.GenesisHash)
	if err != nil || genesis != s.genesis {
		return fmt.Errorf("%w: sidecar genesis hash does not match the running chain", errTDilithium3DKGEpochRosterUnavailable)
	}
	s.bootstrap, s.bootstrapSet, s.finalized = file.BootstrapEpoch, file.BootstrapEpochSet, file.LastFinalizedEpoch
	for _, record := range file.Epochs {
		roster, err := s.recordFromJSON(record)
		if err != nil {
			return err
		}
		if prior, exists := s.epochs[roster.Epoch]; exists && prior.BoundaryHash != roster.BoundaryHash {
			return fmt.Errorf("%w: sidecar contains two boundary blocks for epoch %d", errTDilithium3DKGEpochRosterUnavailable, roster.Epoch)
		}
		s.epochs[roster.Epoch] = roster
	}
	s.loaded = true
	return nil
}

func (s *tdilithium3DKGEpochRosterStore) recordFromJSON(record tdilithium3DKGEpochRosterRecordJSON) (*tdilithium3DKGEpochRoster, error) {
	boundary, err := parseTDilithium3DKGRosterHash(record.BoundaryHash)
	if err != nil {
		return nil, fmt.Errorf("%w: epoch %d boundary hash: %v", errTDilithium3DKGEpochRosterUnavailable, record.Epoch, err)
	}
	entries := make([]tdilithium3DKGEpochRosterEntry, 0, len(record.Entries))
	for _, raw := range record.Entries {
		addressBytes, err := hex.DecodeString(raw.Address)
		if err != nil || len(addressBytes) != len(types.Address{}) {
			return nil, fmt.Errorf("%w: epoch %d has a malformed roster address", errTDilithium3DKGEpochRosterUnavailable, record.Epoch)
		}
		publicKey, err := hex.DecodeString(raw.PublicKey)
		if err != nil || len(publicKey) != qcrypto.Dilithium3PublicKeySize {
			return nil, fmt.Errorf("%w: epoch %d has a malformed roster identity key", errTDilithium3DKGEpochRosterUnavailable, record.Epoch)
		}
		if _, err := qcrypto.PublicKeyFromBytes(publicKey); err != nil {
			return nil, fmt.Errorf("%w: epoch %d has an invalid roster identity key: %v", errTDilithium3DKGEpochRosterUnavailable, record.Epoch, err)
		}
		var address types.Address
		copy(address[:], addressBytes)
		entries = append(entries, tdilithium3DKGEpochRosterEntry{Address: address, PublicKey: publicKey})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: epoch %d has an empty roster", errTDilithium3DKGEpochRosterUnavailable, record.Epoch)
	}
	digest := tdilithium3DKGEpochRosterDigest(s.chainID, s.genesis, record.Epoch, boundary, entries)
	claimed, err := parseTDilithium3DKGRosterHash(record.Digest)
	if err != nil || claimed != digest {
		return nil, fmt.Errorf("%w: epoch %d sidecar digest does not match its contents", errTDilithium3DKGEpochRosterUnavailable, record.Epoch)
	}
	return &tdilithium3DKGEpochRoster{Epoch: record.Epoch, BoundaryHash: boundary, Entries: entries, Digest: digest}, nil
}

// capture records the roster of one epoch boundary and persists the sidecar.
// Re-delivering the same boundary is a no-op. A different boundary block for an
// already-finalized epoch is refused (a finalized epoch cannot change).
func (s *tdilithium3DKGEpochRosterStore) capture(epoch uint64, boundary types.Hash, entries []tdilithium3DKGEpochRosterEntry, finalized uint64) error {
	if len(entries) == 0 {
		return fmt.Errorf("%w: refusing to capture an empty roster for epoch %d", errTDilithium3DKGEpochRosterUnavailable, epoch)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return err
	}
	digest := tdilithium3DKGEpochRosterDigest(s.chainID, s.genesis, epoch, boundary, entries)
	if prior, exists := s.epochs[epoch]; exists {
		if prior.BoundaryHash == boundary {
			if finalized > s.finalized {
				s.finalized = finalized
				return s.persistLocked()
			}
			return nil
		}
		if epoch <= finalized {
			return fmt.Errorf("%w: epoch %d is finalized with boundary %s but was re-captured with %s",
				errTDilithium3DKGEpochRosterUnavailable, epoch, prior.BoundaryHash.String(), boundary.String())
		}
		// Not finalized yet: a reorg can legitimately replace the boundary
		// block, so the newer canonical boundary wins.
	}
	if !s.bootstrapSet {
		// The first captured boundary is the bootstrap boundary. Epochs
		// strictly below it may have been observed only during a bootstrap
		// sync whose early epochs were partially processed, so they are not
		// servable. The boundary itself was observed while applying the node's
		// own blocks, so it is servable (session-derivation spec, bootstrap
		// rule revision, R74).
		s.bootstrap, s.bootstrapSet = epoch, true
	}
	s.epochs[epoch] = &tdilithium3DKGEpochRoster{
		Epoch: epoch, BoundaryHash: boundary,
		Entries: append([]tdilithium3DKGEpochRosterEntry(nil), entries...), Digest: digest,
	}
	if finalized > s.finalized {
		s.finalized = finalized
	}
	s.pruneLocked()
	return s.persistLocked()
}

// effectiveFinalizedLocked returns the highest finalized epoch this node can
// vouch for: the live value when available, otherwise the persisted floor.
func (s *tdilithium3DKGEpochRosterStore) effectiveFinalizedLocked(live uint64) uint64 {
	if live > s.finalized {
		return live
	}
	return s.finalized
}

// pruneLocked enforces both sidecar budgets, dropping the oldest epochs first.
// The bootstrap boundary is a lower bound, so pruning never widens the servable
// window.
func (s *tdilithium3DKGEpochRosterStore) pruneLocked() {
	for len(s.epochs) > tdilithium3DKGEpochRosterEpochBudget || s.entryCountLocked() > tdilithium3DKGEpochRosterEntryBudget {
		oldest, found := uint64(0), false
		for epoch := range s.epochs {
			if !found || epoch < oldest {
				oldest, found = epoch, true
			}
		}
		if !found {
			return
		}
		delete(s.epochs, oldest)
	}
}

func (s *tdilithium3DKGEpochRosterStore) entryCountLocked() int {
	total := 0
	for _, roster := range s.epochs {
		total += len(roster.Entries)
	}
	return total
}

// lookup returns the captured roster of epoch, or the named fail-closed error.
func (s *tdilithium3DKGEpochRosterStore) lookup(epoch uint64, liveFinalized uint64) (*tdilithium3DKGEpochRoster, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return nil, err
	}
	if !s.bootstrapSet || epoch < s.bootstrap {
		return nil, fmt.Errorf("%w: epoch %d is below the bootstrap boundary %d", errTDilithium3DKGEpochRosterUnavailable, epoch, s.bootstrap)
	}
	if epoch > s.effectiveFinalizedLocked(liveFinalized) {
		return nil, fmt.Errorf("%w: epoch %d is not finalized", errTDilithium3DKGEpochRosterUnavailable, epoch)
	}
	roster, exists := s.epochs[epoch]
	if !exists {
		return nil, fmt.Errorf("%w: no snapshot captured for epoch %d", errTDilithium3DKGEpochRosterUnavailable, epoch)
	}
	return &tdilithium3DKGEpochRoster{
		Epoch: roster.Epoch, BoundaryHash: roster.BoundaryHash,
		Entries: append([]tdilithium3DKGEpochRosterEntry(nil), roster.Entries...), Digest: roster.Digest,
	}, nil
}

// lookupCaptured returns the captured roster of epoch without applying the
// finality gate. It exists for the DKG session derivation, which anchors on the
// boundary that was observed while applying blocks (ActivationEpoch-1) rather
// than on finality: that boundary is already an ancestor of the head when the
// activation epoch starts, while its own finality is almost never reached that
// early. The bootstrap refusal is kept, because a node that joined after the
// boundary never observed it and must not guess.
func (s *tdilithium3DKGEpochRosterStore) lookupCaptured(epoch uint64) (*tdilithium3DKGEpochRoster, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return nil, err
	}
	if !s.bootstrapSet || epoch < s.bootstrap {
		return nil, fmt.Errorf("%w: epoch %d is below the bootstrap boundary %d", errTDilithium3DKGEpochRosterUnavailable, epoch, s.bootstrap)
	}
	roster, exists := s.epochs[epoch]
	if !exists {
		return nil, fmt.Errorf("%w: no snapshot captured for epoch %d", errTDilithium3DKGEpochRosterUnavailable, epoch)
	}
	return &tdilithium3DKGEpochRoster{
		Epoch: roster.Epoch, BoundaryHash: roster.BoundaryHash,
		Entries: append([]tdilithium3DKGEpochRosterEntry(nil), roster.Entries...), Digest: roster.Digest,
	}, nil
}

func (s *tdilithium3DKGEpochRosterStore) persistLocked() error {
	file := tdilithium3DKGEpochRosterFileJSON{
		Version:            tdilithium3DKGEpochRosterFileVersion,
		ChainID:            s.chainID,
		GenesisHash:        hex.EncodeToString(s.genesis[:]),
		BootstrapEpoch:     s.bootstrap,
		BootstrapEpochSet:  s.bootstrapSet,
		LastFinalizedEpoch: s.finalized,
		Epochs:             make([]tdilithium3DKGEpochRosterRecordJSON, 0, len(s.epochs)),
	}
	epochs := make([]uint64, 0, len(s.epochs))
	for epoch := range s.epochs {
		epochs = append(epochs, epoch)
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
	for _, epoch := range epochs {
		roster := s.epochs[epoch]
		record := tdilithium3DKGEpochRosterRecordJSON{
			Epoch:        roster.Epoch,
			BoundaryHash: hex.EncodeToString(roster.BoundaryHash[:]),
			Digest:       hex.EncodeToString(roster.Digest[:]),
			Entries:      make([]tdilithium3DKGEpochRosterEntryJSON, 0, len(roster.Entries)),
		}
		for _, entry := range roster.Entries {
			record.Entries = append(record.Entries, tdilithium3DKGEpochRosterEntryJSON{
				Address:   hex.EncodeToString(entry.Address[:]),
				PublicKey: hex.EncodeToString(entry.PublicKey),
			})
		}
		file.Epochs = append(file.Epochs, record)
	}
	blob, err := json.Marshal(&file)
	if err != nil {
		return fmt.Errorf("%w: encode sidecar: %v", errTDilithium3DKGEpochRosterUnavailable, err)
	}
	if directory := filepath.Dir(s.path); directory != "" {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return fmt.Errorf("%w: create sidecar directory: %v", errTDilithium3DKGEpochRosterUnavailable, err)
		}
	}
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".epoch-roster-*")
	if err != nil {
		return fmt.Errorf("%w: create sidecar temp file: %v", errTDilithium3DKGEpochRosterUnavailable, err)
	}
	tempName := temp.Name()
	if _, err := temp.Write(blob); err != nil {
		temp.Close()
		os.Remove(tempName)
		return fmt.Errorf("%w: write sidecar: %v", errTDilithium3DKGEpochRosterUnavailable, err)
	}
	if err := temp.Close(); err != nil {
		os.Remove(tempName)
		return fmt.Errorf("%w: close sidecar: %v", errTDilithium3DKGEpochRosterUnavailable, err)
	}
	if err := os.Chmod(tempName, 0o600); err != nil {
		os.Remove(tempName)
		return fmt.Errorf("%w: chmod sidecar: %v", errTDilithium3DKGEpochRosterUnavailable, err)
	}
	if err := os.Rename(tempName, s.path); err != nil {
		os.Remove(tempName)
		return fmt.Errorf("%w: rename sidecar: %v", errTDilithium3DKGEpochRosterUnavailable, err)
	}
	return nil
}

func parseTDilithium3DKGRosterHash(value string) (types.Hash, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != len(types.Hash{}) {
		return types.Hash{}, fmt.Errorf("malformed 32-byte hash")
	}
	var hash types.Hash
	copy(hash[:], raw)
	return hash, nil
}

// tdilithium3DKGEpochRosterStoreForUse lazily creates and owns the node's
// sidecar. It stays nil (and every lookup fails closed) unless the experimental
// Dilithium3 v1 gates are open, so a production node never touches the file.
func (n *Node) tdilithium3DKGEpochRosterStoreForUse() *tdilithium3DKGEpochRosterStore {
	if n == nil || n.config == nil || n.config.DataDir == "" || !experimentalTDilithium3V1Enabled() {
		return nil
	}
	n.tdilithium3DKGEpochRosterStoreMu.Lock()
	defer n.tdilithium3DKGEpochRosterStoreMu.Unlock()
	if n.tdilithium3DKGEpochRosterStore == nil {
		n.mu.RLock()
		var genesis types.Hash
		if n.genesisBlock != nil && n.genesisBlock.Header != nil {
			genesis = block.ComputeBlockHash(n.genesisBlock.Header)
		}
		n.mu.RUnlock()
		n.tdilithium3DKGEpochRosterStore = newTDilithium3DKGEpochRosterStore(
			filepath.Join(n.config.DataDir, tdilithium3DKGEpochRosterFileName),
			n.config.NetworkID, genesis,
		)
	}
	return n.tdilithium3DKGEpochRosterStore
}

// tdilithium3DKGCurrentFinalizedEpoch reads the live finalized epoch, or 0 when
// the consensus engine is not available (the persisted floor still applies).
func (n *Node) tdilithium3DKGCurrentFinalizedEpoch() uint64 {
	if n == nil || n.blockProducer == nil {
		return 0
	}
	qpos := n.blockProducer.QPOS()
	if qpos == nil {
		return 0
	}
	return qpos.GetFinalizedEpoch()
}

// captureTDilithium3DKGEpochRosterFromBlock is the epoch-boundary hook. It is
// called on every path that applies a block's side effects (local production,
// sync import, live P2P import) and records the roster once per epoch.
//
// Anchor rule — byte-compatible with the R101 epoch boundary root rule, which
// handles the same missed-slot case for headers:
//   - the boundary slot (slot % SlotsPerEpoch == 0) produced a block → the
//     anchor is that block's own hash;
//   - the boundary slot was missed → the anchor is the epoch's FIRST canonical
//     block's parent hash (the chain tip at the epoch boundary), and the
//     capture fires on that first block, not on the missing boundary block.
//
// The missed-slot branch is load-bearing, not cosmetic: the DKG/reshare session
// derivation fails closed on a missing snapshot, and devnet acceptance runs
// showed real devnets miss boundary slots regularly (proposer downtime), which
// permanently bricked every rotation anchored on the uncaptured epoch. An epoch
// whose slots were ALL missed is never captured — there is no canonical block
// to anchor on — and sessions referencing it fail closed, identically on every
// node.
func (n *Node) captureTDilithium3DKGEpochRosterFromBlock(blk *encoding.Block) {
	if n == nil || blk == nil || blk.Header == nil || !experimentalTDilithium3V1Enabled() {
		return
	}
	header := blk.Header
	if header.Slot == 0 {
		return
	}
	epoch := header.Slot / consensus.SlotsPerEpoch
	if header.Epoch != epoch {
		nodeLog.Warn("Dilithium3 DKG epoch roster: refusing block %d with header epoch %d (slot-derived %d)",
			header.Height, header.Epoch, epoch)
		return
	}
	anchor := block.ComputeBlockHash(header)
	if header.Slot%consensus.SlotsPerEpoch != 0 {
		// Missed boundary slot: only the epoch's first canonical block may
		// trigger the capture, anchored at the chain tip of the epoch boundary
		// (its parent) so every node derives the same digest for the epoch.
		if header.Height == 0 || n.blockStore == nil {
			return
		}
		parent, err := n.blockStore.GetBlockByHeight(header.Height - 1)
		if err != nil || parent == nil || parent.Header == nil {
			nodeLog.Warn("Dilithium3 DKG epoch roster: epoch %d not captured: parent block %d unavailable: %v",
				epoch, header.Height-1, err)
			return
		}
		if parent.Header.Slot/consensus.SlotsPerEpoch >= epoch {
			// Not the epoch's first canonical block (or a non-monotonic
			// parent); a boundary block or an earlier first block owns this
			// epoch's capture.
			return
		}
		anchor = header.ParentHash
	}
	if n.blockProducer == nil {
		nodeLog.Warn("Dilithium3 DKG epoch roster: epoch %d not captured: no block producer", epoch)
		return
	}
	qpos := n.blockProducer.QPOS()
	if qpos == nil {
		nodeLog.Warn("Dilithium3 DKG epoch roster: epoch %d not captured: no QPOS engine", epoch)
		return
	}
	set := qpos.GetValidatorSet()
	if set == nil {
		nodeLog.Warn("Dilithium3 DKG epoch roster: epoch %d not captured: no validator set", epoch)
		return
	}
	entries, err := tdilithium3DKGActiveRosterEntries(set.Validators())
	if err != nil {
		nodeLog.Warn("Dilithium3 DKG epoch roster: epoch %d not captured: %v", epoch, err)
		return
	}
	if len(entries) == 0 {
		nodeLog.Warn("Dilithium3 DKG epoch roster: epoch %d not captured: active roster is empty", epoch)
		return
	}
	store := n.tdilithium3DKGEpochRosterStoreForUse()
	if store == nil {
		return
	}
	if err := store.capture(epoch, anchor, entries, qpos.GetFinalizedEpoch()); err != nil {
		nodeLog.Warn("Dilithium3 DKG epoch roster: epoch %d not captured: %v", epoch, err)
		return
	}
	nodeLog.Info("Dilithium3 DKG epoch roster: epoch %d captured (%d entries, anchor %s, block %d slot %d)",
		epoch, len(entries), anchor.String(), header.Height, header.Slot)
}

// finalizedEpochValidatorRoster returns the captured roster of a finalized
// epoch, or the named fail-closed error. It never falls back to the live set.
func (n *Node) finalizedEpochValidatorRoster(epoch uint64) (*tdilithium3DKGEpochRoster, error) {
	store := n.tdilithium3DKGEpochRosterStoreForUse()
	if store == nil {
		return nil, fmt.Errorf("%w: roster snapshot store is not enabled on this node", errTDilithium3DKGEpochRosterUnavailable)
	}
	return store.lookup(epoch, n.tdilithium3DKGCurrentFinalizedEpoch())
}

// capturedEpochValidatorRoster returns the roster captured while applying the
// boundary block of epoch, without requiring that epoch to be finalized. It is
// the anchor for DKG session derivation; see lookupCaptured for why finality is
// deliberately not applied. It never falls back to the live validator set.
func (n *Node) capturedEpochValidatorRoster(epoch uint64) (*tdilithium3DKGEpochRoster, error) {
	store := n.tdilithium3DKGEpochRosterStoreForUse()
	if store == nil {
		return nil, fmt.Errorf("%w: roster snapshot store is not enabled on this node", errTDilithium3DKGEpochRosterUnavailable)
	}
	return store.lookupCaptured(epoch)
}
