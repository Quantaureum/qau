// Quantaureum Node source, version 1.0.0.
package multisig

import (
	"crypto/sha256"
	"encoding/binary"
	// encoding/json is used ONLY by SerializeWallet/DeserializeWallet for local
	// disk persistence (human-readable format). It is NOT used for consensus
	// state hashing — see SerializeWalletBinary + HashWalletConfig instead.
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

type ProposalStatus uint8

const (
	ProposalStatusPending ProposalStatus = iota
	ProposalStatusApproved
	ProposalStatusExecuting
	ProposalStatusExecuted
	ProposalStatusExpired
	ProposalStatusRevoked
)

func (s ProposalStatus) String() string {
	switch s {
	case ProposalStatusPending:
		return "pending"
	case ProposalStatusApproved:
		return "approved"
	case ProposalStatusExecuting:
		return "executing"
	case ProposalStatusExecuted:
		return "executed"
	case ProposalStatusExpired:
		return "expired"
	case ProposalStatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

type WalletConfig struct {
	Address              types.Address `json:"address"`
	Signers              []SignerInfo  `json:"signers"`
	Threshold            int           `json:"threshold"`
	LargeAmountThreshold *big.Int      `json:"largeAmountThreshold,omitempty"`
	CreatedAt            int64         `json:"createdAt"`
}

type SignerInfo struct {
	PublicKey []byte `json:"publicKey"`
	Alias     string `json:"alias,omitempty"`
}

type Proposal struct {
	Hash         types.Hash     `json:"hash"`
	WalletAddr   types.Address  `json:"walletAddr"`
	To           types.Address  `json:"to"`
	Value        *big.Int       `json:"value"`
	Data         []byte         `json:"data,omitempty"`
	GasLimit     uint64         `json:"gasLimit"`
	GasPrice     *big.Int       `json:"gasPrice"`
	SignerBitmap []byte         `json:"signerBitmap"`
	Signatures   [][]byte       `json:"signatures"`
	Status       ProposalStatus `json:"status"`
	Proposer     int            `json:"proposer"`
	CreatedAt    int64          `json:"createdAt"`
	ExpiresAt    int64          `json:"expiresAt"`

	// R39-P1-02 (2026-08-02) FIX: domain-separation context used to
	// produce `Hash`. Persisted so the store + all verifiers can recompute
	// types.ComputeMultisigV2ProposalHash(ChainID, HashWalletAddr, To, Value,
	// Data, Nonce, ExpiresAsUint64) and assert it equals `Hash`. Without
	// these fields, a malicious or buggy caller could store a Proposal whose
	// Hash is unrelated to its field set — letting a later ApproveProposal
	// sign over an arbitrary 32-byte value chosen by the caller.
	//
	// NOTE on the two wallet-address fields:
	//   - WalletAddr is the V1-compat cache key the store uses to look up
	//     walletConfig (historic behavior; consumers like ApproveProposal
	//     call GetWallet(proposal.WalletAddr) so we must NOT retarget it to
	//     the V2-derived address or those queries miss).
	//   - HashWalletAddr is the wallet address actually mixed into the
	//     canonical hash by ComputeMultisigV2ProposalHash. In the V2 path
	//     this is the V2-derived wallet address (NOT the caller EOA); in
	//     the V1 path HashWalletAddr == WalletAddr. Verifying the invariant
	//     uses HashWalletAddr so it matches the bytes the signer actually
	//     signed over.
	//
	// Zero values mean "legacy proposal created before R39-P1-02"; such
	// proposals are rejected by VerifyProposalHash (CreateProposal blocks
	// before persisting them).
	ChainID        uint64        `json:"chainId"`
	Nonce          uint64        `json:"nonce"`
	HashWalletAddr types.Address `json:"hashWalletAddr,omitempty"`
}

func (p *Proposal) SignerCount() int {
	count := 0
	for _, b := range p.SignerBitmap {
		for i := 0; i < 8; i++ {
			if b&(1<<uint(i)) != 0 {
				count++
			}
		}
	}
	return count
}

type MultisigStateStore struct {
	mu        sync.RWMutex
	wallets   map[types.Address]*WalletConfig
	proposals map[types.Hash]*Proposal
	stopCh    chan struct{}
	wg        sync.WaitGroup
	// SECURITY FIX H-7: sync.Once to protect stopCh from double close panic.
	stopOnce sync.Once
}

func NewMultisigStateStore() *MultisigStateStore {
	return &MultisigStateStore{
		wallets:   make(map[types.Address]*WalletConfig),
		proposals: make(map[types.Hash]*Proposal),
		stopCh:    make(chan struct{}),
	}
}

func (s *MultisigStateStore) Stop() {
	// SECURITY FIX H-7: Use sync.Once to prevent double close panic.
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.wg.Wait()
}

func (s *MultisigStateStore) RegisterWallet(config *WalletConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if config == nil {
		return fmt.Errorf("nil wallet config")
	}
	if len(config.Signers) == 0 {
		return fmt.Errorf("wallet must have at least one signer")
	}
	if config.Threshold <= 0 {
		return fmt.Errorf("threshold must be positive")
	}
	if config.Threshold > len(config.Signers) {
		return fmt.Errorf("threshold (%d) cannot exceed signers (%d)", config.Threshold, len(config.Signers))
	}

	if _, exists := s.wallets[config.Address]; exists {
		return fmt.Errorf("wallet already registered: %s", config.Address.String())
	}

	s.wallets[config.Address] = config
	return nil
}

func (s *MultisigStateStore) GetWallet(addr types.Address) *WalletConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.wallets[addr]
}

func (s *MultisigStateStore) IsMultisigWallet(addr types.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.wallets[addr]
	return ok
}

// VerifyProposalHash recomputes the canonical
// ComputeMultisigV2ProposalHash over the proposal's fields and reports
// whether it matches `proposal.Hash`. This is the R39-P1-02 invariant
// check called by CreateProposal (store-side gate, before persisting) and
// ApproveProposal (caller-side gate, after GetProposal).
//
// Rationale: R38-P0-01 P1-02 audit found that CreateProposal trusted
// `proposal.Hash` directly from the caller. A future caller that forgets to
// recompute the hash from the proposal's fields could store a Proposal
// whose Hash is arbitrary — and then ApproveProposal would sign over that
// arbitrary 32-byte value. Storing the chainID/nonce used at hash time
// (added to Proposal in R39-P1-02) lets the store recompute and assert.
//
// Strict posture: there is NO legacy fallback. The proposal store is
// purely in-memory (proposals are never persisted to disk — only wallets
// are serialized), so every Proposal object reachable from store.CreateProposal
// was constructed by a live caller in the current process. Every such caller
// MUST set ChainID > 0 and Nonce > 0 (the canonical hash function itself
// rejects ChainID == 0). A proposal with ChainID == 0 or Nonce == 0 is
// treated as malformed and rejected, closing the "skip the invariant by
// zeroing the fields" bypass that an earlier draft of this fix would have
// left open.
func VerifyProposalHash(proposal *Proposal) (bool, error) {
	if proposal == nil {
		return false, fmt.Errorf("nil proposal")
	}
	if proposal.ChainID == 0 {
		return false, fmt.Errorf("proposal ChainID unset (R39-P1-02 invariant)")
	}
	if proposal.Nonce == 0 {
		return false, fmt.Errorf("proposal Nonce unset (R39-P1-02 invariant)")
	}
	// When HashWalletAddr is unset (the V1 path where WalletAddr == the
	// wallet address used for hash), fall back to WalletAddr. This makes
	// the V1 path — where WalletAddr doubles as the cache key AND the hash
	// input — verify naturally without forcing the caller to set
	// HashWalletAddr. The V2 path sets HashWalletAddr explicitly.
	hashWallet := proposal.HashWalletAddr
	var zeroAddr types.Address
	if hashWallet == zeroAddr {
		hashWallet = proposal.WalletAddr
	}
	recomputed, err := types.ComputeMultisigV2ProposalHash(
		proposal.ChainID,
		hashWallet,
		proposal.To,
		proposal.Value,
		proposal.Data,
		proposal.Nonce,
		uint64(proposal.ExpiresAt),
	)
	if err != nil {
		return false, fmt.Errorf("recompute proposal hash: %w", err)
	}
	return recomputed == proposal.Hash, nil
}

func (s *MultisigStateStore) CreateProposal(proposal *Proposal, walletConfig *WalletConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if proposal == nil {
		return fmt.Errorf("nil proposal")
	}
	if _, exists := s.proposals[proposal.Hash]; exists {
		return fmt.Errorf("proposal already exists")
	}
	if _, exists := s.wallets[proposal.WalletAddr]; !exists {
		return fmt.Errorf("wallet not registered: %s", proposal.WalletAddr.String())
	}

	// R39-P1-02 (2026-08-02) FIX: invariant — the stored Hash MUST equal
	// the canonical ComputeMultisigV2ProposalHash over the proposal's
	// fields. This blocks any caller (RPC, precompile, or future path)
	// from storing a Proposal whose Hash is an arbitrary 32-byte value
	// chosen by the caller rather than recomputed from the fields — which
	// is the R39-P1-02 audit finding (CreateProposal trusted proposal.Hash
	// verbatim, and ApproveProposal then signed over that client-supplied
	// hash). Verifying here at the single chokepoint means every caller
	// is held to the same invariant regardless of whether the caller
	// itself recomputes the hash.
	ok, err := VerifyProposalHash(proposal)
	if err != nil {
		return fmt.Errorf("verify proposal hash: %w", err)
	}
	if !ok {
		// This is fail-closed: refuse to persist a Proposal whose stored
		// Hash does not match the canonical hash of its fields. An attacker
		// who can't produce this invariant simply cannot create a proposal
		// with a mismatched hash.
		return fmt.Errorf("proposal hash mismatch: stored Hash does not equal canonical ComputeMultisigV2ProposalHash over fields (R39-P1-02 invariant)")
	}

	s.proposals[proposal.Hash] = proposal
	return nil
}

// AddSignature records a signer's approval for a proposal.
//
// R31-MED-3 FIX (2026-09-06): the signature is now verified HERE, against
// the signer's Dilithium3 public key from walletConfig, over the canonical
// proposalHash. Previously verification was an implicit contract performed
// only by the RPC caller (rpc/multisig_api.go verified before calling);
// any future caller that invoked the store directly — a new RPC method, a
// dev tool, an internal service — would have silently stored an unverified
// "approval". The store is the single chokepoint where approval state is
// mutated, so it is where verification belongs. Verification failure is
// fail-closed: nothing is stored.
//
// The signed message is exactly proposalHash[:] (32 bytes), matching what
// the RPC layer verified before this fix and what qvm/precompiled V2's
// approveProposal verifies on-chain (crypto.Verify(pubKey, proposalHash)).
func (s *MultisigStateStore) AddSignature(proposalHash types.Hash, signerIndex int, signature []byte, walletConfig *WalletConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if walletConfig == nil {
		return fmt.Errorf("wallet config required for signature verification (R31-MED-3)")
	}

	proposal, ok := s.proposals[proposalHash]
	if !ok {
		return fmt.Errorf("proposal not found")
	}
	if proposal.Status == ProposalStatusExecuted {
		return fmt.Errorf("proposal already executed")
	}
	if proposal.Status == ProposalStatusExecuting {
		return fmt.Errorf("proposal currently executing")
	}
	if proposal.Status == ProposalStatusExpired {
		return fmt.Errorf("proposal expired")
	}
	if proposal.Status == ProposalStatusRevoked {
		return fmt.Errorf("proposal revoked")
	}

	if signerIndex < 0 || signerIndex >= len(walletConfig.Signers) {
		return fmt.Errorf("invalid signer index: %d", signerIndex)
	}

	// R31-MED-3: verify the Dilithium3 signature IN the store, over the
	// canonical proposal hash, against the indexed signer's public key.
	signerPkBytes := walletConfig.Signers[signerIndex].PublicKey
	if len(signerPkBytes) != crypto.Dilithium3PublicKeySize {
		// Legacy address-only signer entries (20 bytes) have no real public
		// key — they can never produce a verifiable signature. Reject rather
		// than store an unverifiable approval.
		return fmt.Errorf("signer %d has no usable Dilithium3 public key (len=%d) — cannot verify signature", signerIndex, len(signerPkBytes))
	}
	if len(signature) != crypto.Dilithium3SignatureSize {
		return fmt.Errorf("invalid signature size: got %d, want %d", len(signature), crypto.Dilithium3SignatureSize)
	}
	signerPk, err := crypto.PublicKeyFromBytes(signerPkBytes)
	if err != nil {
		return fmt.Errorf("invalid signer public key at index %d: %w", signerIndex, err)
	}
	if !crypto.Verify(signerPk, proposalHash[:], signature) {
		return fmt.Errorf("signature verification failed for signer %d (R31-MED-3 fail-closed)", signerIndex)
	}

	byteIndex := signerIndex / 8
	bitIndex := uint(signerIndex % 8)
	if len(proposal.SignerBitmap) <= byteIndex {
		newBitmap := make([]byte, (len(walletConfig.Signers)+7)/8)
		copy(newBitmap, proposal.SignerBitmap)
		proposal.SignerBitmap = newBitmap
	}
	if proposal.SignerBitmap[byteIndex]&(1<<bitIndex) != 0 {
		return fmt.Errorf("signer %d already signed", signerIndex)
	}

	if len(proposal.Signatures) <= signerIndex {
		newSigs := make([][]byte, len(walletConfig.Signers))
		copy(newSigs, proposal.Signatures)
		proposal.Signatures = newSigs
	}
	proposal.Signatures[signerIndex] = make([]byte, len(signature))
	copy(proposal.Signatures[signerIndex], signature)
	proposal.SignerBitmap[byteIndex] |= 1 << bitIndex

	sigCount := proposal.SignerCount()
	if sigCount >= walletConfig.Threshold {
		proposal.Status = ProposalStatusApproved
	} else if sigCount > 0 {
		proposal.Status = ProposalStatusPending
	}

	return nil
}

func (s *MultisigStateStore) MarkExecuted(proposalHash types.Hash) error {
	s.mu.Lock()
	proposal, ok := s.proposals[proposalHash]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("proposal not found")
	}
	if proposal.Status == ProposalStatusExecuted {
		s.mu.Unlock()
		return fmt.Errorf("proposal already executed")
	}
	if proposal.Status != ProposalStatusExecuting {
		s.mu.Unlock()
		return fmt.Errorf("proposal not in executing state: %s", proposal.Status.String())
	}
	proposal.Status = ProposalStatusExecuted
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Warn("multisig: panic in MarkExecuted delayed delete", "hash", proposalHash.String(), "recover", r)
			}
		}()
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-s.stopCh:
			return
		}
		s.mu.Lock()
		if p, ok := s.proposals[proposalHash]; ok && p.Status == ProposalStatusExecuted {
			delete(s.proposals, proposalHash)
		}
		s.mu.Unlock()
	}()

	return nil
}

func (s *MultisigStateStore) TryBeginExecution(proposalHash types.Hash, threshold int) (*Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	proposal, ok := s.proposals[proposalHash]
	if !ok {
		return nil, fmt.Errorf("proposal not found")
	}
	if proposal.Status == ProposalStatusExecuted || proposal.Status == ProposalStatusExecuting {
		return nil, fmt.Errorf("proposal already %s", proposal.Status.String())
	}
	if proposal.Status != ProposalStatusApproved {
		return nil, fmt.Errorf("proposal not in approved state: %s", proposal.Status.String())
	}
	if proposal.SignerCount() < threshold {
		return nil, fmt.Errorf("insufficient signatures: need %d, have %d", threshold, proposal.SignerCount())
	}

	proposal.Status = ProposalStatusExecuting
	return proposal, nil
}

func (s *MultisigStateStore) RollbackExecution(proposalHash types.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if proposal, ok := s.proposals[proposalHash]; ok && proposal.Status == ProposalStatusExecuting {
		proposal.Status = ProposalStatusApproved
	}
}

func (s *MultisigStateStore) MarkExpired(proposals map[types.Hash]*Proposal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for hash, p := range s.proposals {
		// FIX: Also mark Approved proposals as expired. Previously only
		// Pending proposals were checked, allowing Approved proposals to
		// remain active indefinitely past their expiration time. An Approved
		// proposal that has not been executed should still expire if its
		// ExpiresAt deadline has passed.
		if p.ExpiresAt > 0 && now > p.ExpiresAt && (p.Status == ProposalStatusPending || p.Status == ProposalStatusApproved) {
			p.Status = ProposalStatusExpired
			proposals[hash] = p
		}
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Warn("multisig: panic in MarkExpired delayed delete", "count", len(proposals), "recover", r)
			}
		}()
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-s.stopCh:
			return
		}
		s.mu.Lock()
		for hash := range proposals {
			if p, ok := s.proposals[hash]; ok && p.Status == ProposalStatusExpired {
				delete(s.proposals, hash)
			}
		}
		s.mu.Unlock()
	}()
}

func (s *MultisigStateStore) GetProposal(hash types.Hash) *Proposal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.proposals[hash]
}

func (s *MultisigStateStore) GetPendingProposals(walletAddr types.Address) []*Proposal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Proposal
	for _, p := range s.proposals {
		if p.WalletAddr == walletAddr && (p.Status == ProposalStatusPending || p.Status == ProposalStatusApproved) {
			result = append(result, p)
		}
	}
	return result
}

func (s *MultisigStateStore) GetAllProposals(walletAddr types.Address) []*Proposal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Proposal
	for _, p := range s.proposals {
		if p.WalletAddr == walletAddr {
			result = append(result, p)
		}
	}
	return result
}

func (s *MultisigStateStore) GetIncomingTransfersForAddress(recipient types.Address) []*Proposal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Proposal
	for _, p := range s.proposals {
		if p.To == recipient && p.Status == ProposalStatusExecuted {
			result = append(result, p)
		}
	}
	return result
}

const maxProposalsForSigner = 1000

func (s *MultisigStateStore) GetProposalsForSigner(signerAddr types.Address) []*Proposal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var walletAddrs []types.Address
	for addr, config := range s.wallets {
		for _, si := range config.Signers {
			// AUDIT R4-KEYS-01 (2026-07-15): Support both real Dilithium3 public
			// keys (1952 bytes) and legacy address-only entries (20 bytes).
			// L-6 FIX: Use crypto.PublicKeyAddressFromBytes to properly derive the
			// address from the Dilithium3 public key. The previous implementation
			// assumed the first 20 bytes of PublicKey were the address, which is
			// incorrect — Dilithium3 public keys are 1952 bytes and the address is
			// derived via types.AddressFromPublicKey (hash-based), not by truncation.
			if len(si.PublicKey) == crypto.Dilithium3PublicKeySize {
				checkAddr := crypto.PublicKeyAddressFromBytes(si.PublicKey)
				if checkAddr == signerAddr {
					walletAddrs = append(walletAddrs, addr)
					break
				}
			} else if len(si.PublicKey) >= 20 {
				// Legacy: first 20 bytes are the address (backward compat).
				var checkAddr types.Address
				copy(checkAddr[:], si.PublicKey[:20])
				if checkAddr == signerAddr {
					walletAddrs = append(walletAddrs, addr)
					break
				}
			}
		}
	}

	var result []*Proposal
	for _, p := range s.proposals {
		for _, wa := range walletAddrs {
			if p.WalletAddr == wa && (p.Status == ProposalStatusPending || p.Status == ProposalStatusApproved) {
				result = append(result, p)
				break
			}
		}
		if len(result) >= maxProposalsForSigner {
			break
		}
	}
	return result
}

// SerializeWallet serializes a wallet config for local persistence.
// R4-C2 FIX (2026-07-06): Uses JSON for local disk persistence only.
// This method is NOT used for consensus state hashing. The multisig state is
// local to each node and not part of the consensus state root. Use
// SerializeWalletBinary + HashWalletConfig for deterministic hashing.
func (s *MultisigStateStore) SerializeWallet(config *WalletConfig) ([]byte, error) {
	type jsonWallet struct {
		Address              string       `json:"address"`
		Signers              []SignerInfo `json:"signers"`
		Threshold            int          `json:"threshold"`
		LargeAmountThreshold string       `json:"largeAmountThreshold,omitempty"`
		CreatedAt            int64        `json:"createdAt"`
	}

	jw := jsonWallet{
		Address:   config.Address.String(),
		Signers:   config.Signers,
		Threshold: config.Threshold,
		CreatedAt: config.CreatedAt,
	}
	if config.LargeAmountThreshold != nil {
		jw.LargeAmountThreshold = config.LargeAmountThreshold.String()
	}

	return json.Marshal(jw)
}

func (s *MultisigStateStore) DeserializeWallet(data []byte) (*WalletConfig, error) {
	type jsonWallet struct {
		Address              string       `json:"address"`
		Signers              []SignerInfo `json:"signers"`
		Threshold            int          `json:"threshold"`
		LargeAmountThreshold string       `json:"largeAmountThreshold,omitempty"`
		CreatedAt            int64        `json:"createdAt"`
	}

	var jw jsonWallet
	if err := json.Unmarshal(data, &jw); err != nil {
		return nil, err
	}

	config := &WalletConfig{
		Signers:   jw.Signers,
		Threshold: jw.Threshold,
		CreatedAt: jw.CreatedAt,
	}

	if jw.LargeAmountThreshold != "" {
		val, ok := new(big.Int).SetString(jw.LargeAmountThreshold, 10)
		if ok {
			config.LargeAmountThreshold = val
		}
	}

	addr, err := types.ParseAddress(jw.Address)
	if err == nil {
		config.Address = addr
	}

	return config, nil
}

// SerializeWalletBinary provides deterministic binary serialization of a
// WalletConfig using encoding/binary (BigEndian), consistent with qaudb/state.
// R4-C2 FIX (2026-07-06): Added for future consensus-critical serialization
// if multisig state is ever included in the state root.
func (s *MultisigStateStore) SerializeWalletBinary(config *WalletConfig) ([]byte, error) {
	if config == nil {
		return nil, fmt.Errorf("nil config")
	}

	var buf []byte

	// Address (20 bytes)
	buf = append(buf, config.Address[:]...)

	// Threshold (8 bytes, BigEndian)
	var thresholdBuf [8]byte
	binary.BigEndian.PutUint64(thresholdBuf[:], uint64(config.Threshold))
	buf = append(buf, thresholdBuf[:]...)

	// CreatedAt (8 bytes, BigEndian)
	var createdBuf [8]byte
	binary.BigEndian.PutUint64(createdBuf[:], uint64(config.CreatedAt))
	buf = append(buf, createdBuf[:]...)

	// LargeAmountThreshold (32 bytes, fixed-size big.Int)
	if config.LargeAmountThreshold != nil {
		largeBytes := config.LargeAmountThreshold.Bytes()
		padded := make([]byte, 32)
		copy(padded[32-len(largeBytes):], largeBytes)
		buf = append(buf, padded...)
	} else {
		buf = append(buf, make([]byte, 32)...)
	}

	// Signers count (8 bytes) + each signer
	var countBuf [8]byte
	binary.BigEndian.PutUint64(countBuf[:], uint64(len(config.Signers)))
	buf = append(buf, countBuf[:]...)

	for _, si := range config.Signers {
		// Public key length (4 bytes) + public key
		var pkLen [4]byte
		binary.BigEndian.PutUint32(pkLen[:], uint32(len(si.PublicKey)))
		buf = append(buf, pkLen[:]...)
		buf = append(buf, si.PublicKey...)

		// Alias length (4 bytes) + alias
		var aliasLen [4]byte
		binary.BigEndian.PutUint32(aliasLen[:], uint32(len(si.Alias)))
		buf = append(buf, aliasLen[:]...)
		buf = append(buf, []byte(si.Alias)...)
	}

	return buf, nil
}

// DeserializeWalletBinary decodes the deterministic binary representation
// produced by SerializeWalletBinary. The field order mirrors the encoder:
// Address(20), Threshold(8 BE), CreatedAt(8 BE), LargeAmountThreshold(32),
// Signers count(8 BE), then per signer: pkLen(4) + pk + aliasLen(4) + alias.
//
// R4-C2 FIX (2026-07-06): Added to complement SerializeWalletBinary, enabling
// round-trip deterministic serialization for any future consensus state root
// inclusion. Uses encoding/binary.BigEndian, consistent with qaudb/state.
func (s *MultisigStateStore) DeserializeWalletBinary(data []byte) (*WalletConfig, error) {
	// Minimum header: Address(20) + Threshold(8) + CreatedAt(8) +
	// LargeAmountThreshold(32) + Signers count(8) = 76 bytes.
	const headerLen = 20 + 8 + 8 + 32 + 8
	if len(data) < headerLen {
		return nil, fmt.Errorf("data too short: need %d bytes, got %d", headerLen, len(data))
	}

	config := &WalletConfig{}
	off := 0

	// Address (20 bytes)
	copy(config.Address[:], data[off:off+20])
	off += 20

	// Threshold (8 bytes, BigEndian)
	config.Threshold = int(binary.BigEndian.Uint64(data[off : off+8]))
	off += 8

	// CreatedAt (8 bytes, BigEndian)
	config.CreatedAt = int64(binary.BigEndian.Uint64(data[off : off+8]))
	off += 8

	// LargeAmountThreshold (32 bytes, fixed-size big.Int)
	largeBytes := make([]byte, 32)
	copy(largeBytes, data[off:off+32])
	off += 32
	// All-zero bytes serialize from a nil LargeAmountThreshold; keep it nil
	// to faithfully round-trip the original value.
	hasValue := false
	for _, b := range largeBytes {
		if b != 0 {
			hasValue = true
			break
		}
	}
	if hasValue {
		config.LargeAmountThreshold = new(big.Int).SetBytes(largeBytes)
	}

	// Signers count (8 bytes)
	signerCount := binary.BigEndian.Uint64(data[off : off+8])
	off += 8

	config.Signers = make([]SignerInfo, 0, signerCount)
	for i := uint64(0); i < signerCount; i++ {
		// Public key length (4 bytes)
		if off+4 > len(data) {
			return nil, fmt.Errorf("truncated data reading signer %d pkLen", i)
		}
		pkLen := binary.BigEndian.Uint32(data[off : off+4])
		off += 4

		// Public key (pkLen bytes)
		if off+int(pkLen) > len(data) {
			return nil, fmt.Errorf("truncated data reading signer %d publicKey", i)
		}
		pk := make([]byte, pkLen)
		copy(pk, data[off:off+int(pkLen)])
		off += int(pkLen)

		// Alias length (4 bytes)
		if off+4 > len(data) {
			return nil, fmt.Errorf("truncated data reading signer %d aliasLen", i)
		}
		aliasLen := binary.BigEndian.Uint32(data[off : off+4])
		off += 4

		// Alias (aliasLen bytes)
		if off+int(aliasLen) > len(data) {
			return nil, fmt.Errorf("truncated data reading signer %d alias", i)
		}
		alias := string(data[off : off+int(aliasLen)])
		off += int(aliasLen)

		config.Signers = append(config.Signers, SignerInfo{
			PublicKey: pk,
			Alias:     alias,
		})
	}

	return config, nil
}

// HashWalletConfig returns a deterministic SHA-256 hash of the binary
// serialization of config. This provides a stable, encoding/binary-based hash
// suitable for any future inclusion of multisig state in a consensus state root.
//
// R4-C2 FIX (2026-07-06): Added to address the R5 audit concern that
// encoding/json serialization could break state root consistency. JSON output
// is not byte-stable across implementations; this method uses
// SerializeWalletBinary (encoding/binary.BigEndian) + SHA-256 for a fully
// deterministic result.
func (s *MultisigStateStore) HashWalletConfig(config *WalletConfig) (types.Hash, error) {
	data, err := s.SerializeWalletBinary(config)
	if err != nil {
		return types.Hash{}, err
	}
	sum := sha256.Sum256(data)
	return types.BytesToHash(sum[:]), nil
}
