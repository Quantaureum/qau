// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/types"
)

// R3-05: the RPC layer must reconstruct the proposal authParams from the same
// canonical forms as the core layer (canonical proposer address and decimal
// deposit). A non-canonical proposer string or a deposit with leading zeros
// must not make the RPC signature check pass and the core check fail.
func TestCreateProposalNormalizesProposerAndDeposit(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	proposerHex := kp.Public.Address().ToHexAddress()

	// Client-supplied non-canonical forms: uppercase hex without 0x, and a
	// deposit with leading zeros.
	nonCanonicalProposer := strings.ToUpper(strings.TrimPrefix(proposerHex, "0x"))
	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	nonCanonicalDeposit := "0" + deposit.String()

	const (
		chainID        = uint64(1668)
		title          = "raise parameter"
		description    = "test proposal"
		totalVotePower = "1000"
		nonce          = "1"
	)
	deadline := fmt.Sprintf("%d", time.Now().Add(5*time.Minute).Unix())
	changes := []economics.ParameterChange{{Parameter: "param", NewValue: "value"}}

	changesJSON, err := json.Marshal(changes)
	if err != nil {
		t.Fatalf("marshal changes: %v", err)
	}
	authParams := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s",
		proposerHex, uint8(economics.ProposalTypeParameter), title, description,
		deposit.String(), totalVotePower, string(changesJSON))
	message := []byte(fmt.Sprintf("QAU-%s|%d|%s|%s|%s|%s",
		economics.GovernanceProposalSignatureMethod, chainID, proposerHex, nonce, deadline, authParams))
	signature, err := kp.Private.Sign(message)
	if err != nil {
		t.Fatalf("sign proposal message: %v", err)
	}

	gm := economics.NewGovernanceManager(nil)
	defer gm.Close()
	api := NewGovernanceAPI(gm, nil)
	api.SetChainID(chainID)

	request := map[string]any{
		"proposer":       nonCanonicalProposer,
		"type":           uint8(economics.ProposalTypeParameter),
		"title":          title,
		"description":    description,
		"changes":        changes,
		"deposit":        nonCanonicalDeposit,
		"totalVotePower": totalVotePower,
		"nonce":          nonce,
		"deadline":       deadline,
		"signature":      hex.EncodeToString(signature),
		"publicKey":      hex.EncodeToString(kp.Public.Bytes()),
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	if _, rpcErr := api.CreateProposal(context.Background(), raw); rpcErr != nil {
		t.Fatalf("non-canonical but correctly signed proposal rejected: %v", rpcErr)
	}
}

// R4-RES: verify that CastVote's authParams now uses voter.ToHexAddress()
// (normalized) rather than req.Voter (raw, possibly non-normalized input).
// Without this, a client sending voter as "0xabc" (lowercase) would have
// authParams bind "0xabc" while the on-chain record uses "0xABC", breaking
// signature replay protection.
func TestCastVoteNormalizesVoter(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	voterHex := kp.Public.Address().ToHexAddress()
	// Client-supplied non-canonical form: uppercase hex without the 0x prefix.
	nonCanonicalVoter := strings.ToUpper(strings.TrimPrefix(voterHex, "0x"))

	const (
		chainID   = uint64(1668)
		nonce     = "1"
		votePower = "1000"
	)
	deadline := fmt.Sprintf("%d", time.Now().Add(5*time.Minute).Unix())

	// Create a proposal for the voter to vote on. CastVote's signed message
	// is only checked by the RPC layer, so the proposal itself can be made
	// with a nil signature through the core manager directly.
	gm := economics.NewGovernanceManager(economics.DefaultGovernanceConfig())
	defer gm.Close()
	proposer := kp.Public.Address()
	changes := []economics.ParameterChange{{Parameter: "param", NewValue: "value"}}
	proposal, err := gm.CreateProposal(proposer, economics.ProposalTypeParameter, "title", "desc",
		changes, economics.DefaultGovernanceConfig().ProposalDeposit, 100, big.NewInt(1000), 1, nil)
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}

	// The core Vote path requires a StakeSnapshotQuerier (fail-closed since
	// R35-P0-14). Provide one that reports the voter's claimed stake.
	querier := newCastVoteSnapshotQuerier()
	querier.SetStakeAt(1, voterHex, big.NewInt(1000))
	gm.SetStakeQuerier(querier)

	api := NewGovernanceAPI(gm, nil)
	api.SetChainID(chainID)

	// authParams must be built from the CANONICAL voter form — the same
	// representation the RPC layer records on-chain — matching the R3-05
	// normalization applied to CreateProposal and FinalizeProposal.
	authParams := fmt.Sprintf("%d|%s|%d|%s", proposal.ID, voterHex, uint8(economics.VoteOptionYes), votePower)
	message := []byte(fmt.Sprintf("QAU-%s|%d|%s|%s|%s|%s",
		"qau_castVote", chainID, voterHex, nonce, deadline, authParams))
	signature, err := kp.Private.Sign(message)
	if err != nil {
		t.Fatalf("sign vote message: %v", err)
	}

	request := map[string]any{
		"proposalId": proposal.ID,
		"voter":      nonCanonicalVoter,
		"option":     uint8(economics.VoteOptionYes),
		"votePower":  votePower,
		"nonce":      nonce,
		"deadline":   deadline,
		"signature":  hex.EncodeToString(signature),
		"publicKey":  hex.EncodeToString(kp.Public.Bytes()),
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	if _, rpcErr := api.CastVote(context.Background(), raw); rpcErr != nil {
		t.Fatalf("non-canonical but correctly signed vote rejected: %v", rpcErr)
	}

	vote, err := gm.GetVote(proposal.ID, kp.Public.Address())
	if err != nil {
		t.Fatalf("GetVote after CastVote: %v", err)
	}
	if vote == nil {
		t.Fatal("vote not recorded")
	}
}

// castVoteSnapshotQuerier is a minimal StakeSnapshotQuerier for the
// CastVote normalization test (the core Vote path is fail-closed without
// one since R35-P0-14).
type castVoteSnapshotQuerier struct {
	stakes map[types.Address]*big.Int
}

func newCastVoteSnapshotQuerier() *castVoteSnapshotQuerier {
	return &castVoteSnapshotQuerier{stakes: make(map[types.Address]*big.Int)}
}

func (m *castVoteSnapshotQuerier) SetStakeAt(_ uint64, addrHex string, amount *big.Int) {
	addr, err := types.ParseHexAddress(addrHex)
	if err != nil {
		return
	}
	m.stakes[addr] = new(big.Int).Set(amount)
}

func (m *castVoteSnapshotQuerier) GetStakeAmount(addr types.Address) (*big.Int, error) {
	if s, ok := m.stakes[addr]; ok {
		return new(big.Int).Set(s), nil
	}
	return big.NewInt(0), nil
}

func (m *castVoteSnapshotQuerier) GetStakeAmountAtHeight(addr types.Address, _ uint64) (*big.Int, error) {
	return m.GetStakeAmount(addr)
}
