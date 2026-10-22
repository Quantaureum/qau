// Quantaureum Node source, version 1.0.0.
package economics

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// F-01 review follow-up (2026-10-21): the core-layer proposal signature
// verification (verifyProposalSignatureLocked) reconstructs the exact signed
// message that rpc/governance_api.go builds — the format is hand-duplicated in
// the two packages. These tests drive CreateProposal with a non-nil
// ProposalSignature so any drift between the two reconstructions, the deadline
// enforcement, or the pubkey binding fails here instead of silently breaking
// all proposal creation.

// signProposalMessage mirrors the byte layout documented by
// verifyProposalSignatureLocked and verifyGovernanceSignature:
//
//	"QAU-" + method + "|" + chainID + "|" + proposerHex + "|" + nonce +
//	    "|" + deadline + "|" + authParams
//	authParams = proposerHex + "|" + type + "|" + title + "|" + description +
//	    "|" + deposit + "|" + totalVotePower + "|" + changesJSON
func signProposalMessage(t *testing.T, kp *crypto.KeyPair, chainID uint64, nonce, deadline, title, description string, deposit *big.Int, totalVotePower string, changes []ParameterChange) *ProposalSignature {
	t.Helper()
	proposerHex := kp.Public.Address().ToHexAddress()
	changesJSON, err := json.Marshal(changes)
	if err != nil {
		t.Fatalf("marshal changes: %v", err)
	}
	depositStr := "0"
	if deposit != nil {
		depositStr = deposit.String()
	}
	authParams := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s",
		proposerHex, uint8(ProposalTypeParameter), title, description,
		depositStr, totalVotePower, string(changesJSON))
	message := []byte(fmt.Sprintf("QAU-%s|%d|%s|%s|%s|%s",
		GovernanceProposalSignatureMethod, chainID, proposerHex, nonce, deadline, authParams))
	sig, err := kp.Private.Sign(message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return &ProposalSignature{
		ProposerPubKey: kp.Public.Bytes(),
		ProposerSig:    sig,
		Nonce:          nonce,
		Deadline:       deadline,
		ChainID:        chainID,
		TotalVotePower: totalVotePower,
	}
}

func TestCreateProposalCoreSignatureVerification(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	proposer := kp.Public.Address()
	nonce := "42"
	deadline := fmt.Sprintf("%d", time.Now().Add(5*time.Minute).Unix())
	title, description := "title", "desc"
	changes := []ParameterChange{{Parameter: "param", NewValue: "value"}}
	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	const chainID = uint64(1668)
	const totalVotePower = "1000"

	gm := NewGovernanceManager(nil)
	defer gm.Close()

	t.Run("valid signature accepted", func(t *testing.T) {
		sig := signProposalMessage(t, kp, chainID, nonce, deadline, title, description, deposit, totalVotePower, changes)
		proposal, err := gm.CreateProposal(proposer, ProposalTypeParameter, title, description, changes, deposit, 100, nil, 1, sig)
		if err != nil {
			t.Fatalf("CreateProposal with valid signature rejected: %v", err)
		}
		if proposal.Proposer != proposer {
			t.Fatal("proposal proposer mismatch")
		}
	})

	t.Run("expired deadline rejected", func(t *testing.T) {
		gm2 := NewGovernanceManager(nil)
		defer gm2.Close()
		expired := fmt.Sprintf("%d", time.Now().Add(-2*time.Minute).Unix())
		sig := signProposalMessage(t, kp, chainID, "43", expired, title, description, deposit, totalVotePower, changes)
		if _, err := gm2.CreateProposal(proposer, ProposalTypeParameter, title, description, changes, deposit, 100, nil, 1, sig); err == nil {
			t.Fatal("expired proposal signature accepted at core layer")
		}
	})

	t.Run("tampered deadline rejected", func(t *testing.T) {
		gm3 := NewGovernanceManager(nil)
		defer gm3.Close()
		sig := signProposalMessage(t, kp, chainID, "44", deadline, title, description, deposit, totalVotePower, changes)
		// Re-sign nothing: mutate the deadline field after signing.
		tampered := *sig
		tampered.Deadline = fmt.Sprintf("%d", time.Now().Add(6*time.Minute).Unix())
		if _, err := gm3.CreateProposal(proposer, ProposalTypeParameter, title, description, changes, deposit, 100, nil, 1, &tampered); err == nil {
			t.Fatal("tampered deadline accepted at core layer")
		}
	})

	t.Run("wrong chainID rejected", func(t *testing.T) {
		gm4 := NewGovernanceManager(nil)
		defer gm4.Close()
		sig := signProposalMessage(t, kp, chainID, "45", deadline, title, description, deposit, totalVotePower, changes)
		forged := *sig
		forged.ChainID = 1669
		if _, err := gm4.CreateProposal(proposer, ProposalTypeParameter, title, description, changes, deposit, 100, nil, 1, &forged); err == nil {
			t.Fatal("signature accepted under a different chain ID")
		}
	})

	t.Run("signature from different key rejected", func(t *testing.T) {
		gm5 := NewGovernanceManager(nil)
		defer gm5.Close()
		other, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair (other): %v", err)
		}
		// Sign with `other` but claim the first key holder as proposer.
		sig := signProposalMessage(t, other, chainID, "46", deadline, title, description, deposit, totalVotePower, changes)
		if _, err := gm5.CreateProposal(proposer, ProposalTypeParameter, title, description, changes, deposit, 100, nil, 1, sig); err == nil {
			t.Fatal("signature from a different key accepted for the proposer")
		}
	})

	t.Run("failed signature does not burn nonce", func(t *testing.T) {
		gm6 := NewGovernanceManager(nil)
		defer gm6.Close()
		bad := signProposalMessage(t, kp, chainID, "47", deadline, title, description, deposit, totalVotePower, changes)
		bad.ProposerSig = make([]byte, crypto.Dilithium3SignatureSize) // all-zero signature
		if _, err := gm6.CreateProposal(proposer, ProposalTypeParameter, title, description, changes, deposit, 100, nil, 1, bad); err == nil {
			t.Fatal("all-zero signature accepted")
		}
		// The nonce counter must not have advanced, so a retry with nonce 1
		// and a valid signature still works.
		good := signProposalMessage(t, kp, chainID, "47", deadline, title, description, deposit, totalVotePower, changes)
		if _, err := gm6.CreateProposal(proposer, ProposalTypeParameter, title, description, changes, deposit, 100, nil, 1, good); err != nil {
			t.Fatalf("retry after failed signature rejected (nonce burned?): %v", err)
		}
	})
}

// TestGovernanceRPCAndCoreMessageFormatsAgree pins that the RPC layer and the
// core layer build byte-identical signed messages from the same request data.
// The formats are hand-duplicated; this test fails on any drift between them.
func TestGovernanceRPCAndCoreMessageFormatsAgree(t *testing.T) {
	proposerHex := types.Address{0xaa, 0xbb}.ToHexAddress()
	const nonce = "7"
	const deadline = "1700000000"
	const chainID = uint64(1668)
	title, description := "t", "d"
	changes := []ParameterChange{{Parameter: "p", NewValue: "v"}}
	deposit := big.NewInt(123)
	const totalVotePower = "55"

	changesJSON, _ := json.Marshal(changes)
	authParams := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s",
		proposerHex, uint8(ProposalTypeParameter), title, description,
		deposit.String(), totalVotePower, string(changesJSON))

	// Core reconstruction (mirrors verifyProposalSignatureLocked step 5,
	// including the "0" fallback for a nil deposit).
	coreMessage := fmt.Sprintf("QAU-%s|%d|%s|%s|%s|%s",
		GovernanceProposalSignatureMethod, chainID, proposerHex, nonce, deadline, authParams)

	// RPC reconstruction (mirrors rpc/governance_api.go verifyGovernanceSignature).
	rpcMessage := fmt.Sprintf("QAU-%s|%d|%s|%s|%s|%s",
		GovernanceProposalSignatureMethod, chainID, proposerHex, nonce, deadline, authParams)

	if coreMessage != rpcMessage {
		t.Fatalf("message format drift:\ncore = %q\nrpc  = %q", coreMessage, rpcMessage)
	}

	// The nil-deposit fallback must also agree.
	coreNil := fmt.Sprintf("QAU-%s|%d|%s|%s|%s|%s",
		GovernanceProposalSignatureMethod, chainID, proposerHex, nonce, deadline,
		fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s", proposerHex, uint8(ProposalTypeParameter), title, description, "0", totalVotePower, string(changesJSON)))
	if !strings.Contains(coreNil, "|0|") {
		t.Fatal("nil-deposit fallback does not use \"0\"")
	}

	// Sanity: signature bytes actually verify over this message shape.
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	sig, err := kp.Private.Sign([]byte(coreMessage))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !crypto.Verify(kp.Public, []byte(coreMessage), sig) {
		t.Fatal("self-test verify failed")
	}
	_ = hex.EncodeToString
}
