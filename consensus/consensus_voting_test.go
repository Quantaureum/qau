// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

func TestVotingErrorConstants(t *testing.T) {
	errors := []error{
		ErrInvalidVote, ErrDuplicateVote, ErrVoteFromNonValidator,
		ErrInvalidVoteSignature, ErrBlockMismatch, ErrQuorumNotReached,
		ErrVoteTimeout, ErrInvalidAggregatedSignature, ErrDoubleSign,
	}
	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error %T has empty message", e)
		}
	}
}

func TestVotingConstants(t *testing.T) {
	if DefaultVoteTimeout != 2*time.Second {
		t.Error("DefaultVoteTimeout mismatch")
	}
}

func TestGetVotingSystemCaller(t *testing.T) {
	caller := getVotingSystemCaller()
	if caller == (types.Address{}) {
		t.Error("expected non-zero address")
	}

	caller2 := getVotingSystemCaller()
	if caller != caller2 {
		t.Error("should be idempotent")
	}
}

func TestVoteType_Values(t *testing.T) {
	if VoteTypePrevote != 0 {
		t.Error("VoteTypePrevote should be 0")
	}
}

func TestBLS_NewSignatureAggregator(t *testing.T) {
	aggr := NewSignatureAggregator()
	if aggr == nil {
		t.Fatal("expected non-nil")
	}
}

func TestBLS_Aggregate_Empty(t *testing.T) {
	aggr := NewSignatureAggregator()
	_, err := aggr.Aggregate(nil, nil, nil)
	if err != ErrEmptySignatures {
		t.Errorf("expected ErrEmptySignatures, got %v", err)
	}
}

func TestBLS_ErrorConstants(t *testing.T) {
	errors := []error{
		ErrEmptySignatures, ErrSignatureMismatch, ErrInvalidSignature,
		ErrInvalidAggregateFormat,
	}
	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error %T has empty message", e)
		}
	}
}
