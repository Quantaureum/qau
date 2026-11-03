// Quantaureum Go SDK source, version 1.0.0.
package client

// Per-epoch verifiable randomness client methods (qau_randomnessGet /
// qau_randomnessLatest). The randomness is the per-epoch VRF accumulator
// recorded on the epoch boundary block header — publicly verifiable against
// block data; see docs/RANDOMNESS-API.md in the node repository.

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
)

// RandomnessRecord is one epoch's verifiable randomness.
type RandomnessRecord struct {
	// Epoch is the epoch the randomness belongs to.
	Epoch uint64
	// Randomness is the VRF accumulator — the canonical randomness value.
	Randomness common.Hash
	// BoundaryBlock is the height of the epoch's boundary (last) block,
	// epoch*32+31, whose header carries the accumulator.
	BoundaryBlock uint64
	// BlockHash is the hash of BoundaryBlock.
	BlockHash common.Hash
	// Finalized is true only when the epoch is finalized (irreversible).
	Finalized bool
	// Source identifies the provenance; always "vrf-accumulator".
	Source string
}

// rawRandomnessRecord mirrors the wire format: epoch is a decimal JSON
// number; boundaryBlock is a 0x-prefixed hex height; randomness/blockHash
// are 0x-prefixed 32-byte hex.
type rawRandomnessRecord struct {
	Epoch         uint64 `json:"epoch"`
	Randomness    string `json:"randomness"`
	BoundaryBlock string `json:"boundaryBlock"`
	BlockHash     string `json:"blockHash"`
	Finalized     bool   `json:"finalized"`
	Source        string `json:"source"`
}

// EpochRandomness returns the verifiable randomness of a specific epoch.
// A sealed but not-yet-finalized epoch is served with Finalized=false; an
// epoch whose boundary block does not exist yet on the node returns a
// JSON-RPC error.
func (c *Client) EpochRandomness(ctx context.Context, epoch uint64) (*RandomnessRecord, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	var raw rawRandomnessRecord
	params := []any{map[string]string{"epoch": strconv.FormatUint(epoch, 10)}}
	if err := c.rpc.Call(ctx, &raw, "qau_randomnessGet", params...); err != nil {
		return nil, fmt.Errorf("qau_randomnessGet(%d) failed: %w", epoch, err)
	}
	return decodeRandomness(raw)
}

// LatestRandomness returns the verifiable randomness of the highest
// finalized epoch. Until the chain's first epoch finalization this returns
// a JSON-RPC error.
func (c *Client) LatestRandomness(ctx context.Context) (*RandomnessRecord, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	var raw rawRandomnessRecord
	if err := c.rpc.Call(ctx, &raw, "qau_randomnessLatest"); err != nil {
		return nil, fmt.Errorf("qau_randomnessLatest failed: %w", err)
	}
	return decodeRandomness(raw)
}

// decodeRandomness parses the wire format into the typed record.
func decodeRandomness(raw rawRandomnessRecord) (*RandomnessRecord, error) {
	boundary, err := parseHexUint64(raw.BoundaryBlock)
	if err != nil {
		return nil, fmt.Errorf("boundaryBlock: %w", err)
	}
	return &RandomnessRecord{
		Epoch:         raw.Epoch,
		Randomness:    common.HexToHash(raw.Randomness),
		BoundaryBlock: boundary,
		BlockHash:     common.HexToHash(raw.BlockHash),
		Finalized:     raw.Finalized,
		Source:        raw.Source,
	}, nil
}

// parseHexUint64 parses a 0x-prefixed (or bare) hex uint64.
func parseHexUint64(s string) (uint64, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if s == "" {
		return 0, fmt.Errorf("empty hex value")
	}
	return strconv.ParseUint(s, 16, 64)
}
