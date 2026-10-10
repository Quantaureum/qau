// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bytes"
	"crypto/sha3"
	"fmt"
	"io"
	"math/bits"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// dealerTestEntropy is a deterministic byte stream for tests: a SHAKE256
// stream over the seed, so dealings are reproducible and two seeds never
// produce overlapping streams.
type dealerTestEntropy struct{ reader io.Reader }

func newDealerTestEntropy(seed string) *dealerTestEntropy {
	shake := sha3.NewSHAKE256()
	_, _ = shake.Write([]byte("QAU dealer test entropy"))
	_, _ = shake.Write([]byte{byte(len(seed))})
	_, _ = shake.Write([]byte(seed))
	return &dealerTestEntropy{reader: shake}
}

func (stream *dealerTestEntropy) Read(destination []byte) (int, error) {
	return io.ReadFull(stream.reader, destination)
}

func dealerTestSession() DKGSession {
	return DKGSession{
		Protocol:             protocol.ThresholdProtocolDilithium3V1,
		ChainID:              1668,
		KeyGeneration:        1,
		Committee:            protocol.CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}},
		ActivationEpoch:      7,
		Nonce:                [32]byte{9},
		IdentityRosterDigest: [32]byte{8},
	}
}

// TestDealSharesProduceSignableCommittee deals a full committee offline and
// then exercises the SAME public-response combination algebra the distributed
// ceremony path is validated against, for every 4-of-6 signer mask. This is
// the ceremony's proof that its shares open signatures under the assembled
// group key across the whole access structure.
func TestDealSharesProduceSignableCommittee(t *testing.T) {
	sharesSlice, key, rho, err := DealShares(dealerTestSession(), newDealerTestEntropy("committee-alpha"))
	if err != nil {
		t.Fatal(err)
	}
	var shares [6]*LocalShare
	copy(shares[:], sharesSlice)
	for mask := uint8(0); mask < 64; mask++ {
		if bits.OnesCount8(mask) != 4 {
			continue
		}
		t.Run(fmt.Sprintf("mask-%06b", mask), func(t *testing.T) {
			testMode3PublicResponseCombinationForMask(t, shares, key, rho, mask)
		})
	}
}

func TestDealSharesRejectInvalidSession(t *testing.T) {
	bad := dealerTestSession()
	bad.ChainID = 0
	if _, _, _, err := DealShares(bad, newDealerTestEntropy("x")); err == nil {
		t.Fatal("zero chain ID session accepted")
	}
	if _, _, _, err := DealShares(dealerTestSession(), nil); err == nil {
		t.Fatal("nil entropy accepted")
	}
}

// TestDealSharesDistinctEntropy asserts two independent dealings do not share
// key material (guards against an entropy-plumbing regression collapsing the
// draws).
func TestDealSharesDistinctEntropy(t *testing.T) {
	_, keyA, _, err := DealShares(dealerTestSession(), newDealerTestEntropy("committee-alpha"))
	if err != nil {
		t.Fatal(err)
	}
	_, keyB, _, err := DealShares(dealerTestSession(), newDealerTestEntropy("committee-beta"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keyA.PublicKey, keyB.PublicKey) {
		t.Fatal("two dealings produced the same group public key")
	}
}
