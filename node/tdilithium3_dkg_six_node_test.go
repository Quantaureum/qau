// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func testTDilithium3DKGRunners(t *testing.T) ([6]*tdilithium3DKGRunner, *tdilithium3DKGMemoryTransport) {
	t.Helper()
	root := t.TempDir()
	session := dilithium3v1.DKGSession{
		Protocol:        protocol.ThresholdProtocolDilithium3V1,
		ChainID:         1669,
		KeyGeneration:   1,
		Committee:       protocol.CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{101, 102, 103, 104, 105, 106}},
		ActivationEpoch: 7,
		Nonce:           [32]byte{1, 2, 3},
	}
	session.IdentityRosterDigest = testTDilithium3IdentityRosterDigest(t, session, "DEVNET ONLY live DKG identity")
	transport := newTDilithium3DKGMemoryTransport()
	var runners [6]*tdilithium3DKGRunner
	for position := range runners {
		entropy := bytes.NewReader(bytes.Repeat([]byte{byte(position + 1), byte(position + 17), byte(position + 33)}, 1<<16))
		runner, err := newTDilithium3DKGRunner(tdilithium3DKGRunnerConfig{
			Session:             session.Clone(),
			ParticipantPosition: uint8(position),
			BasePath:            filepath.Join(root, "node", string(rune('a'+position)), "shares.enc"),
			Password:            []byte("DEVNET ONLY six-node DKG password"),
			Entropy:             entropy,
		})
		if err != nil {
			t.Fatal(err)
		}
		runners[position] = runner
	}
	return runners, transport
}

func restartTDilithium3DKGRunners(t *testing.T, previous [6]*tdilithium3DKGRunner) [6]*tdilithium3DKGRunner {
	t.Helper()
	var restarted [6]*tdilithium3DKGRunner
	for position, old := range previous {
		runner, err := newTDilithium3DKGRunner(tdilithium3DKGRunnerConfig{
			Session:             old.session.Clone(),
			ParticipantPosition: uint8(position),
			BasePath:            old.basePath,
			Password:            append([]byte(nil), old.password...),
			Entropy:             bytes.NewReader(bytes.Repeat([]byte{byte(200 + position)}, 1<<16)),
		})
		if err != nil {
			t.Fatal(err)
		}
		restarted[position] = runner
	}
	return restarted
}
