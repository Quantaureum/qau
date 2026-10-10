// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// offlineCeremonyTestEntries builds six validator identities with real
// Dilithium3 keys (DEVNET ONLY seeds — test fixture material, production keys
// never exist on this machine).
func offlineCeremonyTestEntries(t *testing.T) []OfflineCeremonyRosterEntry {
	t.Helper()
	entries := make([]OfflineCeremonyRosterEntry, 6)
	for position := range entries {
		var seed [mode3.SeedSize]byte
		copy(seed[:], fmt.Sprintf("DEVNET ONLY offline ceremony %d", position))
		publicKey, _ := mode3.NewKeyFromSeed(&seed)
		entries[position] = OfflineCeremonyRosterEntry{
			Address:   types.AddressFromPublicKey(publicKey.Bytes()),
			PublicKey: publicKey.Bytes(),
			Stake:     big.NewInt(1_000_000),
		}
	}
	return entries
}

func TestOfflineCeremonySessionDerivesDeterministically(t *testing.T) {
	entries := offlineCeremonyTestEntries(t)
	var genesis types.Hash
	copy(genesis[:], "DEVNET ONLY offline ceremony genesis")

	first, err := OfflineCeremonySession(1668, genesis, 7, entries)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OfflineCeremonySession(1668, genesis, 7, entries)
	if err != nil {
		t.Fatal(err)
	}
	if first.Nonce != second.Nonce || first.IdentityRosterDigest != second.IdentityRosterDigest {
		t.Fatal("session derivation is not deterministic")
	}
	if first.Committee.Threshold != 4 || len(first.Committee.Participants) != 6 {
		t.Fatalf("committee family broken: threshold %d participants %d",
			first.Committee.Threshold, len(first.Committee.Participants))
	}
	if first.KeyGeneration != 7 || first.ActivationEpoch != 7 {
		t.Fatalf("activation/generation mismatch: %+v", first)
	}

	// Any roster-content drift must change the session's digests.
	perturbed := offlineCeremonyTestEntries(t)
	perturbed[3].PublicKey[0] ^= 1
	third, err := OfflineCeremonySession(1668, genesis, 7, perturbed)
	if err != nil {
		t.Fatal(err)
	}
	if first.IdentityRosterDigest == third.IdentityRosterDigest {
		t.Fatal("roster perturbation left the identity roster digest unchanged")
	}

	if _, err := OfflineCeremonySession(1668, genesis, 0, entries); err == nil {
		t.Fatal("activation epoch zero accepted")
	}
}

func TestInstallOfflineCeremonyShareRoundTrip(t *testing.T) {
	entries := offlineCeremonyTestEntries(t)
	var genesis types.Hash
	copy(genesis[:], "DEVNET ONLY offline ceremony genesis")
	session, err := OfflineCeremonySession(1668, genesis, 7, entries)
	if err != nil {
		t.Fatal(err)
	}
	shares, key, _, err := dilithium3v1.DealShares(session, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, share := range shares {
			share.Zeroize()
		}
	}()

	transportPassword := []byte("DEVNET ONLY transport password 0123456789")
	storePassword := []byte("DEVNET ONLY store password 0123456789abc")

	plaintext, err := shares[0].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := tss.EncryptSingleShareBlob(plaintext, transportPassword)
	for i := range plaintext {
		plaintext[i] = 0
	}
	if err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	pid, err := InstallOfflineCeremonyShare(dataDir, blob, transportPassword, storePassword)
	if err != nil {
		t.Fatal(err)
	}
	if pid != shares[0].ParticipantID {
		t.Fatalf("installed participant %d, want %d", pid, shares[0].ParticipantID)
	}

	store := newThresholdShareStore(dataDir)
	loaded, err := store.LoadCandidate(session.KeyGeneration, shares[0].ParticipantID, storePassword)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Zeroize()
	if !bytes.Equal(loaded.Key.PublicKey, shares[0].Key.PublicKey) ||
		loaded.ActivationEpoch != 7 || loaded.Committee.Threshold != 4 {
		t.Fatal("loaded candidate diverged from the installed share")
	}
	if !bytes.Equal(loaded.Key.PublicKey, key.PublicKey) {
		t.Fatal("candidate key diverged from the committee group key")
	}

	// The transport password must not unlock an already-installed share.
	wrong := []byte("DEVNET ONLY wrong transport password")
	if _, err := InstallOfflineCeremonyShare(t.TempDir(), blob, wrong, storePassword); err == nil {
		t.Fatal("wrong transport password accepted")
	}
}
