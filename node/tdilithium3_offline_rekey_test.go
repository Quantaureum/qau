// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// testOfflineRekeyNode returns a node whose share store holds one activated
// share, armed for the given offline activation epoch.
func testOfflineRekeyNode(t *testing.T, armedEpoch uint64) (*Node, uint64) {
	t.Helper()
	useCountingThresholdPersistenceCrypto(t)
	base := filepath.Join(t.TempDir(), "shares.enc")
	password := "DEVNET ONLY offline rekey password"
	store := newThresholdShareStore(base)
	share := testThresholdStoreShare(t, 2)
	if err := store.Store(share, []byte(password)); err != nil {
		t.Fatal(err)
	}
	certificate, sessionDigest, verifier, bindings := testThresholdActivationCertificate(t, share)
	if err := store.ActivateCandidate(certificate, sessionDigest, share.ActivationEpoch, verifier, bindings, []byte(password)); err != nil {
		t.Fatalf("activation: %v", err)
	}
	n := &Node{config: &Config{
		DataDir:                     base,
		ValidatorKeyPassword:        password,
		TSSV1SealingActivationEpoch: armedEpoch,
	}}
	return n, share.ActivationEpoch
}

// Re-arming the offline path for a later ceremony retires the active share
// immediately: until the new ceremony's share activates, nothing may sign or
// anchor with the old key, which is the key being replaced.
func TestOfflineActiveShareSupersededByLaterCeremony(t *testing.T) {
	matching, activation := testOfflineRekeyNode(t, 0)
	matching.config.TSSV1SealingActivationEpoch = activation
	epoch, key, _, err := matching.tdilithium3ActiveShareIdentityCached()
	if err != nil || epoch != activation || len(key) == 0 {
		t.Fatalf("the share of the armed ceremony must load: epoch=%d err=%v", epoch, err)
	}

	superseded, activation := testOfflineRekeyNode(t, 0)
	superseded.config.TSSV1SealingActivationEpoch = activation + 8
	if _, _, _, err := superseded.tdilithium3ActiveShareIdentityCached(); !errors.Is(err, errTDilithium3ActiveShareSuperseded) {
		t.Fatalf("an active share older than the armed ceremony must be refused, got %v", err)
	}
	// The refusal holds on the cached path too.
	if _, _, _, err := superseded.tdilithium3ActiveShareIdentityCached(); !errors.Is(err, errTDilithium3ActiveShareSuperseded) {
		t.Fatalf("second read: %v", err)
	}

	disarmed, _ := testOfflineRekeyNode(t, 0)
	if _, _, _, err := disarmed.tdilithium3ActiveShareIdentityCached(); err != nil {
		t.Fatalf("a disarmed node keeps reading its share (the executor gate is closed anyway): %v", err)
	}
}

// A verify-only node learns the armed ceremony's group key from its operator
// (the same trust source as the ceremony itself), so it can follow a re-key
// whose new key no handoff from the replaced key can vouch for.
func TestOfflineTrustedObserverGroupKey(t *testing.T) {
	key := make([]byte, 1952)
	for index := range key {
		key[index] = byte(index*7 + 3)
	}
	observer := &Node{config: &Config{
		DataDir:                     filepath.Join(t.TempDir(), "observer"),
		ValidatorKeyPassword:        "DEVNET ONLY observer password",
		TSSV1SealingActivationEpoch: 40,
		TSSV1TrustedGroupKey:        hex.EncodeToString(key),
	}}
	gotEpoch, gotKey, ok, err := observer.offlineTDilithium3TrustedGroupKey()
	if err != nil || !ok || gotEpoch != 40 || hex.EncodeToString(gotKey) != hex.EncodeToString(key) {
		t.Fatalf("trusted key not served: epoch=%d ok=%v err=%v", gotEpoch, ok, err)
	}

	unset := &Node{config: &Config{TSSV1SealingActivationEpoch: 40}}
	if _, _, ok, err := unset.offlineTDilithium3TrustedGroupKey(); ok || err != nil {
		t.Fatalf("no trusted key configured must be a quiet no-op: ok=%v err=%v", ok, err)
	}
	disarmed := &Node{config: &Config{TSSV1TrustedGroupKey: hex.EncodeToString(key)}}
	if _, _, ok, err := disarmed.offlineTDilithium3TrustedGroupKey(); ok || err == nil {
		t.Fatalf("a trusted key without an armed epoch must be refused: ok=%v err=%v", ok, err)
	}
	for _, bad := range []string{"zz", hex.EncodeToString(key[:100]), strings.Repeat("00", 1952)} {
		broken := &Node{config: &Config{TSSV1SealingActivationEpoch: 40, TSSV1TrustedGroupKey: bad}}
		if _, _, ok, err := broken.offlineTDilithium3TrustedGroupKey(); ok || err == nil {
			t.Fatalf("malformed trusted key %.8s… accepted", bad)
		}
	}

	// A node holding a share of the armed ceremony uses the share's key; the
	// configured key is only for verify-only nodes, and a holder whose
	// configured key differs from its share's is told so.
	holder, activation := testOfflineRekeyNode(t, 0)
	holder.config.TSSV1SealingActivationEpoch = activation
	holder.config.TSSV1TrustedGroupKey = hex.EncodeToString(key)
	if _, _, ok, err := holder.offlineTDilithium3TrustedGroupKey(); ok || err == nil {
		t.Fatalf("a share holder with a foreign configured key must be refused with an error: ok=%v err=%v", ok, err)
	}
	_, shareKey, _, err := holder.tdilithium3ActiveShareIdentityCached()
	if err != nil {
		t.Fatal(err)
	}
	holder.config.TSSV1TrustedGroupKey = hex.EncodeToString(shareKey)
	if _, _, ok, err := holder.offlineTDilithium3TrustedGroupKey(); ok || err != nil {
		t.Fatalf("a share holder configured with its own key must be a quiet no-op: ok=%v err=%v", ok, err)
	}

	// The experimental runtime-DKG path rotates keys itself and is never
	// re-rooted.
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	experimental := &Node{config: &Config{
		NetworkID:                   TestnetNetworkID,
		TSSV1SealingActivationEpoch: 40,
		TSSV1TrustedGroupKey:        hex.EncodeToString(key),
	}}
	if _, _, ok, err := experimental.offlineTDilithium3TrustedGroupKey(); ok || err != nil {
		t.Fatalf("the experimental network must not take a trusted key: ok=%v err=%v", ok, err)
	}
}
