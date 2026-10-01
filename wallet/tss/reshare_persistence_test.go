// Quantaureum Node source, version 1.0.0.
package tss

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

func newPersistenceTestManager(t *testing.T) *TSSManager {
	t.Helper()
	config := DefaultTSSConfig()
	config.Threshold, config.TotalShares = 2, 3
	manager, err := NewTSSManager(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.GenerateKeyShares(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.ZeroizeAllShares)
	return manager
}

func TestReshareSnapshotRestoresSparseConfiguration(t *testing.T) {
	manager := newPersistenceTestManager(t)
	participants := []int{4, 7}
	var contributions []*qtd.SubShare
	for _, participant := range []int{1, 2, 3} {
		shares, err := manager.PrepareReshare(participant, participants, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, share := range shares {
			if share.ToParticipant == 4 {
				contributions = append(contributions, share)
			}
		}
	}
	if err := manager.InstallResharedShare(4, participants, 2, []int{1, 2, 3}, contributions, nil); err != nil {
		t.Fatal(err)
	}
	password := []byte("DEVNET ONLY snapshot test password")
	data, err := manager.ExportKeySharesEncrypted(password)
	if err != nil {
		t.Fatal(err)
	}
	restored := newPersistenceTestManager(t)
	if err := restored.ImportKeySharesEncrypted(data, password); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.ParticipantIDs(), participants) || restored.config.TotalShares != 2 || restored.Threshold() != 2 {
		t.Fatalf("restored wrong holder configuration: ids=%v threshold=%d total=%d", restored.ParticipantIDs(), restored.Threshold(), restored.config.TotalShares)
	}
	if restored.ShareCount() != 1 || !bytes.Equal(restored.GroupPublicKey(), manager.GroupPublicKey()) {
		t.Fatal("snapshot changed active share count or group key")
	}
}

func TestRetiredReshareSnapshotRestoresWithoutActivating(t *testing.T) {
	manager := newPersistenceTestManager(t)
	if err := manager.RetireResharedShare([]int{4, 7}, 2); err != nil {
		t.Fatal(err)
	}
	password := []byte("DEVNET ONLY retired snapshot password")
	data, err := manager.ExportKeySharesEncrypted(password)
	if err != nil {
		t.Fatal(err)
	}
	restored := newPersistenceTestManager(t)
	if err := restored.ImportKeySharesEncrypted(data, password); err != nil {
		t.Fatal(err)
	}
	if restored.ShareCount() != 0 || !reflect.DeepEqual(restored.ParticipantIDs(), []int{4, 7}) {
		t.Fatal("retired shares became active or holder metadata was lost")
	}
	for participant, previous := range manager.retiredShares {
		loaded := restored.retiredShares[participant]
		if loaded == nil || !bytes.Equal(loaded.Encode(), previous.Encode()) {
			t.Fatal("retired generation was not preserved")
		}
	}
}

func TestMalformedShareImportPreservesCurrentState(t *testing.T) {
	manager := newPersistenceTestManager(t)
	before := append([]byte(nil), manager.qtdShares[1].S1ShareBytes...)
	key := manager.GroupPublicKey()
	if err := manager.ImportKeyShares([]byte{0, 1, 0, 0, 1, 0}); err == nil {
		t.Fatal("accepted truncated share")
	}
	if manager.ShareCount() != 3 || manager.qtdShares[1] == nil || !bytes.Equal(manager.qtdShares[1].S1ShareBytes, before) || !bytes.Equal(manager.GroupPublicKey(), key) {
		t.Fatal("failed import destroyed current signing state")
	}
}

func TestPublicOnlyReshareSnapshotDoesNotResurrectOldShares(t *testing.T) {
	manager := newPersistenceTestManager(t)
	if err := manager.RetireResharedShare([]int{4, 7}, 2); err != nil {
		t.Fatal(err)
	}
	if err := manager.RetireResharedShare([]int{5, 8}, 2); err != nil {
		t.Fatal(err)
	}
	manager.SetAllowPlaintextExport(true)
	data, err := manager.ExportKeyShares()
	if err != nil {
		t.Fatal(err)
	}
	restored := newPersistenceTestManager(t)
	if err := restored.ImportKeyShares(data); err != nil {
		t.Fatal(err)
	}
	if restored.ShareCount() != 0 || len(restored.retiredShares) != 0 || !reflect.DeepEqual(restored.ParticipantIDs(), []int{5, 8}) {
		t.Fatal("public-only snapshot restored private shares or lost current holders")
	}
}

func TestKeyStateRejectsTruncationWithoutMutation(t *testing.T) {
	manager := newPersistenceTestManager(t)
	manager.SetAllowPlaintextExport(true)
	data, err := manager.ExportKeyShares()
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), manager.qtdShares[1].S1ShareBytes...)
	for _, length := range []int{1, 10, 11, 18, len(data) / 2, len(data) - 1} {
		if err := manager.ImportKeyShares(data[:length]); err == nil {
			t.Fatalf("accepted truncated key state of length %d", length)
		}
		if manager.ShareCount() != 3 || !bytes.Equal(manager.qtdShares[1].S1ShareBytes, before) {
			t.Fatal("invalid snapshot changed existing state")
		}
	}
	if err := manager.ImportKeyShares(append(data, 0)); err == nil {
		t.Fatal("accepted trailing data")
	}
}

func TestKeyStateCannotDowngradeThresholdSecurity(t *testing.T) {
	manager := newPersistenceTestManager(t)
	manager.SetAllowPlaintextExport(true)
	data, err := manager.ExportKeyShares()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(data[len(keyStateMagic):], 1)
	if err := manager.ImportKeyShares(data); err == nil {
		t.Fatal("snapshot bypassed the minimum threshold")
	}
	if manager.Threshold() != 2 || manager.ShareCount() != 3 {
		t.Fatal("invalid threshold changed active state")
	}
}
