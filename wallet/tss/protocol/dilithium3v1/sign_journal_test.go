// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"go.etcd.io/bbolt"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestSigningJournalBurnsUnfinishedSessionsOnReopen(t *testing.T) {
	states := []protocol.SingleUseState{
		protocol.SingleUsePrepared, protocol.SingleUseCommitted,
		protocol.SingleUseResponded, protocol.SingleUseFinalized,
	}
	path := filepath.Join(t.TempDir(), "signing", "journal.db")
	journal, err := OpenSigningJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	for position, state := range states {
		var sessionID [32]byte
		sessionID[0] = byte(position + 1)
		for _, next := range states {
			if next > state {
				break
			}
			if _, err := journal.Advance(sessionID, next, []byte("DEVNET ONLY private nonce material")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenSigningJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	for position, state := range states {
		var sessionID [32]byte
		sessionID[0] = byte(position + 1)
		record, found, err := journal.Read(sessionID)
		if err != nil || !found {
			t.Fatalf("recovered record %d: found=%v err=%v", position, found, err)
		}
		want := protocol.SingleUseBurned
		if state == protocol.SingleUseFinalized {
			want = state
		}
		if record.State != want || record.Protocol != protocol.ThresholdProtocolDilithium3V1 {
			t.Fatalf("record %d: state=%v protocol=%v", position, record.State, record.Protocol)
		}
		if _, err := journal.Advance(sessionID, protocol.SingleUseCommitted, []byte("replay")); err == nil {
			t.Fatal("replayed session accepted")
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte("DEVNET ONLY private nonce material")) {
		t.Fatal("journal retained plaintext preprocessing material")
	}
}

func TestSigningJournalRejectsReplayAndConcurrentOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.db")
	journal, err := OpenSigningJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	var sessionID [32]byte
	sessionID[0] = 1
	prepared, err := journal.Advance(sessionID, protocol.SingleUsePrepared, []byte("first"))
	if err != nil || prepared.State != protocol.SingleUsePrepared {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := journal.Advance(sessionID, protocol.SingleUsePrepared, []byte("second")); err == nil {
		t.Fatal("nonce reuse accepted")
	}
	stored, found, err := journal.Read(sessionID)
	if err != nil || !found || stored != prepared {
		t.Fatalf("failed transition changed durable state: found=%v err=%v", found, err)
	}
	if _, err := OpenSigningJournal(path); err == nil {
		t.Fatal("second process could bypass the file lock")
	}
}

func TestSigningJournalRejectsCorruptRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.db")
	journal, err := OpenSigningJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	var sessionID [32]byte
	sessionID[0] = 1
	if err := journal.db.Update(func(transaction *bbolt.Tx) error {
		return transaction.Bucket(signingJournalBucket).Put(sessionID[:], []byte("corrupt"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSigningJournal(path); err == nil {
		t.Fatal("corrupt record accepted on recovery")
	}
}

func TestSigningJournalRejectsTamperedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.db")
	journal, err := OpenSigningJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	var sessionID [32]byte
	sessionID[0] = 3
	if _, err := journal.Advance(sessionID, protocol.SingleUsePrepared, []byte("nonce")); err != nil {
		t.Fatal(err)
	}
	if err := journal.db.Update(func(transaction *bbolt.Tx) error {
		bucket := transaction.Bucket(signingJournalBucket)
		encoded := append([]byte(nil), bucket.Get(sessionID[:])...)
		encoded[80] ^= 1
		return bucket.Put(sessionID[:], encoded)
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Read(sessionID); err == nil {
		t.Fatal("tampered record was readable")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSigningJournal(path); err == nil {
		t.Fatal("tampered record recovered on reopen")
	}
}

func TestSigningJournalCrashRecoveryAcrossProcesses(t *testing.T) {
	if os.Getenv("QAU_TEST_SIGNING_JOURNAL_HELPER") == "1" {
		journal, err := OpenSigningJournal(os.Getenv("QAU_TEST_SIGNING_JOURNAL_PATH"))
		if err != nil {
			t.Fatal(err)
		}
		var sessionID [32]byte
		sessionID[0] = 7
		if _, err := journal.Advance(sessionID, protocol.SingleUsePrepared, []byte("private nonce")); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.Advance(sessionID, protocol.SingleUseCommitted, []byte("public commitment")); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(os.Stdout, "ready")
		_, _ = bufio.NewReader(os.Stdin).ReadByte()
		return
	}
	path := filepath.Join(t.TempDir(), "signing.db")
	command := exec.Command(os.Args[0], "-test.run=^TestSigningJournalCrashRecoveryAcrossProcesses$")
	command.Env = append(os.Environ(), "QAU_TEST_SIGNING_JOURNAL_HELPER=1", "QAU_TEST_SIGNING_JOURNAL_PATH="+path)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = input.Close()
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	ready, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || ready != "ready\n" {
		t.Fatalf("helper startup: ready=%q err=%v", ready, err)
	}
	if _, err := OpenSigningJournal(path); err == nil {
		t.Fatal("process lock bypassed")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	journal, err := OpenSigningJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	var sessionID [32]byte
	sessionID[0] = 7
	recovered, found, err := journal.Read(sessionID)
	if err != nil || !found || recovered.State != protocol.SingleUseBurned {
		t.Fatalf("committed nonce recovered: found=%v state=%v err=%v", found, recovered.State, err)
	}
}
