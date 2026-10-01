// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"bytes"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

func TestAuthenticatedTSSMessagesInSameSecond(t *testing.T) {
	senderAddress := generateTestAddress(0x11)
	receiverAddress := generateTestAddress(0x22)
	senderKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sender, err := NewValidatorKeyExchange(senderAddress)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewValidatorKeyExchange(receiverAddress)
	if err != nil {
		t.Fatal(err)
	}
	signer := &testTSSAuthSigner{localPriv: senderKey.Private, pubKeys: map[types.Address]*crypto.PublicKey{senderAddress: senderKey.Public}}
	sender.SetAuthSigner(signer)
	receiver.SetAuthSigner(signer)
	senderPublic, err := sender.LocalKyberPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	receiverPublic, err := receiver.LocalKyberPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.RegisterKyberKey(receiverAddress, receiverPublic); err != nil {
		t.Fatal(err)
	}
	if err := receiver.RegisterKyberKey(senderAddress, senderPublic); err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{[]byte("round two session one"), []byte("round two session two"), []byte("round two session three")}
	ciphertexts := make([][]byte, len(payloads))
	ready := false
	for attempt := 0; attempt < 4; attempt++ {
		started := time.Now().Unix()
		for index, payload := range payloads {
			ciphertexts[index], err = sender.SealForPeer(receiverAddress, payload)
			if err != nil {
				t.Fatal(err)
			}
		}
		if time.Now().Unix() == started {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("could not create messages in one timestamp interval")
	}
	for index := 0; index < 2; index++ {
		opened, err := receiver.OpenFromPeer(senderAddress, ciphertexts[index])
		if err != nil || !bytes.Equal(opened, payloads[index]) {
			t.Fatalf("distinct same-second message %d rejected: %v", index, err)
		}
	}
	if _, err := receiver.OpenFromPeer(senderAddress, ciphertexts[0]); err == nil {
		t.Fatal("accepted replay of an authenticated message")
	}
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for attempt := 0; attempt < 8; attempt++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := receiver.OpenFromPeer(senderAddress, ciphertexts[2]); err == nil {
				accepted.Add(1)
			}
		}()
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("concurrent delivery accepted %d copies, want exactly one", accepted.Load())
	}
	for index := 0; index < maxTSSReplayEntries; index++ {
		var digest [32]byte
		binary.BigEndian.PutUint64(digest[:8], uint64(index))
		receiver.peerMessageDigests[digest] = time.Now().Unix()
	}
	boundedSize := len(receiver.peerMessageDigests)
	additional, err := sender.SealForPeer(receiverAddress, []byte("bounded replay cache message"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.OpenFromPeer(senderAddress, additional); err == nil {
		t.Fatal("full replay cache did not fail closed")
	}
	if len(receiver.peerMessageDigests) != boundedSize {
		t.Fatal("full replay cache grew")
	}
	for digest := range receiver.peerMessageDigests {
		receiver.peerMessageDigests[digest] = time.Now().Add(-6 * time.Minute).Unix()
	}
	if _, err := receiver.OpenFromPeer(senderAddress, additional); err != nil {
		t.Fatalf("expired replay entries blocked a fresh authenticated message: %v", err)
	}
	if len(receiver.peerMessageDigests) != 1 {
		t.Fatalf("replay cache retained expired entries: %d", len(receiver.peerMessageDigests))
	}
}
