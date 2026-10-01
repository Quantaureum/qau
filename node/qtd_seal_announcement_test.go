// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestQTDSealAnnouncementRoundTrip(t *testing.T) {
	root := types.Hash{7}
	signature := bytes.Repeat([]byte{9}, 3293)
	sealers := []int{0, 8}
	payload, err := encodeQTDSealAnnouncement(37, root, signature, sealers)
	if err != nil {
		t.Fatal(err)
	}
	slot, decodedRoot, decodedSignature, decodedSealers, err := decodeQTDSealAnnouncement(payload)
	if err != nil {
		t.Fatal(err)
	}
	if slot != 37 || decodedRoot != root || !bytes.Equal(signature, decodedSignature) || !reflect.DeepEqual(sealers, decodedSealers) {
		t.Fatal("announcement did not round trip")
	}
	for length := 0; length < len(payload); length++ {
		if _, _, _, _, err := decodeQTDSealAnnouncement(payload[:length]); err == nil {
			t.Fatalf("accepted truncated frame at %d", length)
		}
	}
	if _, _, _, _, err := decodeQTDSealAnnouncement(append(payload, 0)); err == nil {
		t.Fatal("accepted trailing bytes")
	}
	binary.BigEndian.PutUint32(payload[len(payload)-4:], 0)
	if _, _, _, _, err := decodeQTDSealAnnouncement(payload); err == nil {
		t.Fatal("accepted duplicate sealers")
	}
}

func TestQTDSealAnnouncementRejectsInvalidDimensions(t *testing.T) {
	for _, sealers := range [][]int{nil, {-1}, {1, 1}, make([]int, 65)} {
		if _, err := encodeQTDSealAnnouncement(1, types.Hash{1}, []byte{1}, sealers); err == nil {
			t.Fatalf("accepted invalid sealers %v", sealers)
		}
	}
	for _, signature := range [][]byte{nil, make([]byte, 4097)} {
		if _, err := encodeQTDSealAnnouncement(1, types.Hash{1}, signature, []int{1}); err == nil {
			t.Fatal("accepted invalid signature size")
		}
	}
}
