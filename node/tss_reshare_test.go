// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/wallet/tss"

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

func TestReshareExpansionDoesNotRequireNewThresholdOldHolders(t *testing.T) {
	config := tss.DefaultTSSConfig()
	config.Threshold, config.TotalShares = 2, 2
	manager, err := tss.NewTSSManager(config)
	if err != nil {
		t.Fatal(err)
	}
	node := &Node{tssManager: manager, blockProducer: &BlockProducer{}}
	_, err = node.runDistributedReshare(2, []int{1, 2}, []int{4, 7, 11}, 3)
	if err == nil || !strings.Contains(err.Error(), "local validator participant ID") {
		t.Fatalf("valid expansion did not reach local identity validation: %v", err)
	}
}

func TestP2PReshareTransportWaitReportsMissingParticipants(t *testing.T) {
	transport := NewP2PReshareTransport(nil, 2, []byte("session"))
	transport.waitTimeout = 10 * time.Millisecond
	transport.Ingest(&reshareWireMessage{
		SessionID:       []byte("session"),
		FromParticipant: 1,
		ToParticipant:   2,
		Contribution: &qtd.SubShare{
			FromParticipant: 1,
			ToParticipant:   2,
		},
	})
	transport.Ingest(&reshareWireMessage{
		SessionID:       []byte("session"),
		FromParticipant: 3,
		ToParticipant:   2,
		Contribution: &qtd.SubShare{
			FromParticipant: 3,
			ToParticipant:   2,
		},
	})

	_, err := transport.Wait(context.Background(), []int{1, 2, 3, 4})
	if err == nil {
		t.Fatal("Wait returned nil error with a missing contribution")
	}
	if !strings.Contains(err.Error(), "received 2/3 contributions") {
		t.Fatalf("Wait error = %q, want accurate received count", err)
	}
	if !strings.Contains(err.Error(), "missing participants [4]") {
		t.Fatalf("Wait error = %q, want missing participant list", err)
	}
}
