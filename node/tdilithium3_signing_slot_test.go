// Quantaureum Node source, version 1.0.0.
package node

// Tests of the node-side signing slot driver: four scripted slots exchange the
// four rounds through real transports, real inboxes, and the real TSS routing,
// with one injected drop that only the retransmission path can recover; and
// every path that cannot sign fails closed, consumes the slot's material, and
// refuses to run at all outside the gate.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// errSigningSlotTestStarved is the failure the scripted slot reports when it is
// closed before its exchange completed, and errSigningSlotTestDelivery is the
// injected delivery failure of the fatal path.
var (
	errSigningSlotTestStarved  = errors.New("scripted signing slot starved")
	errSigningSlotTestDelivery = errors.New("scripted signing delivery failure")
)

// tdilithium3SigningSlotTestSlot is a scripted slot: it queues its next round
// payload once its peers' messages of the current round arrived, and reports
// itself done after the response round. It exercises the driver's lifecycle
// without shares, which stay the wallet layer's concern.
type tdilithium3SigningSlotTestSlot struct {
	lock       sync.Mutex
	signature  []byte
	payloads   map[uint16][]byte
	started    bool
	burned     bool
	done       bool
	outbound   []dilithium3v1.SigningExecutorRoundMessage
	delivered  map[uint16]int
	deliverErr error
	finishErr  error
	filtered   bool
	terminal   bool
}

func newTDilithium3SigningSlotTestSlot(
	payloads map[uint16][]byte,
	signature []byte,
) *tdilithium3SigningSlotTestSlot {
	return &tdilithium3SigningSlotTestSlot{
		payloads: payloads, signature: signature, delivered: make(map[uint16]int),
	}
}

func (slot *tdilithium3SigningSlotTestSlot) Start() error {
	slot.lock.Lock()
	defer slot.lock.Unlock()
	slot.started = true
	slot.queueLocked(dilithium3v1.SigningExecutorKindCommit)
	return nil
}

func (slot *tdilithium3SigningSlotTestSlot) queueLocked(kind uint16) {
	slot.outbound = append(slot.outbound, dilithium3v1.SigningExecutorRoundMessage{
		Kind: kind, Payload: slot.payloads[kind],
	})
}

func (slot *tdilithium3SigningSlotTestSlot) Drain() []dilithium3v1.SigningExecutorRoundMessage {
	slot.lock.Lock()
	defer slot.lock.Unlock()
	queued := slot.outbound
	slot.outbound = nil
	return queued
}

func (slot *tdilithium3SigningSlotTestSlot) Deliver(senderID uint32, kind uint16, payload []byte) error {
	slot.lock.Lock()
	defer slot.lock.Unlock()
	if slot.deliverErr != nil {
		err := slot.deliverErr
		slot.deliverErr = nil
		return err
	}
	if slot.done {
		return nil
	}
	slot.delivered[kind]++
	if slot.delivered[kind] != 3 {
		return nil
	}
	switch kind {
	case dilithium3v1.SigningExecutorKindCommit:
		slot.queueLocked(dilithium3v1.SigningExecutorKindReveal)
	case dilithium3v1.SigningExecutorKindReveal:
		slot.queueLocked(dilithium3v1.SigningExecutorKindAcceptance)
	case dilithium3v1.SigningExecutorKindAcceptance:
		slot.queueLocked(dilithium3v1.SigningExecutorKindResponse)
	case dilithium3v1.SigningExecutorKindResponse:
		slot.done = true
	}
	return nil
}

func (slot *tdilithium3SigningSlotTestSlot) Done() bool {
	slot.lock.Lock()
	defer slot.lock.Unlock()
	return slot.done || slot.terminal
}

// Filtered scripts the slot's filter classification for the request schedule.
func (slot *tdilithium3SigningSlotTestSlot) Filtered() bool {
	slot.lock.Lock()
	defer slot.lock.Unlock()
	return slot.filtered
}

// scriptAccepted marks the slot done with its canned signature, so the driver
// closes it on its first Done check.
func (slot *tdilithium3SigningSlotTestSlot) scriptAccepted() {
	slot.lock.Lock()
	defer slot.lock.Unlock()
	slot.done = true
}

// scriptFinish arms the terminal outcome of a slot that never completes: the
// error Finish returns, the filter classification the schedule reads, and the
// terminal flag that makes the driver close it at once, the way a burned party
// does.
func (slot *tdilithium3SigningSlotTestSlot) scriptFinish(err error, filtered bool) {
	slot.lock.Lock()
	defer slot.lock.Unlock()
	slot.finishErr = err
	slot.filtered = filtered
	slot.terminal = true
}

func (slot *tdilithium3SigningSlotTestSlot) Finish() ([]byte, error) {
	slot.lock.Lock()
	defer slot.lock.Unlock()
	if slot.done && !slot.burned {
		return slot.signature, nil
	}
	slot.burned = true
	if slot.finishErr != nil {
		return nil, slot.finishErr
	}
	return nil, errSigningSlotTestStarved
}

func (slot *tdilithium3SigningSlotTestSlot) wasStarted() bool {
	slot.lock.Lock()
	defer slot.lock.Unlock()
	return slot.started
}

func (slot *tdilithium3SigningSlotTestSlot) wasBurned() bool {
	slot.lock.Lock()
	defer slot.lock.Unlock()
	return slot.burned
}

// failNextDelivery arms one delivery failure, the driver's fatal branch.
func (slot *tdilithium3SigningSlotTestSlot) failNextDelivery(err error) {
	slot.lock.Lock()
	defer slot.lock.Unlock()
	slot.deliverErr = err
}

// tdilithium3SigningSlotTestNode is one node of the in-process network.
type tdilithium3SigningSlotTestNode struct {
	node      *Node
	slot      *tdilithium3SigningSlotTestSlot
	transport *tdilithium3SigningTransport
	inbox     *tdilithium3SigningInbox
	driver    *tdilithium3SigningSlotDriver
	peer      p2p.PeerID
}

// tdilithium3SigningSlotTestNetwork routes broadcasts between the nodes through
// the real TSS message path, with an optional one-shot drop.
type tdilithium3SigningSlotTestNetwork struct {
	mu     sync.Mutex
	nodes  []*tdilithium3SigningSlotTestNode
	drop   func(from, to int, messageType uint8) bool
	routed int
}

func (network *tdilithium3SigningSlotTestNetwork) broadcast(from int, messageType uint8, encoded []byte) error {
	network.mu.Lock()
	nodes := append([]*tdilithium3SigningSlotTestNode(nil), network.nodes...)
	drop := network.drop
	network.routed++
	network.mu.Unlock()
	packet := p2p.PeerMessage{From: nodes[from].peer, Type: messageType, Payload: append([]byte(nil), encoded...)}
	for to := range nodes {
		if to == from {
			continue
		}
		if drop != nil && drop(from, to, messageType) {
			continue
		}
		nodes[to].node.handleTSSMessage(packet)
	}
	return nil
}

// tdilithium3SigningSlotTestDrop drops the first message of one kind from one
// sender to one receiver, so only a retransmission can recover it.
type tdilithium3SigningSlotTestDrop struct {
	mu               sync.Mutex
	from, to         int
	messageType      uint8
	used, didRecover bool
}

func (drop *tdilithium3SigningSlotTestDrop) shouldDrop(from, to int, messageType uint8) bool {
	drop.mu.Lock()
	defer drop.mu.Unlock()
	if drop.used || from != drop.from || to != drop.to || messageType != drop.messageType {
		return false
	}
	drop.used = true
	return true
}

// tdilithium3SigningSlotTestPayloads returns one canonical payload per round
// kind, the scripted content the transports encode.
func tdilithium3SigningSlotTestPayloads(t *testing.T) map[uint16][]byte {
	t.Helper()
	return map[uint16][]byte{
		dilithium3v1.SigningExecutorKindCommit: tdilithium3SigningTestPayload(
			t, p2p.MsgTypeTDilithium3SigningCommit,
		),
		dilithium3v1.SigningExecutorKindReveal: tdilithium3SigningTestPayload(
			t, p2p.MsgTypeTDilithium3SigningReveal,
		),
		dilithium3v1.SigningExecutorKindAcceptance: tdilithium3SigningTestPayload(
			t, p2p.MsgTypeTDilithium3SigningAcceptance,
		),
		dilithium3v1.SigningExecutorKindResponse: tdilithium3SigningTestPayload(
			t, p2p.MsgTypeTDilithium3SigningResponse,
		),
	}
}

// tdilithium3SigningSlotTestHarness is the four-node in-process network of one
// scripted slot: real transports, real inboxes, and the real TSS routing.
type tdilithium3SigningSlotTestHarness struct {
	network   *tdilithium3SigningSlotTestNetwork
	signature []byte
}

func tdilithium3SigningSlotTestHarnessFor(
	t *testing.T,
	drop *tdilithium3SigningSlotTestDrop,
) *tdilithium3SigningSlotTestHarness {
	t.Helper()
	fixture := tdilithium3SigningInboxTestFixtureFor(t)
	payloads := tdilithium3SigningSlotTestPayloads(t)
	signature := []byte("QAU-TDILITHIUM3-V1-SIGNING-SLOT-TEST")
	network := &tdilithium3SigningSlotTestNetwork{}
	if drop != nil {
		network.drop = drop.shouldDrop
	}
	for index, participantID := range fixture.context.Signers {
		node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
		inbox, err := newTDilithium3SigningInboxFromIdentitySnapshot(fixture.context, fixture.identities)
		if err != nil {
			t.Fatalf("signer %d: inbox: %v", participantID, err)
		}
		transport, err := newTDilithium3SigningTransport(
			fixture.context, participantID, fixture.signers[participantID],
			func(messageType uint8, encoded []byte) error {
				return network.broadcast(index, messageType, encoded)
			},
		)
		if err != nil {
			t.Fatalf("signer %d: transport: %v", participantID, err)
		}
		slot := newTDilithium3SigningSlotTestSlot(payloads, signature)
		driver, err := newTDilithium3SigningSlotDriver(node, slot, transport, inbox)
		if err != nil {
			t.Fatalf("signer %d: driver: %v", participantID, err)
		}
		driver.retransmit = 5 * time.Millisecond
		network.nodes = append(network.nodes, &tdilithium3SigningSlotTestNode{
			node: node, slot: slot, transport: transport, inbox: inbox, driver: driver,
			peer: fixture.identities[participantID].Peer,
		})
	}
	return &tdilithium3SigningSlotTestHarness{network: network, signature: signature}
}

// run starts every driver concurrently and returns the signatures and failures.
func (harness *tdilithium3SigningSlotTestHarness) run(
	t *testing.T,
	ctx context.Context,
) ([][]byte, []error) {
	t.Helper()
	signatures := make([][]byte, len(harness.network.nodes))
	failures := make([]error, len(harness.network.nodes))
	var wg sync.WaitGroup
	for index := range harness.network.nodes {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			signatures[index], failures[index] = harness.network.nodes[index].driver.run(ctx)
		}(index)
	}
	wg.Wait()
	return signatures, failures
}

// TestTDilithium3SigningSlotDriverCompletesTheExchange requires the four
// drivers of one slot to complete an honest exchange over the real routing,
// with one dropped reveal that only a retransmission recovers, and to close
// every inbox and consume every sequence afterward.
func TestTDilithium3SigningSlotDriverCompletesTheExchange(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	drop := &tdilithium3SigningSlotTestDrop{from: 0, to: 2, messageType: p2p.MsgTypeTDilithium3SigningReveal}
	harness := tdilithium3SigningSlotTestHarnessFor(t, drop)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	signatures, failures := harness.run(t, ctx)

	drop.mu.Lock()
	used := drop.used
	drop.mu.Unlock()
	if !used {
		t.Fatal("the injected drop never fired")
	}
	for index, node := range harness.network.nodes {
		if failures[index] != nil {
			t.Fatalf("signer %d: run: %v", index, failures[index])
		}
		if string(signatures[index]) != string(harness.signature) {
			t.Fatalf("signer %d: signature %q, want %q", index, signatures[index], harness.signature)
		}
		if node.node.tdilithium3SigningInboxSnapshot() != nil {
			t.Fatalf("signer %d: inbox was not cleared", index)
		}
		if node.transport.Sequence() != 4 {
			t.Fatalf("signer %d: sequence %d, want 4", index, node.transport.Sequence())
		}
	}
}

// TestTDilithium3SigningSlotDriverEndsOnFatalDelivery requires a delivery the
// slot refuses to end that slot with its cause and consume its material, so
// the remaining nodes cannot complete the exchange either.
func TestTDilithium3SigningSlotDriverEndsOnFatalDelivery(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	harness := tdilithium3SigningSlotTestHarnessFor(t, nil)
	faulty := harness.network.nodes[2]
	faulty.slot.failNextDelivery(errSigningSlotTestDelivery)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, failures := harness.run(t, ctx)

	if !errors.Is(failures[2], errSigningSlotTestDelivery) {
		t.Fatalf("faulty signer: error = %v", failures[2])
	}
	if !faulty.slot.wasBurned() {
		t.Fatal("fatal delivery left the material live")
	}
	for index := range harness.network.nodes {
		if index == 2 {
			continue
		}
		if failures[index] == nil {
			t.Fatalf("signer %d completed a slot whose signer 2 died", index)
		}
	}
}

// TestTDilithium3SigningSlotDriverFailsClosed requires every path that cannot
// sign to close the slot and consume its material, and requires the driver to
// refuse a mainnet node, a closed gate, an unbounded context, and mismatched
// wiring before the slot starts.
func TestTDilithium3SigningSlotDriverFailsClosed(t *testing.T) {
	fixture := tdilithium3SigningInboxTestFixtureFor(t)
	payloads := tdilithium3SigningSlotTestPayloads(t)
	newHarness := func(t *testing.T, networkID uint64, broadcast func(uint8, []byte) error) (*tdilithium3SigningSlotTestSlot, *tdilithium3SigningSlotDriver) {
		t.Helper()
		node := &Node{config: &Config{NetworkID: networkID}}
		inbox, err := newTDilithium3SigningInboxFromIdentitySnapshot(fixture.context, fixture.identities)
		if err != nil {
			t.Fatal(err)
		}
		transport, err := newTDilithium3SigningTransport(
			fixture.context, fixture.context.Signers[0], fixture.signers[fixture.context.Signers[0]], broadcast,
		)
		if err != nil {
			t.Fatal(err)
		}
		slot := newTDilithium3SigningSlotTestSlot(payloads, []byte("unused"))
		driver, err := newTDilithium3SigningSlotDriver(node, slot, transport, inbox)
		if err != nil {
			t.Fatal(err)
		}
		driver.retransmit = 5 * time.Millisecond
		return slot, driver
	}
	silent := func(uint8, []byte) error { return nil }

	t.Run("starved slot", func(t *testing.T) {
		t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
		slot, driver := newHarness(t, TestnetNetworkID, silent)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		if _, err := driver.run(ctx); err == nil {
			t.Fatal("starved slot produced a signature")
		}
		if !slot.wasBurned() {
			t.Fatal("starved slot left its material live")
		}
	})

	t.Run("send failure", func(t *testing.T) {
		t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
		slot, driver := newHarness(t, TestnetNetworkID, func(uint8, []byte) error {
			return errSigningSlotTestStarved
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := driver.run(ctx); !errors.Is(err, errSigningSlotTestStarved) {
			t.Fatalf("send failure: error = %v", err)
		}
		if !slot.wasBurned() {
			t.Fatal("failed send left the material live")
		}
	})

	t.Run("mainnet", func(t *testing.T) {
		t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
		slot, driver := newHarness(t, MainnetNetworkID, silent)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := driver.run(ctx); err == nil {
			t.Fatal("mainnet node drove a signing slot")
		}
		if slot.wasStarted() || slot.wasBurned() {
			t.Fatal("mainnet refusal touched the slot")
		}
	})

	t.Run("gate closed", func(t *testing.T) {
		t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "0")
		slot, driver := newHarness(t, TestnetNetworkID, silent)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := driver.run(ctx); err == nil {
			t.Fatal("closed gate drove a signing slot")
		}
		if slot.wasStarted() || slot.wasBurned() {
			t.Fatal("closed gate refusal touched the slot")
		}
	})

	t.Run("unbounded context", func(t *testing.T) {
		t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
		slot, driver := newHarness(t, TestnetNetworkID, silent)
		if _, err := driver.run(context.Background()); err == nil {
			t.Fatal("unbounded context drove a signing slot")
		}
		if slot.wasStarted() {
			t.Fatal("unbounded context refusal touched the slot")
		}
	})

	t.Run("mismatched wiring", func(t *testing.T) {
		t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
		node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
		foreign := fixture.context
		foreign.SessionID = [32]byte{0x99}
		inbox, err := newTDilithium3SigningInboxFromIdentitySnapshot(foreign, fixture.identities)
		if err != nil {
			t.Fatal(err)
		}
		transport, err := newTDilithium3SigningTransport(
			fixture.context, fixture.context.Signers[0], fixture.signers[fixture.context.Signers[0]], silent,
		)
		if err != nil {
			t.Fatal(err)
		}
		slot := newTDilithium3SigningSlotTestSlot(payloads, []byte("unused"))
		if _, err := newTDilithium3SigningSlotDriver(node, slot, transport, inbox); err == nil {
			t.Fatal("mismatched transport and inbox accepted")
		}
	})
}
