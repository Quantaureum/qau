// Quantaureum Node source, version 1.0.0.
package node

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/consensus"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// Dilithium3 DKG cross-process group test runs the canonical RSS ceremony over
// six real p2p.Host instances living in six separate operating-system
// processes. Every group seed, published contribution and acknowledgement
// travels through a real TCP connection, the real encrypted transport, the real
// protocol registry and the real inbound validation, so the test covers the
// transport contract the in-process harness can only simulate.
//
// The child processes are the same test binary re-executed with a helper
// environment variable. Each child owns one participant position, derives the
// deterministic DEVNET-only identities locally (no private key ever crosses the
// wire), and drives the shared phase schedule the parent hands out over stdin.
// All randomness comes from a per-position deterministic reader, so the whole
// transcript — not just internal agreement — is reproducible and must match the
// in-process reference computed by the parent.

const (
	tdilithium3DKGCrossProcessHelperEnv = "QAU_TEST_TDILITHIUM3_DKG_P2P_HELPER"
	tdilithium3DKGCrossProcessRootEnv   = "QAU_TEST_TDILITHIUM3_DKG_P2P_ROOT"
	tdilithium3DKGCrossProcessIndexEnv  = "QAU_TEST_TDILITHIUM3_DKG_P2P_INDEX"

	// tdilithium3DKGCeremonyHelperEnv selects the production-entry-point helper
	// process, which drives runTDilithium3DKGCeremony instead of the raw group
	// machinery.
	tdilithium3DKGCeremonyHelperEnv = "QAU_TEST_TDILITHIUM3_DKG_CEREMONY_HELPER"

	tdilithium3DKGCrossProcessPositions = 6

	// tdilithium3DKGCrossProcessPhaseTimeout bounds one synchronised protocol
	// phase across all six children.
	tdilithium3DKGCrossProcessPhaseTimeout = 240 * time.Second
)

// tdilithium3DKGCrossProcessSession returns the deterministic DKG session shared
// by the parent and every child. It mirrors testTDilithium3DKGRunners so the
// cross-process transcript can be compared against the in-process reference.
func tdilithium3DKGCrossProcessSession(t *testing.T) dilithium3v1.DKGSession {
	t.Helper()
	session := dilithium3v1.DKGSession{
		Protocol:        protocol.ThresholdProtocolDilithium3V1,
		ChainID:         1669,
		KeyGeneration:   1,
		Committee:       protocol.CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{101, 102, 103, 104, 105, 106}},
		ActivationEpoch: 7,
		Nonce:           [32]byte{1, 2, 3},
	}
	session.IdentityRosterDigest = testTDilithium3IdentityRosterDigest(t, session, "DEVNET ONLY live DKG identity")
	return session
}

// tdilithium3DKGCrossProcessSeed derives the DEVNET-only Dilithium3 identity
// seed of one committee position. It is public test material: the same literal
// is used by the in-process harness, so both paths authenticate the same keys.
func tdilithium3DKGCrossProcessSeed(position int) [mode3.SeedSize]byte {
	var seed [mode3.SeedSize]byte
	copy(seed[:], fmt.Sprintf("DEVNET ONLY live DKG identity %d", position))
	return seed
}

func tdilithium3DKGCrossProcessIdentity(position int) (*mode3.PrivateKey, types.Address) {
	seed := tdilithium3DKGCrossProcessSeed(position)
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	return privateKey, types.AddressFromPublicKey(publicKey.Bytes())
}

// tdilithium3DKGCrossProcessChild is one helper process plus the pipes used to
// schedule it.
type tdilithium3DKGCrossProcessChild struct {
	command *exec.Cmd
	input   io.WriteCloser
	index   int
	// waited records that exec.Cmd.Wait was already handed to wait(), which may
	// only be called once.
	waited bool
	// lines carries the helper protocol lines. The reader goroutine closes it
	// once the child's stdout reaches EOF, so a child that prints its last line
	// and exits immediately still has every buffered line delivered before the
	// parent observes the exit.
	lines  chan string
	stderr bytes.Buffer

	// mu guards tail and readErr, diagnostics for a child that never produced the
	// expected line.
	mu      sync.Mutex
	tail    []string
	readErr error
}

func (child *tdilithium3DKGCrossProcessChild) record(line string) {
	child.mu.Lock()
	defer child.mu.Unlock()
	child.tail = append(child.tail, line)
	if len(child.tail) > 400 {
		child.tail = append([]string(nil), child.tail[len(child.tail)-400:]...)
	}
}

func (child *tdilithium3DKGCrossProcessChild) diagnostics() string {
	child.mu.Lock()
	defer child.mu.Unlock()
	return fmt.Sprintf("stdout:\n%s\nstderr:\n%s", strings.Join(child.tail, "\n"), child.stderr.String())
}

func (child *tdilithium3DKGCrossProcessChild) stdoutError() error {
	child.mu.Lock()
	defer child.mu.Unlock()
	return child.readErr
}

func (child *tdilithium3DKGCrossProcessChild) write(t *testing.T, line string) {
	t.Helper()
	if _, err := io.WriteString(child.input, line+"\n"); err != nil {
		t.Fatalf("child %d: write %q: %v\n%s", child.index, line, err, child.diagnostics())
	}
}

// readLine returns the next child output line carrying the wanted prefix,
// discarding any interleaved log lines the node logger writes to stdout.
func (child *tdilithium3DKGCrossProcessChild) readLine(t *testing.T, prefix string, timeout time.Duration) string {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-child.lines:
			if !ok {
				t.Fatalf("child %d exited before printing %q (%v)\n%s", child.index, prefix, child.stdoutError(), child.diagnostics())
			}
			if strings.HasPrefix(strings.TrimSpace(line), prefix) {
				return line
			}
		case <-deadline:
			t.Fatalf("child %d did not print %q within %s\n%s", child.index, prefix, timeout, child.diagnostics())
		}
	}
}

func (child *tdilithium3DKGCrossProcessChild) stop() {
	_ = child.input.Close()
	// exec.Cmd.Wait may run only once. If wait() already owns it, just make sure
	// the process is gone; killing an already-reaped process is a harmless error.
	if child.waited {
		_ = child.command.Process.Kill()
		return
	}
	_ = child.command.Process.Kill()
	_ = child.command.Wait()
}

// wait reaps the helper process, giving up after timeout so that a regression in
// the shutdown path fails the test instead of hanging it.
func (child *tdilithium3DKGCrossProcessChild) wait(timeout time.Duration) error {
	child.waited = true
	done := make(chan error, 1)
	go func() { done <- child.command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("helper process did not exit within %s", timeout)
	}
}

// TestTDilithium3DKGGroupP2PCrossProcess drives the twenty canonical RSS groups
// across six processes and requires every process to assemble the same mode3
// public key and transcript digest as the in-process reference run.
func TestTDilithium3DKGGroupP2PCrossProcess(t *testing.T) {
	if os.Getenv(tdilithium3DKGCrossProcessHelperEnv) == "1" {
		runTDilithium3DKGGroupP2PChild(t)
		return
	}
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")

	root := t.TempDir()
	children := make([]*tdilithium3DKGCrossProcessChild, tdilithium3DKGCrossProcessPositions)
	defer func() {
		for _, child := range children {
			if child != nil {
				child.stop()
			}
		}
	}()

	peerByPosition := [tdilithium3DKGCrossProcessPositions]p2p.PeerID{}
	addrByPosition := [tdilithium3DKGCrossProcessPositions]string{}
	for index := range children {
		child := tdilithium3DKGCrossProcessStartChild(t, index, root,
			"^TestTDilithium3DKGGroupP2PCrossProcess$", tdilithium3DKGCrossProcessHelperEnv)
		children[index] = child
		ready := strings.Fields(child.readLine(t, "ready ", tdilithium3DKGCrossProcessPhaseTimeout))
		if len(ready) != 4 {
			t.Fatalf("child %d: malformed ready line %q", index, strings.Join(ready, " "))
		}
		reported, err := strconv.Atoi(ready[1])
		if err != nil || reported != index {
			t.Fatalf("child %d reported index %q", index, ready[1])
		}
		peerByPosition[index] = p2p.PeerID(ready[2])
		addrByPosition[index] = ready[3]
	}
	for index := 0; index < tdilithium3DKGCrossProcessPositions; index++ {
		for other := index + 1; other < tdilithium3DKGCrossProcessPositions; other++ {
			if peerByPosition[index] == peerByPosition[other] {
				t.Fatalf("children %d and %d share peer identity %s", index, other, peerByPosition[index])
			}
			if addrByPosition[index] == addrByPosition[other] {
				t.Fatalf("children %d and %d listen on the same address", index, other)
			}
		}
	}

	table := &bytes.Buffer{}
	for position := 0; position < tdilithium3DKGCrossProcessPositions; position++ {
		fmt.Fprintf(table, "peer %d %s %s\n", position, peerByPosition[position], addrByPosition[position])
	}
	for _, child := range children {
		child.write(t, strings.TrimRight(table.String(), "\n"))
		child.write(t, "start")
	}

	// The randomness round must not overlap the group phase: a group message
	// arriving while a node is still revealing randomness is a phase violation,
	// so the parent releases the group phase only once all six children have
	// finished revealing. The group drivers themselves tolerate skew (messages
	// for a group a node has not reached yet are retained), so the twenty groups
	// then run unsynchronised on purpose.
	for _, child := range children {
		child.readLine(t, fmt.Sprintf("randomness %d", child.index), tdilithium3DKGCrossProcessPhaseTimeout)
	}
	for _, child := range children {
		child.write(t, "groups")
	}

	outcomes := [tdilithium3DKGCrossProcessPositions]tdilithium3DKGCrossProcessOutcome{}
	for _, child := range children {
		line := strings.Fields(child.readLine(t, fmt.Sprintf("result %d ", child.index), tdilithium3DKGCrossProcessPhaseTimeout))
		if len(line) != 4 {
			t.Fatalf("child %d: malformed result line %q", child.index, strings.Join(line, " "))
		}
		outcomes[child.index] = tdilithium3DKGCrossProcessParseOutcome(t, child.index, line[2], line[3])
	}
	for _, child := range children {
		if err := child.input.Close(); err != nil {
			t.Fatalf("child %d: close stdin: %v", child.index, err)
		}
		if err := child.wait(tdilithium3DKGCrossProcessPhaseTimeout); err != nil {
			t.Fatalf("child %d exited with %v\n%s", child.index, err, child.diagnostics())
		}
	}
	for index := 1; index < tdilithium3DKGCrossProcessPositions; index++ {
		if outcomes[index].publicKey != outcomes[0].publicKey {
			t.Fatalf("child %d assembled a different mode3 public key", index)
		}
		if outcomes[index].transcriptDigest != outcomes[0].transcriptDigest {
			t.Fatalf("child %d assembled a different transcript digest", index)
		}
	}

	// Every child must commit the same exact-epoch activation certificate. The
	// certificate binds all six signed activation acknowledgements against the
	// assembled committee key, so agreement proves the six processes reached
	// activation over the real transport instead of only agreeing on a public key.
	activationDigests := [tdilithium3DKGCrossProcessPositions][32]byte{}
	for _, child := range children {
		line := strings.Fields(child.readLine(t, fmt.Sprintf("activation %d ", child.index), tdilithium3DKGCrossProcessPhaseTimeout))
		if len(line) != 3 {
			t.Fatalf("child %d: malformed activation line %q", child.index, strings.Join(line, " "))
		}
		digest, err := hex.DecodeString(line[2])
		if err != nil || len(digest) != 32 {
			t.Fatalf("child %d: malformed activation certificate digest %q", child.index, line[2])
		}
		copy(activationDigests[child.index][:], digest)
	}
	for index := 1; index < tdilithium3DKGCrossProcessPositions; index++ {
		if activationDigests[index] != activationDigests[0] {
			t.Fatalf("child %d committed a different activation certificate", index)
		}
	}

	reference := tdilithium3DKGCrossProcessInProcessReference(t)
	if reference.publicKey != outcomes[0].publicKey || reference.transcriptDigest != outcomes[0].transcriptDigest {
		t.Fatalf("cross-process transcript diverged from the in-process reference")
	}
}

func tdilithium3DKGCrossProcessStartChild(t *testing.T, index int, root, testRun, helperEnv string) *tdilithium3DKGCrossProcessChild {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run="+testRun)
	command.Env = append(os.Environ(),
		helperEnv+"=1",
		tdilithium3DKGCrossProcessRootEnv+"="+root,
		tdilithium3DKGCrossProcessIndexEnv+"="+strconv.Itoa(index),
		"QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1=1",
	)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child := &tdilithium3DKGCrossProcessChild{
		command: command, input: input, index: index,
		lines: make(chan string, 256),
	}
	command.Stderr = &child.stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(child.lines)
		reader := bufio.NewReader(output)
		for {
			line, err := reader.ReadString('\n')
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				child.record(trimmed)
			}
			if tdilithium3DKGCrossProcessProtocolLine(line) {
				select {
				case child.lines <- line:
				default:
				}
			}
			if err != nil {
				child.mu.Lock()
				child.readErr = err
				child.mu.Unlock()
				return
			}
		}
	}()
	return child
}

// tdilithium3DKGCrossProcessProtocolLine reports whether one stdout line is part
// of the helper protocol rather than node log output. The node logger writes to
// stdout, so the parent must ignore log lines instead of flooding the hand-off
// channel and dropping a scheduled protocol line.
func tdilithium3DKGCrossProcessProtocolLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	for _, prefix := range []string{"ready ", "randomness ", "result ", "activation ", "ceremony ", "failure "} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

type tdilithium3DKGCrossProcessOutcome struct {
	publicKey        [1952]byte
	transcriptDigest [32]byte
}

func tdilithium3DKGCrossProcessParseOutcome(t *testing.T, index int, publicKeyHex, transcriptHex string) tdilithium3DKGCrossProcessOutcome {
	t.Helper()
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(publicKey) != 1952 {
		t.Fatalf("child %d: malformed mode3 public key (%d bytes): %v", index, len(publicKey), err)
	}
	transcript, err := hex.DecodeString(transcriptHex)
	if err != nil || len(transcript) != 32 {
		t.Fatalf("child %d: malformed transcript digest (%d bytes): %v", index, len(transcript), err)
	}
	var outcome tdilithium3DKGCrossProcessOutcome
	copy(outcome.publicKey[:], publicKey)
	copy(outcome.transcriptDigest[:], transcript)
	return outcome
}

// tdilithium3DKGCrossProcessInProcessReference reproduces the same ceremony with
// the in-process harness and returns the reference transcript. Both paths share
// the deterministic session, identities and entropy, so any divergence is a real
// protocol difference rather than a timing artefact.
func tdilithium3DKGCrossProcessInProcessReference(t *testing.T) tdilithium3DKGCrossProcessOutcome {
	t.Helper()
	session := tdilithium3DKGCrossProcessSession(t)
	harness := newTDilithium3DKGNetworkHarness(t)
	harnessDigest, err := harness.runners[0].session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if harnessDigest != expectedDigest {
		t.Fatal("in-process harness session drifted from the cross-process session")
	}
	ctx, cancel := context.WithTimeout(context.Background(), tdilithium3DKGCrossProcessPhaseTimeout)
	defer cancel()
	harness.mustCompleteRandomness(t, ctx)
	for _, group := range dilithium3v1.CanonicalRSSGroups() {
		for position, err := range harness.runNetworkPhase(ctx, func(ctx context.Context, position int) error {
			return harness.runGroup(ctx, position, group)
		}) {
			if err != nil {
				t.Fatalf("reference node %d group %06b: %v", position, group, err)
			}
		}
	}
	result, err := tdilithium3DKGFinalize(harness.runners[0])
	if err != nil {
		t.Fatal(err)
	}
	return tdilithium3DKGCrossProcessOutcome{publicKey: result.PublicKey, transcriptDigest: result.TranscriptDigest}
}

// runTDilithium3DKGGroupP2PChild is the helper-process half of the test. It owns
// exactly one committee position and one real p2p.Host, and mirrors the phase
// schedule the parent hands out.
func runTDilithium3DKGGroupP2PChild(t *testing.T) {
	if !experimentalTDilithium3V1Enabled() {
		t.Fatal("child requires the experimental Dilithium3 v1 gates")
	}
	index, err := strconv.Atoi(os.Getenv(tdilithium3DKGCrossProcessIndexEnv))
	if err != nil || index < 0 || index >= tdilithium3DKGCrossProcessPositions {
		t.Fatalf("child index %q is invalid", os.Getenv(tdilithium3DKGCrossProcessIndexEnv))
	}
	root := os.Getenv(tdilithium3DKGCrossProcessRootEnv)
	if root == "" {
		t.Fatal("child requires a working root")
	}
	position := uint8(index)
	session := tdilithium3DKGCrossProcessSession(t)

	host, err := p2p.NewHost(&p2p.Config{
		ListenAddr:      "127.0.0.1:0",
		DevMode:         true,
		NetworkID:       TestnetNetworkID,
		MaxPeers:        8,
		MaxInboundPeers: 8,
		EnableDHT:       false,
		NodeKeyPath:     filepath.Join(root, "p2p", strconv.Itoa(index), "nodekey"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}

	stdout := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(stdout, "ready %d %s %s\n", index, host.ID(), host.Addr())
	if err := stdout.Flush(); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(os.Stdin)
	peerByPosition := [tdilithium3DKGCrossProcessPositions]p2p.PeerID{}
	addrByPosition := [tdilithium3DKGCrossProcessPositions]string{}
	for entry := 0; entry < tdilithium3DKGCrossProcessPositions; entry++ {
		fields := strings.Fields(tdilithium3DKGCrossProcessChildReadLine(t, reader, "peer "))
		if len(fields) != 4 {
			t.Fatalf("malformed peer line %q", strings.Join(fields, " "))
		}
		slot, err := strconv.Atoi(fields[1])
		if err != nil || slot < 0 || slot >= tdilithium3DKGCrossProcessPositions {
			t.Fatalf("malformed peer slot %q", fields[1])
		}
		peerByPosition[slot] = p2p.PeerID(fields[2])
		addrByPosition[slot] = fields[3]
	}
	tdilithium3DKGCrossProcessChildReadLine(t, reader, "start")

	ctx, cancel := context.WithTimeout(context.Background(), tdilithium3DKGCrossProcessPhaseTimeout)
	defer cancel()
	for other := index + 1; other < tdilithium3DKGCrossProcessPositions; other++ {
		if err := host.Connect(ctx, addrByPosition[other]); err != nil {
			t.Fatalf("child %d: connect to child %d: %v", index, other, err)
		}
	}
	for host.ConnectedPeerCount() != tdilithium3DKGCrossProcessPositions-1 {
		if err := ctx.Err(); err != nil {
			t.Fatalf("child %d: %v with %d/%d peers", index, err, host.ConnectedPeerCount(), tdilithium3DKGCrossProcessPositions-1)
		}
		time.Sleep(20 * time.Millisecond)
	}

	privateKey, _ := tdilithium3DKGCrossProcessIdentity(index)
	addresses := make(map[uint32]types.Address, tdilithium3DKGCrossProcessPositions)
	validators := make([]*consensus.Validator, 0, tdilithium3DKGCrossProcessPositions)
	peerByAddress := make(map[types.Address]p2p.PeerID, tdilithium3DKGCrossProcessPositions)
	keysByParticipant := make(map[uint32]*qcrypto.PublicKey, tdilithium3DKGCrossProcessPositions)
	for slot := 0; slot < tdilithium3DKGCrossProcessPositions; slot++ {
		_, address := tdilithium3DKGCrossProcessIdentity(slot)
		seed := tdilithium3DKGCrossProcessSeed(slot)
		publicKey, _ := mode3.NewKeyFromSeed(&seed)
		key, err := qcrypto.PublicKeyFromBytes(publicKey.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		addresses[session.Committee.Participants[slot]] = address
		validators = append(validators, &consensus.Validator{Address: address, Active: true, PublicKeyBytes: publicKey.Bytes()})
		peerByAddress[address] = peerByPosition[slot]
		keysByParticipant[session.Committee.Participants[slot]] = key
	}
	verifier := dilithium3v1.DKGIdentityVerifier(func(participantID uint32, message, signature []byte) bool {
		key := keysByParticipant[participantID]
		return key != nil && qcrypto.Verify(key, message, signature)
	})
	inbox, err := newTDilithium3DKGInboxFromValidatorSnapshot(session, position, addresses, validators, func(address types.Address) (p2p.PeerID, bool) {
		peer, found := peerByAddress[address]
		return peer, found
	})
	if err != nil {
		t.Fatal(err)
	}
	localNode := &Node{config: &Config{NetworkID: TestnetNetworkID}, tdilithium3DKGInbox: inbox}
	// The DKG inbox deliberately refuses activation envelopes because they carry
	// the candidate-bound activation transcript rather than the per-message
	// identity domain, so the child taps them off the host subscription directly
	// and verifies them as a set once all six are collected.
	activationPackets := make(chan []byte, 2*tdilithium3DKGCrossProcessPositions)
	go func() {
		for message := range host.SubscribeTSS() {
			if message.Type == p2p.MsgTypeTDilithium3DKGActivation {
				select {
				case activationPackets <- append([]byte(nil), message.Payload...):
				default:
				}
				continue
			}
			localNode.handleTSSMessage(message)
		}
	}()

	runner, err := newTDilithium3DKGRunner(tdilithium3DKGRunnerConfig{
		Session:             session.Clone(),
		ParticipantPosition: position,
		BasePath:            filepath.Join(root, "runner", strconv.Itoa(index), "shares.enc"),
		Password:            []byte("DEVNET ONLY six-node DKG password"),
		Entropy: bytes.NewReader(bytes.Repeat(
			[]byte{byte(index + 1), byte(index + 17), byte(index + 33)}, 1<<16)),
	})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(message []byte) ([]byte, error) {
		signature := make([]byte, mode3.SignatureSize)
		mode3.SignTo(privateKey, message, signature)
		return signature, nil
	}
	broadcast := func(kind uint8, payload []byte) error {
		return host.BroadcastTSS(kind, payload)
	}
	sendPrivate := func(kind uint8, recipient uint8, payload []byte) error {
		if recipient >= tdilithium3DKGCrossProcessPositions {
			return fmt.Errorf("Dilithium3 DKG recipient position %d is out of range", recipient)
		}
		return host.SendTSSToPeer(peerByPosition[recipient], kind, payload)
	}

	exchange := newTDilithium3DKGGroupExchange()
	if err := localNode.runTDilithium3DKGRandomness(ctx, runner, exchange, sign, broadcast); err != nil {
		t.Fatalf("child %d randomness round: %v", index, err)
	}
	fmt.Fprintf(stdout, "randomness %d\n", index)
	if err := stdout.Flush(); err != nil {
		t.Fatal(err)
	}
	tdilithium3DKGCrossProcessChildReadLine(t, reader, "groups")

	for _, group := range dilithium3v1.CanonicalRSSGroups() {
		if err := localNode.runTDilithium3DKGGroup(ctx, runner, group, exchange, sign, broadcast, sendPrivate); err != nil {
			t.Fatalf("child %d group %06b: %v", index, group, err)
		}
	}
	result, err := tdilithium3DKGFinalize(runner)
	if err != nil {
		t.Fatalf("child %d finalize: %v", index, err)
	}
	if result.Share == nil || runner.record.Stage != tdilithium3DKGStageAcknowledgementPersisted {
		t.Fatalf("child %d finalized without a durable share", index)
	}
	fmt.Fprintf(stdout, "result %d %x %x\n", index, result.PublicKey, result.TranscriptDigest)
	if err := stdout.Flush(); err != nil {
		t.Fatal(err)
	}

	// Activation: the child signs its own durable candidate share, the six signed
	// acknowledgements travel over the same real TCP transport and inbound
	// validation, and the child then commits the exact-epoch activation locally and
	// reloads the active share the way a restart would.
	own, err := encodeTDilithium3DKGActivationEnvelope(session, result.Share, sign)
	if err != nil {
		t.Fatalf("child %d activation envelope: %v", index, err)
	}
	if err := p2p.ValidateTDilithium3DKGEnvelope(p2p.MsgTypeTDilithium3DKGActivation, own); err != nil {
		t.Fatalf("child %d activation envelope rejected by P2P validation: %v", index, err)
	}
	if err := broadcast(p2p.MsgTypeTDilithium3DKGActivation, own); err != nil {
		t.Fatalf("child %d broadcast activation: %v", index, err)
	}
	collected := map[string][]byte{string(own): own}
	activationDeadline := time.After(tdilithium3DKGCrossProcessPhaseTimeout)
	for len(collected) < tdilithium3DKGCrossProcessPositions {
		select {
		case packet := <-activationPackets:
			collected[string(packet)] = packet
		case <-activationDeadline:
			t.Fatalf("child %d collected %d/%d activation acknowledgements", index, len(collected), tdilithium3DKGCrossProcessPositions)
		}
	}
	activationPacketsIn := make([][]byte, 0, tdilithium3DKGCrossProcessPositions)
	for _, packet := range collected {
		activationPacketsIn = append(activationPacketsIn, packet)
	}
	certificate, err := assembleTDilithium3DKGActivationCertificate(session, result.PublicKey, result.TranscriptDigest, activationPacketsIn, verifier)
	if err != nil {
		t.Fatalf("child %d activation certificate: %v", index, err)
	}
	sessionDigest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.shareStore.ActivateCandidate(certificate, sessionDigest, session.ActivationEpoch, verifier, runner.password); err != nil {
		t.Fatalf("child %d activation commit: %v", index, err)
	}
	active, err := newThresholdShareStore(runner.basePath).LoadActiveAtEpoch(session.ActivationEpoch, verifier, runner.password)
	if err != nil {
		t.Fatalf("child %d activation reload: %v", index, err)
	}
	if active.ParticipantID != session.Committee.Participants[position] {
		t.Fatalf("child %d reloaded participant %d instead of %d", index, active.ParticipantID, session.Committee.Participants[position])
	}
	active.Zeroize()
	certificateDigest, err := certificate.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(stdout, "activation %d %x\n", index, certificateDigest)
	if err := stdout.Flush(); err != nil {
		t.Fatal(err)
	}
	// Stop the real host on the way out. This exercises Host.Stop over six live
	// TCP peers with idle read loops, which used to deadlock in
	// encryptedConn.Close (R42-CLOSE-DEADLOCK). The parent bounds the wait, so a
	// regression fails the test instead of hanging it.
	if err := host.Stop(); err != nil {
		t.Fatalf("child %d host stop: %v", index, err)
	}
}

func tdilithium3DKGCrossProcessChildReadLine(t *testing.T, reader *bufio.Reader, prefix string) string {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("helper read %q: %v", prefix, err)
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
}

// TestTDilithium3DKGCeremonyP2PCrossProcess drives the production entry point
// — runTDilithium3DKGCeremony — in six separate operating-system processes, each
// with a real p2p.Host and its own roster sidecar.
//
// This is the end-to-end wiring test the process-level harness cannot give: the
// session is derived from chain state inside the ceremony (not injected), the
// roster is read from the captured-epoch sidecar, the inbox is installed by the
// ceremony itself, and every envelope travels over real TCP. All six processes
// must derive the same session digest and assemble the same mode3 group public
// key, and each must be able to resume the persisted record afterwards.
func TestTDilithium3DKGCeremonyP2PCrossProcess(t *testing.T) {
	if os.Getenv(tdilithium3DKGCeremonyHelperEnv) == "1" {
		runTDilithium3DKGCeremonyP2PChild(t)
		return
	}
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")

	root := t.TempDir()
	children := make([]*tdilithium3DKGCrossProcessChild, tdilithium3DKGCrossProcessPositions)
	defer func() {
		for _, child := range children {
			if child != nil {
				child.stop()
			}
		}
	}()

	peerByPosition := [tdilithium3DKGCrossProcessPositions]p2p.PeerID{}
	addrByPosition := [tdilithium3DKGCrossProcessPositions]string{}
	for index := range children {
		child := tdilithium3DKGCrossProcessStartChild(t, index, root,
			"^TestTDilithium3DKGCeremonyP2PCrossProcess$", tdilithium3DKGCeremonyHelperEnv)
		children[index] = child
		ready := strings.Fields(child.readLine(t, "ready ", tdilithium3DKGCrossProcessPhaseTimeout))
		if len(ready) != 4 {
			t.Fatalf("child %d: malformed ready line %q", index, strings.Join(ready, " "))
		}
		reported, err := strconv.Atoi(ready[1])
		if err != nil || reported != index {
			t.Fatalf("child %d reported index %q", index, ready[1])
		}
		peerByPosition[index] = p2p.PeerID(ready[2])
		addrByPosition[index] = ready[3]
	}
	for index := 0; index < tdilithium3DKGCrossProcessPositions; index++ {
		for other := index + 1; other < tdilithium3DKGCrossProcessPositions; other++ {
			if peerByPosition[index] == peerByPosition[other] {
				t.Fatalf("children %d and %d share peer identity %s", index, other, peerByPosition[index])
			}
			if addrByPosition[index] == addrByPosition[other] {
				t.Fatalf("children %d and %d listen on the same address", index, other)
			}
		}
	}

	table := &bytes.Buffer{}
	for position := 0; position < tdilithium3DKGCrossProcessPositions; position++ {
		fmt.Fprintf(table, "peer %d %s %s\n", position, peerByPosition[position], addrByPosition[position])
	}
	for _, child := range children {
		child.write(t, strings.TrimRight(table.String(), "\n"))
		child.write(t, "start")
	}

	// No phase schedule: every child runs its own ceremony timeline. A child that
	// finishes the randomness round and starts the groups earlier than its peers is
	// exactly the production condition the exchange buffering exists for.
	sessionDigests := [tdilithium3DKGCrossProcessPositions]string{}
	publicKeys := [tdilithium3DKGCrossProcessPositions]string{}
	for _, child := range children {
		digest, publicKey := tdilithium3DKGCeremonyChildOutcome(t, child)
		sessionDigests[child.index] = digest
		publicKeys[child.index] = publicKey
	}
	for index := 1; index < tdilithium3DKGCrossProcessPositions; index++ {
		if sessionDigests[index] != sessionDigests[0] {
			t.Fatalf("child %d derived a different DKG session digest", index)
		}
		if publicKeys[index] != publicKeys[0] {
			t.Fatalf("child %d assembled a different mode3 public key", index)
		}
	}
	for _, child := range children {
		if err := child.input.Close(); err != nil {
			t.Fatalf("child %d: close stdin: %v", child.index, err)
		}
		if err := child.wait(tdilithium3DKGCrossProcessPhaseTimeout); err != nil {
			t.Fatalf("child %d exited with %v\n%s", child.index, err, child.diagnostics())
		}
	}
}

// tdilithium3DKGCeremonyChildOutcome reads one child's ceremony result, failing
// with the child's own diagnostics when the child reported a failure or exited.
func tdilithium3DKGCeremonyChildOutcome(t *testing.T, child *tdilithium3DKGCrossProcessChild) (string, string) {
	t.Helper()
	deadline := time.After(tdilithium3DKGCrossProcessPhaseTimeout)
	for {
		select {
		case line, ok := <-child.lines:
			if !ok {
				t.Fatalf("child %d exited before reporting its ceremony result (%v)\n%s",
					child.index, child.stdoutError(), child.diagnostics())
			}
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) == 0 {
				continue
			}
			switch fields[0] {
			case "ceremony":
				if len(fields) != 4 {
					t.Fatalf("child %d: malformed ceremony line %q", child.index, strings.Join(fields, " "))
				}
				return fields[2], fields[3]
			case "failure":
				t.Fatalf("child %d ceremony failed: %s\n%s", child.index, strings.Join(fields[2:], " "), child.diagnostics())
			}
		case <-deadline:
			t.Fatalf("child %d did not report its ceremony result within %s\n%s",
				child.index, tdilithium3DKGCrossProcessPhaseTimeout, child.diagnostics())
		}
	}
}

// tdilithium3DKGCeremonyP2PIdentity derives the DEVNET-only identity of one
// committee position. Every child derives the same six identities from the same
// public seeds, so all six agree on the roster without any key crossing the wire.
func tdilithium3DKGCeremonyP2PIdentity(t *testing.T, position int) *qcrypto.KeyPair {
	t.Helper()
	seed := sha3.Sum256([]byte(fmt.Sprintf("DEVNET ONLY ceremony cross-process identity %d", position)))
	pair, err := qcrypto.GenerateKeyPairFromSeed(seed[:])
	if err != nil {
		t.Fatalf("derive ceremony identity %d: %v", position, err)
	}
	return pair
}

// runTDilithium3DKGCeremonyP2PChild runs one node's production ceremony against
// the other five processes.
func runTDilithium3DKGCeremonyP2PChild(t *testing.T) {
	if !experimentalTDilithium3V1Enabled() {
		t.Fatal("child requires the experimental Dilithium3 v1 gates")
	}
	index, err := strconv.Atoi(os.Getenv(tdilithium3DKGCrossProcessIndexEnv))
	if err != nil || index < 0 || index >= tdilithium3DKGCrossProcessPositions {
		t.Fatalf("child index %q is invalid", os.Getenv(tdilithium3DKGCrossProcessIndexEnv))
	}
	root := os.Getenv(tdilithium3DKGCrossProcessRootEnv)
	if root == "" {
		t.Fatal("child requires a working root")
	}

	host, err := p2p.NewHost(&p2p.Config{
		ListenAddr:      "127.0.0.1:0",
		DevMode:         true,
		NetworkID:       TestnetNetworkID,
		MaxPeers:        8,
		MaxInboundPeers: 8,
		EnableDHT:       false,
		NodeKeyPath:     filepath.Join(root, "ceremony-p2p", strconv.Itoa(index), "nodekey"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}

	stdout := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(stdout, "ready %d %s %s\n", index, host.ID(), host.Addr())
	if err := stdout.Flush(); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(os.Stdin)
	peerByPosition := [tdilithium3DKGCrossProcessPositions]p2p.PeerID{}
	addrByPosition := [tdilithium3DKGCrossProcessPositions]string{}
	for entry := 0; entry < tdilithium3DKGCrossProcessPositions; entry++ {
		fields := strings.Fields(tdilithium3DKGCrossProcessChildReadLine(t, reader, "peer "))
		if len(fields) != 4 {
			t.Fatalf("malformed peer line %q", strings.Join(fields, " "))
		}
		slot, err := strconv.Atoi(fields[1])
		if err != nil || slot < 0 || slot >= tdilithium3DKGCrossProcessPositions {
			t.Fatalf("malformed peer slot %q", fields[1])
		}
		peerByPosition[slot] = p2p.PeerID(fields[2])
		addrByPosition[slot] = fields[3]
	}
	tdilithium3DKGCrossProcessChildReadLine(t, reader, "start")

	ctx, cancel := context.WithTimeout(context.Background(), tdilithium3DKGCrossProcessPhaseTimeout)
	defer cancel()
	for other := index + 1; other < tdilithium3DKGCrossProcessPositions; other++ {
		if err := host.Connect(ctx, addrByPosition[other]); err != nil {
			t.Fatalf("child %d: connect to child %d: %v", index, other, err)
		}
	}
	for host.ConnectedPeerCount() != tdilithium3DKGCrossProcessPositions-1 {
		if err := ctx.Err(); err != nil {
			t.Fatalf("child %d: %v with %d/%d peers", index, err, host.ConnectedPeerCount(), tdilithium3DKGCrossProcessPositions-1)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The ceremony resolves private-send targets through the host's validator to
	// peer map, which in production is filled by the verified status path.
	host.AuthorizeValidatorRegistration()
	pairs := [tdilithium3DKGCrossProcessPositions]*qcrypto.KeyPair{}
	validators := make([]*consensus.Validator, 0, tdilithium3DKGCrossProcessPositions)
	for slot := 0; slot < tdilithium3DKGCrossProcessPositions; slot++ {
		pairs[slot] = tdilithium3DKGCeremonyP2PIdentity(t, slot)
		address := pairs[slot].Public.Address()
		validators = append(validators, &consensus.Validator{
			Address: address, Active: true, PublicKeyBytes: pairs[slot].Public.Bytes(),
		})
		host.RegisterValidatorPeer(address, peerByPosition[slot])
	}
	entries, err := tdilithium3DKGActiveRosterEntries(validators)
	if err != nil {
		t.Fatal(err)
	}
	localAddress := pairs[index].Public.Address()
	localPosition := -1
	for position, entry := range entries {
		if entry.Address == localAddress {
			localPosition = position
		}
	}
	if localPosition < 0 {
		t.Fatalf("child %d address %s is not in the roster", index, localAddress.String())
	}

	node := &Node{
		config: &Config{
			DataDir:              filepath.Join(root, "ceremony", strconv.Itoa(index)),
			NetworkID:            TestnetNetworkID,
			ValidatorKeyPassword: "DEVNET ONLY ceremony cross-process password",
		},
		genesisBlock: &encoding.Block{Header: &encoding.BlockHeader{}},
		blockProducer: &BlockProducer{
			validatorKey:  pairs[index].Private,
			validatorAddr: localAddress,
		},
		p2pHost: host,
	}
	// The roster the ceremony anchors on is the boundary of activationEpoch-1, and
	// the bootstrap boundary sits strictly below it.
	store := node.tdilithium3DKGEpochRosterStoreForUse()
	if store == nil {
		t.Fatal("the roster sidecar is not enabled with the gates open and a data dir")
	}
	if err := store.capture(5, tdilithium3DKGRosterTestHash(0x90), entries, 4); err != nil {
		t.Fatal(err)
	}
	if err := store.capture(6, tdilithium3DKGRosterTestHash(0x91), entries, 5); err != nil {
		t.Fatal(err)
	}

	// The ceremony installs its own inbox; inbound traffic is dispatched the way
	// the production loop does.
	go func() {
		for message := range host.SubscribeTSS() {
			node.handleTSSMessage(message)
		}
	}()

	session, err := node.deriveTDilithium3DKGSession(7)
	if err != nil {
		t.Fatalf("child %d session derivation: %v", index, err)
	}
	sessionDigest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := node.runTDilithium3DKGCeremony(ctx, 7)
	if err != nil {
		fmt.Fprintf(stdout, "failure %d %v\n", index, err)
		if flushErr := stdout.Flush(); flushErr != nil {
			t.Fatal(flushErr)
		}
		t.Fatalf("child %d ceremony: %v", index, err)
	}

	// The ceremony must leave a durable, resumable record behind: a fresh runner
	// over the same session and directory has to find the persisted share. This is
	// the cross-process half of the restart claim (design, D3).
	resumed, err := newTDilithium3DKGRunner(tdilithium3DKGRunnerConfig{
		Session:             session,
		ParticipantPosition: uint8(localPosition),
		BasePath:            node.config.DataDir,
		Password:            []byte(node.config.ValidatorKeyPassword),
		Entropy:             rand.Reader,
	})
	if err != nil {
		t.Fatalf("child %d resume: %v", index, err)
	}
	if resumed.record.Stage != tdilithium3DKGStageAcknowledgementPersisted {
		t.Fatalf("child %d resumed at stage %d instead of a persisted acknowledgement", index, resumed.record.Stage)
	}
	if resumed.record.PublicKey != publicKey {
		t.Fatalf("child %d resumed with a different group public key", index)
	}

	fmt.Fprintf(stdout, "ceremony %d %x %x\n", index, sessionDigest, publicKey)
	if err := stdout.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := host.Stop(); err != nil {
		t.Fatalf("child %d host stop: %v", index, err)
	}
}
