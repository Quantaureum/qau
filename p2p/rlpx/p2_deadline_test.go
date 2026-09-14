// Quantaureum Node source, version 1.0.0.
package rlpx

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/p2p/enode"
)

// TestP2_DEADLINE_InitiatorHandshakeReturnsDeadlineError verifies that
// InitiatorHandshake returns an error (not silently ignores it) when
// SetDeadline fails on the underlying connection.
//
// P2-DEADLINE FIX (R29, 2026-07-26): Previously, the SetDeadline error in
// InitiatorHandshake was silently ignored (#nosec G104). If SetDeadline
// failed (e.g., on a closed connection), the handshake would proceed with
// NO timeout — a malicious peer could stall the handshake forever, tying
// up a goroutine and preventing connection cleanup. The fix returns the
// SetDeadline error so the caller can close the connection immediately.
//
// This test uses a closed pipe (which causes SetDeadline to return an
// error) and verifies that InitiatorHandshake propagates the error instead
// of silently ignoring it.
func TestP2_DEADLINE_InitiatorHandshakeReturnsDeadlineError(t *testing.T) {
	os.Setenv("QAU_DEV_MODE_BLOCKS", "1")
	defer os.Setenv("QAU_DEV_MODE_BLOCKS", "1")

	// Create a pipe and close the other end — SetDeadline on the closed
	// end will return an error.
	c1, c2 := net.Pipe()
	conn := NewConn(c1, randomID())
	c2.Close() // Close the other end to make SetDeadline fail

	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	remoteID := randomID()
	remoteNode := enode.NewNode(remoteID, net.ParseIP("127.0.0.1"), 30303, 30303)

	err = conn.InitiatorHandshake(keyPair.Private, remoteNode)

	// P2-DEADLINE: The error MUST be non-nil. Previously, SetDeadline's
	// error was silently ignored, and the handshake would proceed to
	// read from the closed pipe (which would eventually error, but with
	// a confusing "EOF" or "broken pipe" message instead of the clear
	// "failed to set handshake deadline" message).
	if err == nil {
		t.Fatal("P2-DEADLINE REGRESSION: InitiatorHandshake returned nil " +
			"error on a closed connection — the SetDeadline error was " +
			"silently ignored, allowing the handshake to proceed without " +
			"a timeout (Slowloris vulnerability)")
	}

	// The error should mention "deadline" — this confirms the error came
	// from SetDeadline, not from a later read/write operation. If the
	// error message is "EOF" or "broken pipe" without "deadline", it
	// means SetDeadline was silently ignored and the error came from a
	// later operation (regression).
	if !strings.Contains(err.Error(), "deadline") {
		t.Errorf("P2-DEADLINE REGRESSION: error does not mention 'deadline' "+
			"— the SetDeadline error was silently ignored and the error "+
			"came from a later operation instead. Error: %v", err)
	}

	// The error should NOT be ErrHandshakeFailed — that would mean the
	// handshake proceeded past SetDeadline and failed later. We want the
	// SetDeadline error to be returned directly.
	if errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("P2-DEADLINE REGRESSION: error is ErrHandshakeFailed — "+
			"this means SetDeadline was silently ignored and the handshake "+
			"proceeded to fail later. Error: %v", err)
	}
}

// TestP2_DEADLINE_ResponderHandshakeReturnsDeadlineError verifies that
// ResponderHandshakeWithStore returns an error when SetDeadline fails.
//
// P2-DEADLINE FIX (R29, 2026-07-26): Same rationale as the initiator
// handshake — the SetDeadline error must not be silently ignored.
func TestP2_DEADLINE_ResponderHandshakeReturnsDeadlineError(t *testing.T) {
	os.Setenv("QAU_DEV_MODE_BLOCKS", "1")
	defer os.Setenv("QAU_DEV_MODE_BLOCKS", "1")

	c1, c2 := net.Pipe()
	conn := NewConn(c1, randomID())
	c2.Close() // Close the other end to make SetDeadline fail

	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	err = conn.ResponderHandshakeWithStore(keyPair.Private, nil)

	if err == nil {
		t.Fatal("P2-DEADLINE REGRESSION: ResponderHandshakeWithStore returned " +
			"nil error on a closed connection — the SetDeadline error was " +
			"silently ignored")
	}

	if !strings.Contains(err.Error(), "deadline") {
		t.Errorf("P2-DEADLINE REGRESSION: error does not mention 'deadline' "+
			"— the SetDeadline error was silently ignored. Error: %v", err)
	}
}
