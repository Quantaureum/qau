// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
)

// TestP2_RotateKeys_ZeroizesOldKeysOnFailure verifies that RotateKeys zeroizes
// the old session keys when the re-handshake fails.
//
// P2-ROTATEKEYS-ZEROIZE FIX (R29, 2026-07-26): Previously, on RotateKeys
// failure, only c.Conn.Close() was called — the underlying TCP connection
// was closed, but the OLD session keys (c.sendKey, c.recvKey) and cipher
// objects remained in the encryptedConn struct in heap memory. An attacker
// who could dump memory or trigger a cold-boot attack could extract the old
// AES-256-GCM session keys and decrypt previously-recorded traffic. The fix
// zeroizes the key material on the failure path (mirroring the success path's
// P1-06 zeroization).
//
// This test works by:
//  1. Establishing a successful client/server handshake (so the client has
//     valid session keys).
//  2. Capturing the backing arrays of the client's sendKey/recvKey (via slice
//     header copy — both the captured slice and the struct field point to the
//     same backing array).
//  3. Closing the server side so the next handshake will fail.
//  4. Calling RotateKeys on the client — this fails because the server is gone.
//  5. Verifying that the captured backing arrays are now all zeros (proving
//     zeroize() was called on the failure path).
//  6. Verifying that the struct fields are nil'd out (so the cipher objects
//     are released for GC).
func TestP2_RotateKeys_ZeroizesOldKeysOnFailure(t *testing.T) {
	// Generate key pairs for server and client
	serverKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	clientKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientPeerID := derivePeerIDFromKeyPair(clientKey)

	// Start a TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	var wg sync.WaitGroup

	// Server: accept connection, run server handshake, then CLOSE immediately
	// so the client's RotateKeys re-handshake will fail.
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("server accept failed: %v", err)
			return
		}
		serverConn, err := performServerHandshake(conn, serverKey, false)
		if err != nil {
			t.Errorf("server handshake failed: %v", err)
			conn.Close()
			return
		}
		// Close immediately to make the client's RotateKeys fail. We use
		// Close() (not just conn.Close()) so the server's keys are also
		// zeroized — defense in depth.
		serverConn.Close()
	}()

	// Client: dial and run client handshake
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}

	clientPowNonce := computeTestPoWNonce(t, clientKey)
	clientConn, err := performClientHandshake(conn, clientKey, clientPeerID, "", clientPowNonce)
	if err != nil {
		conn.Close()
		t.Fatalf("client handshake failed: %v", err)
	}

	encConn := clientConn.(*encryptedConn)

	// Capture the original key slices. These slice headers point to the SAME
	// backing arrays as encConn.sendKey/recvKey. After RotateKeys calls
	// zeroize(c.sendKey), the backing arrays will be zeroed — and since
	// origSendKey/origRecvKey share the same backing arrays, we can verify
	// the zeroization by reading through them.
	encConn.writeMu.Lock()
	encConn.readMu.Lock()
	origSendKey := encConn.sendKey
	origRecvKey := encConn.recvKey
	encConn.readMu.Unlock()
	encConn.writeMu.Unlock()

	// Sanity check: the keys must be non-empty before rotation
	if len(origSendKey) == 0 {
		t.Fatal("sendKey is empty before rotation — test setup is broken")
	}
	if len(origRecvKey) == 0 {
		t.Fatal("recvKey is empty before rotation — test setup is broken")
	}

	// Sanity check: the keys must contain non-zero data (they're derived from
	// a random shared secret, so the probability of all-zero keys is negligible)
	sendKeyHasNonZero := false
	for _, b := range origSendKey {
		if b != 0 {
			sendKeyHasNonZero = true
			break
		}
	}
	if !sendKeyHasNonZero {
		t.Fatal("sendKey is all zeros before rotation — unexpected, " +
			"keys should contain real key material")
	}
	recvKeyHasNonZero := false
	for _, b := range origRecvKey {
		if b != 0 {
			recvKeyHasNonZero = true
			break
		}
	}
	if !recvKeyHasNonZero {
		t.Fatal("recvKey is all zeros before rotation — unexpected, " +
			"keys should contain real key material")
	}

	// Wait for the server to close the connection, then give the TCP stack
	// time to propagate the FIN to the client.
	wg.Wait()
	time.Sleep(200 * time.Millisecond)

	// Now try to rotate keys — this should fail because the server closed
	// the connection and there's no one to respond to the re-handshake.
	rotateErr := encConn.RotateKeys()
	if rotateErr == nil {
		// If RotateKeys succeeded, the test is invalid — we need the failure
		// path to verify zeroization. This could happen if the server hasn't
		// fully closed yet (timing-dependent). Clean up and skip.
		encConn.Close()
		t.Skip("RotateKeys succeeded unexpectedly — the server may not have " +
			"closed the connection in time. This is a test timing issue, " +
			"not a regression.")
	}

	// Verify the old key backing arrays were zeroized. We read through the
	// captured slice headers (origSendKey/origRecvKey), which still point to
	// the original backing arrays even though encConn.sendKey/recvKey are now
	// nil. If zeroize() was NOT called, these arrays would still contain the
	// original key material.
	for i, b := range origSendKey {
		if b != 0 {
			encConn.Close()
			t.Errorf("P2-ROTATEKEYS-ZEROIZE REGRESSION: sendKey[%d] = 0x%02x, "+
				"expected 0x00 — old session key was NOT zeroized on RotateKeys "+
				"failure path. The backing array still contains the original "+
				"AES-256-GCM key material, which is extractable via memory dump "+
				"or cold-boot attack.", i, b)
			break
		}
	}
	for i, b := range origRecvKey {
		if b != 0 {
			encConn.Close()
			t.Errorf("P2-ROTATEKEYS-ZEROIZE REGRESSION: recvKey[%d] = 0x%02x, "+
				"expected 0x00 — old session key was NOT zeroized on RotateKeys "+
				"failure path. The backing array still contains the original "+
				"AES-256-GCM key material, which is extractable via memory dump "+
				"or cold-boot attack.", i, b)
			break
		}
	}

	// Verify the struct fields are nil'd out. This ensures the cipher objects
	// (which hold internal AES-GCM state derived from the keys) are released
	// for GC. Without this, the cipher.AEAD objects would linger in heap
	// memory until the encryptedConn itself is GC'd.
	//
	// We acquire the locks to read the fields safely (RotateKeys has already
	// released them by this point, but defensive locking is good practice).
	encConn.writeMu.Lock()
	encConn.readMu.Lock()
	sendKeyNil := encConn.sendKey == nil
	recvKeyNil := encConn.recvKey == nil
	sendCipherNil := encConn.sendCipher == nil
	recvCipherNil := encConn.recvCipher == nil
	readBufNil := encConn.readBuf == nil
	encConn.readMu.Unlock()
	encConn.writeMu.Unlock()

	if !sendKeyNil {
		t.Error("P2-ROTATEKEYS-ZEROIZE REGRESSION: encConn.sendKey is not nil " +
			"after RotateKeys failure — the slice header was not nil'd out, " +
			"keeping a reference to the (now zeroed) backing array")
	}
	if !recvKeyNil {
		t.Error("P2-ROTATEKEYS-ZEROIZE REGRESSION: encConn.recvKey is not nil " +
			"after RotateKeys Failure — the slice header was not nil'd out, " +
			"keeping a reference to the (now zeroed) backing array")
	}
	if !sendCipherNil {
		t.Error("P2-ROTATEKEYS-ZEROIZE REGRESSION: encConn.sendCipher is not nil " +
			"after RotateKeys failure — the cipher object (holding internal " +
			"AES-GCM state) was not released for GC")
	}
	if !recvCipherNil {
		t.Error("P2-ROTATEKEYS-ZEROIZE REGRESSION: encConn.recvCipher is not nil " +
			"after RotateKeys failure — the cipher object (holding internal " +
			"AES-GCM state) was not released for GC")
	}
	if !readBufNil {
		t.Error("P2-ROTATEKEYS-ZEROIZE REGRESSION: encConn.readBuf is not nil " +
			"after RotateKeys failure — the read buffer was not released for GC")
	}
}

// TestP2_RotateKeys_LeavesConnectionClosed verifies that after a failed
// RotateKeys, the encryptedConn is in a closed state — subsequent calls to
// Read/Write/Close should not panic and should return an error.
//
// P2-ROTATEKEYS-ZEROIZE FIX (R29, 2026-07-26): The fix zeroizes keys and
// nils out ciphers on the failure path. This test ensures the encryptedConn
// is safely unusable after a failed rotation (no nil-pointer panic on
// subsequent operations, which would happen if ciphers were nil'd but the
// Read/Write methods didn't check for nil).
func TestP2_RotateKeys_LeavesConnectionClosed(t *testing.T) {
	serverKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	clientKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientPeerID := derivePeerIDFromKeyPair(clientKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		serverConn, err := performServerHandshake(conn, serverKey, false)
		if err != nil {
			conn.Close()
			return
		}
		serverConn.Close()
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}

	clientPowNonce := computeTestPoWNonce(t, clientKey)
	clientConn, err := performClientHandshake(conn, clientKey, clientPeerID, "", clientPowNonce)
	if err != nil {
		conn.Close()
		t.Fatalf("client handshake failed: %v", err)
	}

	encConn := clientConn.(*encryptedConn)
	wg.Wait()
	time.Sleep(200 * time.Millisecond)

	// Trigger a failed RotateKeys
	_ = encConn.RotateKeys()

	// Subsequent Write should not panic (cipher is nil, so Write must handle
	// that gracefully by returning an error)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("P2-ROTATEKEYS-ZEROIZE REGRESSION: Write panicked after "+
				"failed RotateKeys: %v — the nil cipher was not handled gracefully",
				r)
		}
	}()
	_, writeErr := encConn.Write([]byte("test"))
	if writeErr == nil {
		t.Error("expected Write to fail after failed RotateKeys (cipher is nil)")
	}

	// Subsequent Read should not panic either
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("P2-ROTATEKEYS-ZEROIZE REGRESSION: Read panicked after "+
				"failed RotateKeys: %v — the nil cipher was not handled gracefully",
				r)
		}
	}()
	buf := make([]byte, 16)
	_, readErr := encConn.Read(buf)
	if readErr == nil {
		t.Error("expected Read to fail after failed RotateKeys (cipher is nil)")
	}

	// Close should be idempotent (safe to call again)
	if err := encConn.Close(); err != nil {
		// Close may return an error ("use of closed connection") — that's fine,
		// we just want to verify it doesn't panic.
		t.Logf("Close returned error (expected): %v", err)
	}
}
