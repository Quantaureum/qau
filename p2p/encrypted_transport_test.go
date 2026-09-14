// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/p2p/discover"
	"github.com/quantaureum/qau/p2p/enode"
	"golang.org/x/crypto/sha3"
)

// computeTestPoWNonce computes a valid proof-of-work nonce for the given
// keypair's node ID. This is needed because the server now rejects handshakes
// without a valid PoW nonce (P2P-05: legacy format removed).
// AUDIT (2026) P2P-05
func computeTestPoWNonce(t *testing.T, kp *crypto.KeyPair) uint64 {
	t.Helper()
	pubBytes := kp.Public.Bytes()
	h := sha3.New256()
	h.Write(pubBytes)
	nodeIDHash := h.Sum(nil)
	var nodeID enode.ID
	copy(nodeID[:], nodeIDHash)

	target := new(big.Int).Lsh(big.NewInt(1), 256-uint(discover.MinProofOfWorkDifficulty))
	data := make([]byte, len(nodeID)+8)
	copy(data, nodeID[:])

	for i := uint64(0); i < 1<<30; i++ {
		binary.LittleEndian.PutUint64(data[len(nodeID):], i)
		hasher := sha3.New256()
		hasher.Write(data)
		hashInt := new(big.Int).SetBytes(hasher.Sum(nil))
		if hashInt.Cmp(target) < 0 {
			return i
		}
	}
	t.Fatal("failed to find PoW nonce within iteration limit")
	return 0
}

// TestEncryptedBidirectionalCommunication tests that after a successful
// handshake, both sides can send and receive encrypted data correctly.
// This is the critical regression test for Q-B-003-C1: before the fix,
// the client passed remoteID="" to deriveSessionKeys, causing the keys to
// mismatch and making encrypted traffic undecryptable.
func TestEncryptedBidirectionalCommunication(t *testing.T) {
	// Generate key pairs for server and client
	serverKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	clientKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	// Derive peer IDs
	_ = derivePeerIDFromKeyPair(serverKey) // serverPeerID not used in this test
	clientPeerID := derivePeerIDFromKeyPair(clientKey)

	// Start a TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	var wg sync.WaitGroup

	// Server: accept connection and run server handshake
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("server accept failed: %v", err)
			return
		}
		defer conn.Close()

		serverConn, err := performServerHandshake(conn, serverKey, false)
		if err != nil {
			t.Errorf("server handshake failed: %v", err)
			return
		}
		defer serverConn.Close()

		// Server sends a message to client
		testMsg := []byte("hello from server")
		n, err := serverConn.Write(testMsg)
		if err != nil {
			t.Errorf("server write failed: %v", err)
			return
		}
		if n != len(testMsg) {
			t.Errorf("server write returned %d, want %d", n, len(testMsg))
		}

		// Server reads the echoed message from client
		buf := make([]byte, 256)
		n, err = serverConn.Read(buf)
		if err != nil {
			t.Errorf("server read failed: %v", err)
			return
		}
		if string(buf[:n]) != "hello from client" {
			t.Errorf("server got %q, want %q", string(buf[:n]), "hello from client")
		}
	}()

	// Client: dial and run client handshake
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
		if err != nil {
			t.Errorf("client dial failed: %v", err)
			return
		}
		defer conn.Close()

		// Pass localID but remoteID="" so the client reads it from the wire
		// P2P-05: PoW nonce is now mandatory (legacy format removed)
		clientPowNonce := computeTestPoWNonce(t, clientKey)
		clientConn, err := performClientHandshake(conn, clientKey, clientPeerID, "", clientPowNonce)
		if err != nil {
			t.Errorf("client handshake failed: %v", err)
			return
		}
		defer clientConn.Close()

		// Client reads the message from server
		buf := make([]byte, 256)
		n, err := clientConn.Read(buf)
		if err != nil {
			t.Errorf("client read failed: %v", err)
			return
		}
		if string(buf[:n]) != "hello from server" {
			t.Errorf("client got %q, want %q", string(buf[:n]), "hello from server")
		}

		// Client echoes a message back to server
		echoMsg := []byte("hello from client")
		n, err = clientConn.Write(echoMsg)
		if err != nil {
			t.Errorf("client write failed: %v", err)
			return
		}
		if n != len(echoMsg) {
			t.Errorf("client write returned %d, want %d", n, len(echoMsg))
		}
	}()

	wg.Wait()
}

// TestEncryptedDialIntegration tests the encryptedDial helper used by Connect().
// It verifies that encryptedDial produces a fully functional encrypted connection.
func TestEncryptedDialIntegration(t *testing.T) {
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
	var clientConn net.Conn
	var serverConn net.Conn
	var clientErr, serverErr error
	var serverSide *encryptedConn

	// Server goroutine: accept and perform full server handshake.
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConn, serverErr = listener.Accept()
		if serverErr != nil {
			return
		}
		var serverConnRaw net.Conn
		serverConnRaw, serverErr = performServerHandshake(serverConn, serverKey, false)
		if serverErr == nil {
			serverSide = serverConnRaw.(*encryptedConn)
		}
	}()

	// Client goroutine: dial encrypted connection.
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientConn, clientErr = encryptedDial(listener.Addr().String(), clientKey, clientPeerID, computeTestPoWNonce(t, clientKey))
	}()

	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client dial failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake failed: %v", serverErr)
	}
	defer clientConn.Close()
	defer serverConn.Close()
	defer serverSide.Close()

	// Client can write and server can read
	msg := []byte("encrypted dial test")
	n, err := clientConn.Write(msg)
	if err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	if n != len(msg) {
		t.Fatalf("client write returned %d, want %d", n, len(msg))
	}

	buf := make([]byte, 256)
	n, err = serverSide.Read(buf)
	if err != nil {
		t.Fatalf("server read failed: %v", err)
	}
	if string(buf[:n]) != "encrypted dial test" {
		t.Errorf("server got %q, want %q", string(buf[:n]), "encrypted dial test")
	}
}

// TestSessionKeyDerivationDeterminism verifies that both sides of a connection
// derive the same send/recv keys given the same inputs.
func TestSessionKeyDerivationDeterminism(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	localID := PeerID("local-peer-id-abc123")
	remoteID := PeerID("remote-peer-id-xyz789")

	// Initiator side
	sendKeyInit, recvKeyInit, err := deriveSessionKeys(sharedSecret, true, localID, remoteID)
	if err != nil {
		t.Fatalf("initiator key derivation failed: %v", err)
	}

	// Responder side
	sendKeyResp, recvKeyResp, err := deriveSessionKeys(sharedSecret, false, localID, remoteID)
	if err != nil {
		t.Fatalf("responder key derivation failed: %v", err)
	}

	// The initiator's send key must equal the responder's recv key
	if !ConstantTimeEqual(sendKeyInit, recvKeyResp) {
		t.Error("initiator send key != responder recv key")
	}

	// The initiator's recv key must equal the responder's send key
	if !ConstantTimeEqual(recvKeyInit, sendKeyResp) {
		t.Error("initiator recv key != responder send key")
	}
}

// TestEncryptedConnReadWrite tests that encryptedConn satisfies the net.Conn
// interface correctly: Write returns len(p) on success, and Read returns
// partial data when the message is larger than the read buffer.
func TestEncryptedConnReadWrite(t *testing.T) {
	key1, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	key2, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	var wg sync.WaitGroup
	var serverConn net.Conn

	wg.Add(1)
	go func() {
		defer wg.Done()
		raw, err := listener.Accept()
		if err != nil {
			t.Errorf("accept failed: %v", err)
			return
		}
		serverConn, err = performServerHandshake(raw, key2, false)
		if err != nil {
			t.Errorf("handshake failed: %v", err)
			return
		}
	}()

	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	clientConn, err := performClientHandshake(raw, key1, derivePeerIDFromKeyPair(key1), "", computeTestPoWNonce(t, key1))
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	wg.Wait()
	defer clientConn.Close()
	defer serverConn.Close()

	// Client writes a large message
	largeMsg := make([]byte, 4096)
	for i := range largeMsg {
		largeMsg[i] = byte(i % 256)
	}
	n, err := clientConn.Write(largeMsg)
	if err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	if n != len(largeMsg) {
		t.Errorf("client write returned %d, want %d", n, len(largeMsg))
	}

	// Server reads in two smaller buffers (partial reads)
	buf1 := make([]byte, 1024)
	n1, err := serverConn.Read(buf1)
	if err != nil {
		t.Fatalf("server first read failed: %v", err)
	}
	buf2 := make([]byte, 4096)
	n2, err := serverConn.Read(buf2)
	if err != nil {
		t.Fatalf("server second read failed: %v", err)
	}
	combined := append(buf1[:n1], buf2[:n2]...)
	if len(combined) != len(largeMsg) {
		t.Errorf("total bytes read %d, want %d", len(combined), len(largeMsg))
	}
	for i := range combined {
		if combined[i] != largeMsg[i] {
			t.Errorf("byte at index %d: got 0x%02x, want 0x%02x", i, combined[i], largeMsg[i])
			break
		}
	}
}

// TestHandshakeResponseTooShort verifies that the client rejects a server
// response that is shorter than a Kyber768 ciphertext.
func TestHandshakeResponseTooShort(t *testing.T) {
	clientKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientPeerID := derivePeerIDFromKeyPair(clientKey)

	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()

	go func() {
		defer serverEnd.Close()
		var lenBuf [4]byte
		if _, err := io.ReadFull(serverEnd, lenBuf[:]); err != nil {
			return
		}
		length := binary.BigEndian.Uint32(lenBuf[:])
		msg := make([]byte, length)
		if _, err := io.ReadFull(serverEnd, msg); err != nil {
			return
		}
		var respLen [4]byte
		binary.BigEndian.PutUint32(respLen[:], uint32(10))
		serverEnd.Write(respLen[:])
		serverEnd.Write(make([]byte, 10))
	}()

	_, err = performClientHandshake(clientEnd, clientKey, clientPeerID, "", 0)
	if err == nil {
		t.Error("expected error for short server response, got nil")
	}
}

// TestHandshakeInvalidLength verifies that malformed handshake messages
// (wrong length) are rejected by performServerHandshake.
func TestHandshakeInvalidLength(t *testing.T) {
	key, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	// Send a handshake message with wrong length (too short)
	go func() {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(100)) // wrong size
		w.Write(lenBuf[:])
		w.Write(make([]byte, 100))
	}()

	_, err = performServerHandshake(r, key, false)
	if err == nil {
		t.Error("expected error for invalid handshake length, got nil")
	}
}
