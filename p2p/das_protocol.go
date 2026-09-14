// Quantaureum Node source, version 1.0.0.
package p2p

// DAS Protocol Bridge — P0-10 (2026-07-14)
//
// Bridges the P2P layer (Host) with the encoding.BlobNetworkManager.
// BlobNetworkManager expects two injectable functions:
//   - peerGetter: sends a DASSampleRequest to a peer and returns the response
//   - peerList:   returns the list of connected peers for DAS sampling
//
// This file provides factory functions that create these closures backed by
// the P2P Host. The node layer (node/node.go) calls NewDASPeerGetter and
// NewDASPeerList and injects them into BlobNetworkManager via SetPeerGetter
// and SetPeerList.

import (
	"encoding/binary"
	"errors"
	"log"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/encoding"
)

// DASProtocol wraps a P2P Host and provides DAS-specific operations.
// P0-10 (2026-07-14)
type DASProtocol struct {
	host *Host

	// P1-12 (RPC-H1, 2026-07-19): Monotonic counter for generating unique
	// RequestIDs. We start at 1 (not 0) so RequestID=0 remains a sentinel
	// meaning "uninitialized" / "legacy frame" — useful for debugging.
	// Atomic ops avoid the need for a mutex on the counter itself; the
	// per-request routing state lives in Host.dasPending.
	requestIDCounter uint64
}

// NewDASProtocol creates a new DAS protocol handler backed by the given Host.
// P0-10 (2026-07-14)
func NewDASProtocol(host *Host) *DASProtocol {
	return &DASProtocol{host: host}
}

// DASRequestTimeout is the maximum time to wait for a DAS sample response.
// P0-10 (2026-07-14): 5 seconds balances responsiveness vs. hanging on
// unresponsive peers. The DAS client retries with other peers on timeout.
const DASRequestTimeout = 5 * time.Second

// ErrDASRequestTimeout is returned when a DAS sample request times out.
// P0-10 (2026-07-14)
var ErrDASRequestTimeout = errors.New("DAS sample request timed out")

// ErrDASNoPeers is returned when no peers are available for DAS sampling.
// P0-10 (2026-07-14)
var ErrDASNoPeers = errors.New("no peers available for DAS sampling")

// SendSampleRequest sends a DAS sample request to a specific peer and waits
// for the response. This is the synchronous peerGetter function expected by
// BlobNetworkManager.
//
// P1-12 (RPC-H1, 2026-07-19 FIX): Previously this function read responses
// from a SHARED broadcast channel (host.SubscribeDASResponses()). That design
// assumed sequential sampling — one in-flight request at a time — but the
// DASClient actually spawns sampleWithTimeout goroutines that can run
// concurrently under parallel sampling. With the shared channel, a response
// for request A could be consumed by request B's caller, allowing:
//
//  1. A malicious peer to inject a forged cell that gets matched to the
//     wrong requester (data integrity violation).
//  2. A slow response arriving after the requester timed out getting
//     matched to a later, unrelated request (silent corruption).
//  3. Response starvation: one sampler pre-empting another's responses.
//
// FIX: Each call now generates a unique RequestID, registers a per-request
// pending channel with the Host, and writes the RequestID into the wire-level
// DASSampleRequest header (encoding.DASSampleRequestSize = 28 bytes).
// The responder echoes the RequestID in the response header; the Host's
// handleDASProtocol reads the RequestID from the incoming response and
// dispatches it to the matching pending channel. Responses with no matching
// pending channel (late/unsolicited/forged) are dropped.
//
// IMPORTANT: This function is now concurrency-safe. Multiple goroutines may
// call it simultaneously; each will receive its own response. The caller
// must still pass through the existing data[0:8] = RequestID field — if data
// is shorter than 8 bytes, this function writes the RequestID itself.
func (p *DASProtocol) SendSampleRequest(peerID string, msgType uint8, data []byte) ([]byte, error) {
	if p.host == nil {
		return nil, errors.New("DAS protocol: nil host")
	}

	// P1-12: Validate payload size. The caller (BlobNetworkManager.RequestCell)
	// produces a DASSampleRequest via encodeDASSampleRequest, which always
	// emits exactly DASSampleRequestSize bytes. Reject anything shorter to
	// guarantee we have room to inject the RequestID without truncating
	// existing fields.
	if len(data) < encoding.DASSampleRequestSize {
		return nil, errors.New("DAS protocol: payload too short for DASSampleRequest")
	}

	// R33 P2-12 FIX (2026-07-28): Previously this function wrote the
	// RequestID directly into the caller-supplied `data` slice (line below
	// was `binary.BigEndian.PutUint64(data[0:8], requestID)`). This mutated
	// the caller's buffer, violating the implicit contract that a "send"
	// function should not modify its inputs. Concrete harms:
	//   1. If the caller reuses the same `data` buffer across multiple
	//      peers (parallel sampling fan-out), the RequestID written for
	//      peer A would be silently overwritten when the same buffer was
	//      passed for peer B, corrupting the per-request routing that
	//      P1-12 introduced — responses would be matched to the wrong
	//      requester, enabling the cross-requester confusion P1-12 fixed.
	//   2. The caller's encoded DASSampleRequest (which encodes cell index,
	//      blob index, etc.) would have its first 8 bytes clobbered if the
	//      caller inspected or re-broadcast `data` after this call.
	// Fix: copy the input into a local buffer and write the RequestID into
	// the copy. The original `data` is left untouched.
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	// P1-12: Generate a fresh RequestID. atomic.AddUint64 wraps around at
	// uint64 max — acceptable (would take ~584 years at 1B requests/sec).
	// Start at 1 so RequestID=0 remains a sentinel for "uninitialized".
	requestID := atomic.AddUint64(&p.requestIDCounter, 1)

	// P1-12: Write the RequestID into the request header (bytes [0:8]).
	// The caller (BlobNetworkManager.RequestCell) leaves RequestID=0 in
	// the encoded buffer because it doesn't know the per-call ID — we
	// overwrite it here at the protocol boundary (in the copy, not the
	// caller's original buffer — see R33 P2-12 FIX above).
	binary.BigEndian.PutUint64(dataCopy[0:8], requestID)

	// P1-12: Register a per-request pending channel BEFORE sending the
	// request. If we sent first and registered second, a fast peer could
	// return a response before we registered, and handleDASProtocol would
	// drop it (no pending channel found). Register-then-send guarantees
	// the channel exists when the response arrives.
	respCh := p.host.RegisterDASResponseChannel(requestID)
	defer p.host.UnregisterDASResponseChannel(requestID)

	// Send the request to the peer.
	if err := p.host.SendDASSampleRequest(PeerID(peerID), dataCopy); err != nil {
		return nil, err
	}

	// Wait for the response with a timeout. The pending channel is buffered
	// (capacity 1) so handleDASProtocol's non-blocking send will succeed even
	// if we're slow to start selecting — the response sits in the channel
	// until we read it (or until defer-unregister removes the channel).
	//
	// RPC-M4 (R8 2026-07-19 FIX): Verify that the response came from the
	// peer we sent the request to. The P1-12 fix added RequestID-based
	// routing to prevent cross-REQUESTER confusion (one sampler stealing
	// another's response), but routing by RequestID alone does not
	// prevent cross-PEER forgery: any peer that observes or guesses the
	// RequestID (sent in cleartext in the request header at line 108) can
	// emit a MsgTypeDASSampleResp with that ID and have it routed to this
	// pending channel. The resulting payload is then returned to the
	// caller as if it came from the intended peer, allowing data-injection
	// attacks (forged cell/blob substitution). Compare resp.From to the
	// expected peerID and drop forgeries, continuing to wait for the real
	// response until the timer expires.
	expectedPeer := PeerID(peerID)
	timer := time.NewTimer(DASRequestTimeout)
	defer timer.Stop()

	for {
		select {
		case resp := <-respCh:
			if resp.From != expectedPeer {
				// Forged or misrouted response. Log and keep waiting for
				// the legitimate response. We do NOT return an error
				// here because the real peer may still respond before
				// the timeout — erroring out early would let an
				// attacker trivially DoS the sampler by sending one
				// forged frame per request.
				log.Printf("DAS: dropping response for RequestID=%d from unexpected peer %s (expected %s)",
					requestID, resp.From, expectedPeer)
				continue
			}
			return resp.Payload, nil
		case <-timer.C:
			return nil, ErrDASRequestTimeout
		case <-p.host.ctx.Done():
			return nil, p.host.ctx.Err()
		}
	}
}

// GetConnectedPeers returns the list of connected, non-blacklisted peer IDs.
// This is the peerList function expected by BlobNetworkManager.
// P0-10 (2026-07-14)
func (p *DASProtocol) GetConnectedPeers() []string {
	if p.host == nil {
		return nil
	}
	peers := p.host.Peers()
	result := make([]string, 0, len(peers))
	for _, peer := range peers {
		if peer.Connected {
			result = append(result, string(peer.ID))
		}
	}
	return result
}

// NewDASPeerGetter creates a peerGetter function for BlobNetworkManager.
// The returned function sends a DAS sample request to a peer and waits for
// the response.
// P0-10 (2026-07-14)
func NewDASPeerGetter(host *Host) func(peerID string, msgType uint8, data []byte) ([]byte, error) {
	proto := NewDASProtocol(host)
	return proto.SendSampleRequest
}

// NewDASPeerList creates a peerList function for BlobNetworkManager.
// The returned function returns the list of connected peer IDs.
// P0-10 (2026-07-14)
func NewDASPeerList(host *Host) func() []string {
	proto := NewDASProtocol(host)
	return proto.GetConnectedPeers
}
