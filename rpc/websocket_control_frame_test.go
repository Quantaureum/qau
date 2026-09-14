// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

func TestReadMessageRejectsInvalidControlFrames(t *testing.T) {
	tests := []struct {
		name   string
		header byte
		length int
	}{
		{name: "fragmented ping", header: 0x09, length: 1},
		{name: "oversized ping", header: 0x89, length: 126},
		{name: "continuation control opcode", header: 0x8b, length: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			payload := bytes.Repeat([]byte{'x'}, tt.length)
			frame := []byte{tt.header, 0x80 | byte(tt.length)}
			if tt.length >= 126 {
				frame[1] = 0x80 | 126
				frame = append(frame, 0, byte(tt.length))
			}
			frame = append(frame, 1, 2, 3, 4)
			masked := append([]byte(nil), payload...)
			for i := range masked {
				masked[i] ^= frame[2+len(frame[2:])-4+i%4]
			}
			// Build the masked payload explicitly to keep the test frame valid.
			mask := []byte{1, 2, 3, 4}
			for i := range payload {
				masked[i] = payload[i] ^ mask[i%4]
			}
			frame = append(frame, masked...)

			go func() { _, _ = client.Write(frame) }()
			ws := &WebSocketServer{}
			_, err := ws.readMessage(&WSConn{conn: server, reader: bufio.NewReader(server), pongSem: make(chan struct{}, 1)})
			if err == nil {
				t.Fatalf("expected invalid control frame to be rejected")
			}
		})
	}
}
