package trie

import (
	"bytes"
	"testing"
)

// M4-ORDER-ROOT: root must be a pure function of the key-value SET, not of
// insertion order. Reproduces the fresh-replay vs producer-trie divergence:
// a producer grows its trie via StateDB.Copy()+Put per block, while a
// freshly re-synced node re-Puts the same accounts in replay order. If the
// tree structure (and thus Hash()) depends on insertion order, the two nodes
// derive different state roots for identical logical state — the M4 residual.
func TestVerkleRootIndependentOfInsertionOrder(t *testing.T) {
	kvs := [][2][]byte{
		{must32(t, 1), []byte("value-one")},
		{must32(t, 2), []byte("value-two")},
		{must32(t, 3), []byte("value-three")},
		{must32(t, 4), []byte("value-four")},
		{must32(t, 5), []byte("value-five")},
		{must32(t, 6), []byte("value-six")},
		{must32(t, 7), []byte("value-seven")},
		{must32(t, 8), []byte("value-eight")},
	}

	forward := NewVerkleTree(0)
	for _, kv := range kvs {
		if err := forward.Put(kv[0], kv[1]); err != nil {
			t.Fatalf("forward put: %v", err)
		}
	}

	reverse := NewVerkleTree(0)
	for i := len(kvs) - 1; i >= 0; i-- {
		if err := reverse.Put(kvs[i][0], kvs[i][1]); err != nil {
			t.Fatalf("reverse put: %v", err)
		}
	}

	fRoot, rRoot := forward.Root(), reverse.Root()
	if !bytes.Equal(fRoot[:], rRoot[:]) {
		t.Fatalf("M4-ORDER-ROOT: roots differ for identical content:\n  forward=%x\n  reverse=%x", fRoot[:8], rRoot[:8])
	}
}

func must32(t *testing.T, b byte) []byte {
	t.Helper()
	key := make([]byte, 32)
	key[0] = b
	return key
}
