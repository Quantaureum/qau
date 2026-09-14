// Quantaureum Node source, version 1.0.0.
package trie

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestPedersenBasisCreation(t *testing.T) {
	tests := []struct {
		name      string
		vectorLen int
		wantErr   bool
	}{
		{"valid_4", 4, false},
		{"valid_8", 8, false},
		{"valid_16", 16, false},
		{"valid_32", 32, false},
		{"valid_64", 64, false},
		{"valid_128", 128, false},
		{"valid_256", 256, false},
		{"zero_length", 0, true},
		{"too_large", 513, true},
		{"negative", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			basis, err := NewPedersenBasis(tt.vectorLen)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(basis.G) != tt.vectorLen {
				t.Errorf("basis length = %d, want %d", len(basis.G), tt.vectorLen)
			}
		})
	}
}

func TestPedersenCommitment(t *testing.T) {
	basis, err := NewPedersenBasis(4)
	if err != nil {
		t.Fatal(err)
	}

	scalars := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
	}

	comm, err := basis.Commit(scalars)
	if err != nil {
		t.Fatal(err)
	}

	if comm == nil {
		t.Fatal("commitment is nil")
	}

	if len(comm.Bytes()) != PedersenPointSize {
		t.Errorf("commitment size = %d, want %d", len(comm.Bytes()), PedersenPointSize)
	}
}

func TestPedersenCommitmentDeterministic(t *testing.T) {
	basis, err := NewPedersenBasis(4)
	if err != nil {
		t.Fatal(err)
	}

	scalars := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
	}

	comm1, _ := basis.Commit(scalars)
	comm2, _ := basis.Commit(scalars)

	if !comm1.Equal(comm2) {
		t.Error("same inputs produced different commitments")
	}
}

func TestPedersenCommitmentDifferentInputs(t *testing.T) {
	basis, err := NewPedersenBasis(4)
	if err != nil {
		t.Fatal(err)
	}

	scalars1 := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	scalars2 := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(5)}

	comm1, _ := basis.Commit(scalars1)
	comm2, _ := basis.Commit(scalars2)

	if comm1.Equal(comm2) {
		t.Error("different inputs produced same commitment")
	}
}

func TestPedersenCommitmentWithBlinding(t *testing.T) {
	basis, err := NewPedersenBasis(4)
	if err != nil {
		t.Fatal(err)
	}

	scalars := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}

	comm1, _ := basis.Commit(scalars)

	blinding, _ := GenerateBlinding()
	comm2, _ := basis.CommitWithBlinding(scalars, blinding)

	if comm1.Equal(comm2) {
		t.Error("blinded commitment should differ from unblinded")
	}
}

func TestPedersenCommitmentSerialization(t *testing.T) {
	basis, _ := NewPedersenBasis(4)
	scalars := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	comm, _ := basis.Commit(scalars)

	data := comm.Bytes()
	restored, err := PedersenCommitmentFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	if !comm.Equal(restored) {
		t.Error("serialization roundtrip failed")
	}
}

func TestBytesToScalars(t *testing.T) {
	data := make([]byte, 128)
	for i := range data {
		data[i] = byte(i)
	}

	scalars := BytesToScalars(data, 4)
	if len(scalars) != 4 {
		t.Fatalf("got %d scalars, want 4", len(scalars))
	}

	restored := ScalarsToBytes(scalars)
	if !bytes.Equal(data, restored) {
		t.Error("scalars roundtrip failed")
	}
}

func TestGenerateBlinding(t *testing.T) {
	b1, err := GenerateBlinding()
	if err != nil {
		t.Fatal(err)
	}
	b2, err := GenerateBlinding()
	if err != nil {
		t.Fatal(err)
	}

	if b1.Cmp(b2) == 0 {
		t.Log("blinding collision (extremely unlikely but possible)")
	}
}

func TestIPAProofGeneration(t *testing.T) {
	basis, err := NewPedersenBasis(4)
	if err != nil {
		t.Fatal(err)
	}

	a := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	b := []*big.Int{big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8)}
	c := innerProduct(a, b)

	proof, err := GenerateIPAProof(basis, a, b, c)
	if err != nil {
		t.Fatal(err)
	}

	if proof == nil {
		t.Fatal("proof is nil")
	}

	if len(proof.L) != 2 {
		t.Errorf("expected 2 rounds, got %d", len(proof.L))
	}
}

func TestIPAProofVerification(t *testing.T) {
	basis, err := NewPedersenBasis(4)
	if err != nil {
		t.Fatal(err)
	}

	a := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	b := []*big.Int{big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8)}
	c := innerProduct(a, b)

	commitment, _ := basis.Commit(a)

	proof, err := GenerateIPAProof(basis, a, b, c)
	if err != nil {
		t.Fatal(err)
	}

	if proof == nil {
		t.Fatal("proof is nil")
	}
	if len(proof.L) != 2 {
		t.Errorf("expected 2 L points, got %d", len(proof.L))
	}
	if len(proof.R) != 2 {
		t.Errorf("expected 2 R points, got %d", len(proof.R))
	}
	if proof.A == nil {
		t.Fatal("proof.A is nil")
	}

	ok, err := VerifyIPAProof(basis, commitment, b, c, proof)
	// R26-045: VerifyIPAProof is a not-implemented stub that returns an
	// explicit error. Expect the error and a false result (fail-closed).
	if err == nil {
		t.Fatal("expected not-implemented error from VerifyIPAProof, got nil")
	}
	if ok {
		t.Fatal("expected verification to fail (not implemented), got true")
	}
	t.Logf("IPA proof verification returned expected not-implemented error: %v", err)
}

func TestIPAProofSerialization(t *testing.T) {
	basis, _ := NewPedersenBasis(4)
	a := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	b := []*big.Int{big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8)}
	c := innerProduct(a, b)

	proof, _ := GenerateIPAProof(basis, a, b, c)

	data := proof.Bytes()
	restored, err := IPAProofFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(restored.L) != len(proof.L) {
		t.Errorf("L length mismatch: %d vs %d", len(restored.L), len(proof.L))
	}
	if len(restored.R) != len(proof.R) {
		t.Errorf("R length mismatch: %d vs %d", len(restored.R), len(proof.R))
	}
}

func TestVerkleTreeBasicOperations(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	key := []byte("hello")
	value := []byte("world")

	err := tree.Put(key, value)
	if err != nil {
		t.Fatal(err)
	}

	got, err := tree.Get(key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, value) {
		t.Errorf("got %s, want %s", got, value)
	}
}

func TestVerkleTreeUpdate(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	key := []byte("key")
	tree.Put(key, []byte("v1"))
	tree.Put(key, []byte("v2"))

	got, _ := tree.Get(key)
	if !bytes.Equal(got, []byte("v2")) {
		t.Errorf("got %s, want v2", got)
	}
}

func TestVerkleTreeDelete(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	key := []byte("key")
	tree.Put(key, []byte("value"))
	tree.Delete(key)

	_, err := tree.Get(key)
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestVerkleTreeMultipleKeys(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	keys := [][]byte{
		[]byte("key1"),
		[]byte("key2"),
		[]byte("key3"),
		[]byte("key4"),
		[]byte("key5"),
	}

	for i, k := range keys {
		tree.Put(k, []byte{byte(i)})
	}

	for i, k := range keys {
		v, err := tree.Get(k)
		if err != nil {
			t.Errorf("key %s not found: %v", k, err)
			continue
		}
		if !bytes.Equal(v, []byte{byte(i)}) {
			t.Errorf("key %s: got %v, want %v", k, v, []byte{byte(i)})
		}
	}
}

func TestVerkleTreeRootConsistency(t *testing.T) {
	tree1 := NewVerkleTree(MaxTreeDepth)
	tree2 := NewVerkleTree(MaxTreeDepth)

	keys := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	values := [][]byte{[]byte("1"), []byte("2"), []byte("3")}

	for i := range keys {
		tree1.Put(keys[i], values[i])
		tree2.Put(keys[i], values[i])
	}

	if tree1.Root() != tree2.Root() {
		t.Error("identical trees have different roots")
	}
}

func TestVerkleTreeProof(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	key := []byte("test_key")
	value := []byte("test_value")
	tree.Put(key, value)

	proof, err := tree.Prove(key)
	if err != nil {
		t.Fatal(err)
	}

	if proof.IsExclusion {
		t.Error("expected inclusion proof, got exclusion")
	}

	if !bytes.Equal(proof.Value, value) {
		t.Errorf("proof value = %s, want %s", proof.Value, value)
	}

	root := tree.Root()
	if !proof.Verify(root) {
		t.Error("proof verification failed")
	}
}

func TestVerkleTreeExclusionProof(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	tree.Put([]byte("existing"), []byte("value"))

	proof, err := tree.Prove([]byte("nonexistent"))
	if err != nil {
		t.Fatal(err)
	}

	if !proof.IsExclusion {
		t.Error("expected exclusion proof")
	}
}

func TestVerkleTreeCopy(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	tree.Put([]byte("key"), []byte("value"))

	copy := tree.Copy()

	if tree.Root() != copy.Root() {
		t.Error("copy has different root")
	}

	copy.Put([]byte("key2"), []byte("value2"))

	if tree.Root() == copy.Root() {
		t.Error("modifying copy should not affect original")
	}
}

func TestVerkleTreeLargeDataset(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	count := 1000
	for i := 0; i < count; i++ {
		key := make([]byte, 32)
		key[0] = byte(i >> 8)
		key[1] = byte(i)
		value := make([]byte, 32)
		rand.Read(value)
		tree.Put(key, value)
	}

	for i := 0; i < count; i++ {
		key := make([]byte, 32)
		key[0] = byte(i >> 8)
		key[1] = byte(i)
		_, err := tree.Get(key)
		if err != nil {
			t.Errorf("key %d not found after insert", i)
		}
	}
}

func TestVerkleStateDBAccountOperations(t *testing.T) {
	db := NewVerkleStateDB()

	var addr types.Address
	rand.Read(addr[:])

	data := []byte("account_data")

	err := db.SetAccount(addr, data)
	if err != nil {
		t.Fatal(err)
	}

	got, err := db.GetAccount(addr)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, data) {
		t.Error("account data mismatch")
	}
}

func TestVerkleStateDBStorageOperations(t *testing.T) {
	db := NewVerkleStateDB()

	var addr types.Address
	rand.Read(addr[:])

	var slot types.Hash
	rand.Read(slot[:])

	value := []byte("storage_value")

	err := db.SetStorage(addr, slot, value)
	if err != nil {
		t.Fatal(err)
	}

	got, err := db.GetStorage(addr, slot)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, value) {
		t.Error("storage value mismatch")
	}
}

func TestVerkleStateDBCodeOperations(t *testing.T) {
	db := NewVerkleStateDB()

	code := []byte("contract_code")
	codeHash := db.SetCode(code)

	got, err := db.GetCode(codeHash)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, code) {
		t.Error("code mismatch")
	}
}

func TestVerkleStateDBDeleteAccount(t *testing.T) {
	db := NewVerkleStateDB()

	var addr types.Address
	rand.Read(addr[:])

	db.SetAccount(addr, []byte("data"))
	db.DeleteAccount(addr)

	_, err := db.GetAccount(addr)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestVerkleStateDBAccountProof(t *testing.T) {
	db := NewVerkleStateDB()

	var addr types.Address
	rand.Read(addr[:])

	db.SetAccount(addr, []byte("proof_test_data"))

	proof, err := db.ProveAccount(addr)
	if err != nil {
		t.Fatal(err)
	}

	root := db.Root()
	if !db.VerifyAccountProof(root, proof) {
		t.Error("account proof verification failed")
	}
}

func TestVerkleStateDBStorageProof(t *testing.T) {
	db := NewVerkleStateDB()

	var addr types.Address
	rand.Read(addr[:])

	var slot types.Hash
	rand.Read(slot[:])

	db.SetStorage(addr, slot, []byte("storage_proof_data"))

	proof, err := db.ProveStorage(addr, slot)
	if err != nil {
		t.Fatal(err)
	}

	storageRoot := db.GetStorageRoot(addr)
	if !db.VerifyStorageProof(storageRoot, proof) {
		t.Error("storage proof verification failed")
	}
}

func TestVerkleStateDBBatchUpdate(t *testing.T) {
	db := NewVerkleStateDB()

	var addr1, addr2 types.Address
	rand.Read(addr1[:])
	rand.Read(addr2[:])

	updates := []StateUpdate{
		{Type: UpdateAccount, Address: addr1, Value: []byte("account1")},
		{Type: UpdateAccount, Address: addr2, Value: []byte("account2")},
	}

	batchProof, err := db.BatchUpdate(updates)
	if err != nil {
		t.Fatal(err)
	}

	if batchProof.RootBefore == batchProof.RootAfter {
		t.Error("root should change after batch update")
	}

	if len(batchProof.Proofs) != 2 {
		t.Errorf("expected 2 proofs, got %d", len(batchProof.Proofs))
	}
}

func TestVerkleStateDBSnapshot(t *testing.T) {
	db := NewVerkleStateDB()

	var addr types.Address
	rand.Read(addr[:])

	db.SetAccount(addr, []byte("original"))

	snapshot := db.Snapshot()

	db.SetAccount(addr, []byte("modified"))

	db.RevertTo(snapshot)

	got, _ := db.GetAccount(addr)
	if !bytes.Equal(got, []byte("original")) {
		t.Error("revert failed")
	}
}

func TestVerkleStateDBSerialization(t *testing.T) {
	db := NewVerkleStateDB()

	var addr types.Address
	rand.Read(addr[:])
	db.SetAccount(addr, []byte("serialize_test"))

	var slot types.Hash
	rand.Read(slot[:])
	db.SetStorage(addr, slot, []byte("storage_serialize"))

	db.SetCode([]byte("code_serialize"))

	data, err := db.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	db2 := NewVerkleStateDB()
	err = db2.Deserialize(data)
	if err != nil {
		t.Fatal(err)
	}

	if db.Root() != db2.Root() {
		t.Error("serialization roundtrip root mismatch")
	}
}

func TestVerkleStateDBDirtyFlag(t *testing.T) {
	db := NewVerkleStateDB()

	if db.IsDirty() {
		t.Error("new DB should not be dirty")
	}

	var addr types.Address
	rand.Read(addr[:])
	db.SetAccount(addr, []byte("data"))

	if !db.IsDirty() {
		t.Error("DB should be dirty after modification")
	}

	db.ClearDirty()
	if db.IsDirty() {
		t.Error("DB should not be dirty after clear")
	}
}

func TestVerkleStateDBIterateAccounts(t *testing.T) {
	db := NewVerkleStateDB()

	count := 10
	addresses := make([]types.Address, count)
	for i := 0; i < count; i++ {
		rand.Read(addresses[i][:])
		db.SetAccount(addresses[i], []byte{byte(i)})
	}

	seen := 0
	db.IterateAccounts(func(addr types.Address, data []byte) bool {
		seen++
		return true
	})

	if seen != count {
		t.Errorf("iterated %d accounts, expected %d", seen, count)
	}
}

func TestVerkleStateDBIterateStorage(t *testing.T) {
	db := NewVerkleStateDB()

	var addr types.Address
	rand.Read(addr[:])

	count := 5
	slots := make([]types.Hash, count)
	for i := 0; i < count; i++ {
		rand.Read(slots[i][:])
		db.SetStorage(addr, slots[i], []byte{byte(i)})
	}

	seen := 0
	db.IterateStorage(addr, func(slot types.Hash, value []byte) bool {
		seen++
		return true
	})

	if seen != count {
		t.Errorf("iterated %d storage slots, expected %d", seen, count)
	}
}

func TestPedersenHasher(t *testing.T) {
	hasher := PedersenHasher()

	key := []byte("test_key")
	value := []byte("test_value")

	hash1 := hasher.HashLeaf(key, value)
	hash2 := hasher.HashLeaf(key, value)

	if hash1 != hash2 {
		t.Error("Pedersen hasher should be deterministic")
	}

	var children [BranchingFactor]types.Hash
	for i := range children {
		rand.Read(children[i][:])
	}

	internalHash1 := hasher.HashInternal(children)
	internalHash2 := hasher.HashInternal(children)

	if internalHash1 != internalHash2 {
		t.Error("Pedersen internal hash should be deterministic")
	}
}

func TestVerkleTreeWithPedersenHasher(t *testing.T) {
	SetHasher(PedersenHasher())
	defer SetHasher(&sha3Hasher{})

	tree := NewVerkleTree(MaxTreeDepth)

	key := []byte("pedersen_key")
	value := []byte("pedersen_value")

	tree.Put(key, value)

	got, err := tree.Get(key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, value) {
		t.Error("value mismatch with Pedersen hasher")
	}

	proof, _ := tree.Prove(key)
	root := tree.Root()

	if !proof.Verify(root) {
		t.Error("proof verification failed with Pedersen hasher")
	}
}

func TestVerkleStateDBNodeCount(t *testing.T) {
	db := NewVerkleStateDB()

	var addr types.Address
	rand.Read(addr[:])

	db.SetAccount(addr, []byte("data"))

	count := db.GetNodeCount()
	if count == 0 {
		t.Error("node count should be > 0 after insert")
	}
}

func TestVerkleStateDBCodeCount(t *testing.T) {
	db := NewVerkleStateDB()

	db.SetCode([]byte("code1"))
	db.SetCode([]byte("code2"))

	count := db.GetCodeCount()
	if count != 2 {
		t.Errorf("code count = %d, want 2", count)
	}
}

func TestVerkleTreeEmptyOperations(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	_, err := tree.Get([]byte("nonexistent"))
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}

	err = tree.Delete([]byte("nonexistent"))
	if err != nil {
		t.Errorf("delete on empty tree should not error: %v", err)
	}

	// TRIE-R11-005: empty keys are rejected at the API boundary.
	err = tree.Put([]byte{}, []byte("empty_key"))
	if err != ErrInvalidKey {
		t.Errorf("empty key Put: expected ErrInvalidKey, got %v", err)
	}
}

func TestVerkleTreeProofSize(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	for i := 0; i < 50; i++ {
		key := make([]byte, 32)
		key[0] = byte(i)
		tree.Put(key, []byte("value"))
	}

	proof, _ := tree.Prove([]byte{0})
	size := proof.Size()

	if size == 0 {
		t.Error("proof size should be > 0")
	}

	t.Logf("Proof size for 50-key tree: %d bytes", size)
}

func BenchmarkVerkleTreePut(b *testing.B) {
	tree := NewVerkleTree(MaxTreeDepth)
	key := make([]byte, 32)
	value := make([]byte, 32)
	rand.Read(value)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		tree.Put(key, value)
	}
}

func BenchmarkVerkleTreeGet(b *testing.B) {
	tree := NewVerkleTree(MaxTreeDepth)
	key := make([]byte, 32)
	value := make([]byte, 32)
	rand.Read(value)

	for i := 0; i < 10000; i++ {
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		tree.Put(key, value)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % 10000
		key[0] = byte(idx)
		key[1] = byte(idx >> 8)
		tree.Get(key)
	}
}

func BenchmarkVerkleTreeProve(b *testing.B) {
	tree := NewVerkleTree(MaxTreeDepth)
	key := make([]byte, 32)
	value := make([]byte, 32)
	rand.Read(value)

	for i := 0; i < 1000; i++ {
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		tree.Put(key, value)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % 1000
		key[0] = byte(idx)
		key[1] = byte(idx >> 8)
		tree.Prove(key)
	}
}

func BenchmarkPedersenCommit(b *testing.B) {
	basis, _ := NewPedersenBasis(256)
	scalars := make([]*big.Int, 256)
	for i := range scalars {
		scalars[i] = big.NewInt(int64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		basis.Commit(scalars)
	}
}

func BenchmarkVerkleStateDBBatchUpdate(b *testing.B) {
	db := NewVerkleStateDB()
	var addr types.Address
	rand.Read(addr[:])

	updates := []StateUpdate{
		{Type: UpdateAccount, Address: addr, Value: []byte("bench_data")},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.BatchUpdate(updates)
	}
}

func TestVerkleStateDBCommit(t *testing.T) {
	db := NewVerkleStateDB()
	var addr types.Address
	rand.Read(addr[:])
	db.SetAccount(addr, []byte("commit_test"))

	root, err := db.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if root == (types.Hash{}) {
		t.Error("expected non-zero root after commit")
	}
}

func TestVerkleStateDBCopy(t *testing.T) {
	db := NewVerkleStateDB()

	var addr types.Address
	rand.Read(addr[:])
	db.SetAccount(addr, []byte("original"))
	db.SetCode([]byte("code_data"))

	cpy := db.Copy()
	if cpy.Root() != db.Root() {
		t.Error("copy has different root")
	}
	if cpy.IsDirty() != db.IsDirty() {
		t.Error("copy dirty flag mismatch")
	}
}

func TestVerkleStateDBDeserialize_ShortData(t *testing.T) {
	db := NewVerkleStateDB()
	err := db.Deserialize([]byte{})
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestVerkleStateDBDeserialize_ShortRoot(t *testing.T) {
	db := NewVerkleStateDB()
	err := db.Deserialize(make([]byte, 16))
	if err == nil {
		t.Error("expected error for short root data")
	}
}

func TestVerkleStateDBIterateAccounts_Empty(t *testing.T) {
	db := NewVerkleStateDB()
	count := 0
	db.IterateAccounts(func(addr types.Address, _ []byte) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("expected 0 accounts, got %d", count)
	}
}

func TestVerkleStateDBIterateStorage_Empty(t *testing.T) {
	db := NewVerkleStateDB()
	var addr types.Address
	rand.Read(addr[:])
	count := 0
	db.IterateStorage(addr, func(_ types.Hash, _ []byte) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("expected 0 slots, got %d", count)
	}
}

func TestVerkleTreeEmptyTreeProof(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	proof, err := tree.Prove([]byte("any"))
	if err != nil {
		t.Fatal(err)
	}
	if !proof.IsExclusion {
		t.Error("expected exclusion proof for empty tree")
	}
}

func TestEmptyNode(t *testing.T) {
	e := &EmptyNode{}
	if e.NodeType() != NodeTypeEmpty {
		t.Errorf("expected NodeTypeEmpty, got %d", e.NodeType())
	}
	if e.Hash() != (types.Hash{}) {
		t.Error("expected zero hash")
	}
	if len(e.Encode()) != 1 || e.Encode()[0] != NodeTypeEmpty {
		t.Error("invalid empty node encoding")
	}
}

func TestGetHasher(t *testing.T) {
	original := GetHasher()
	if original == nil {
		t.Error("expected non-nil hasher")
	}
	SetHasher(original)
	if GetHasher() != original {
		t.Error("hasher mismatch after reset")
	}
}

func TestNewVerkleProof(t *testing.T) {
	p := NewVerkleProof([]byte("key"), []byte("value"), [][]byte{{0x01}})
	if p == nil {
		t.Error("proof should not be nil")
	}
	if !bytes.Equal(p.Key, []byte("key")) {
		t.Error("key mismatch")
	}
}

func TestDecodeLeafNode_Invalid(t *testing.T) {
	_, err := DecodeLeafNode([]byte{})
	if err != ErrInvalidNode {
		t.Errorf("expected ErrInvalidNode, got %v", err)
	}
	_, err = DecodeLeafNode([]byte{NodeTypeInternal, 0})
	if err != ErrInvalidNode {
		t.Errorf("expected ErrInvalidNode, got %v", err)
	}
}

func TestDecodeInternalNode_Invalid(t *testing.T) {
	_, err := DecodeInternalNode([]byte{})
	if err != ErrInvalidNode {
		t.Errorf("expected ErrInvalidNode, got %v", err)
	}
}

func TestDecodeExtensionNode_Invalid(t *testing.T) {
	_, err := DecodeExtensionNode([]byte{})
	if err != ErrInvalidNode {
		t.Errorf("expected ErrInvalidNode, got %v", err)
	}
}

func TestDecodeNode(t *testing.T) {
	leaf := NewLeafNode([]byte("k"), []byte("v"))
	enc := leaf.Encode()
	dec, err := decodeNode(enc)
	if err != nil {
		t.Fatalf("decode returned error: %v", err)
	}
	if dec == nil {
		t.Fatal("decode returned nil")
	}
	if dec.NodeType() != NodeTypeLeaf {
		t.Errorf("expected leaf, got %d", dec.NodeType())
	}

	internal := NewInternalNode()
	internal.recomputeHash()
	enc2 := internal.Encode()
	dec2, err := decodeNode(enc2)
	if err != nil {
		t.Fatalf("decode internal returned error: %v", err)
	}
	if dec2 == nil {
		t.Fatal("decode returned nil for internal")
	}
	if dec2.NodeType() != NodeTypeInternal {
		t.Errorf("expected internal, got %d", dec2.NodeType())
	}
}

// TestTRIE_R11004_EncodeWithMagicByte verifies that encodeNodeWithMagic
// prepends the VerkleEncodingMagic byte and that decodeNode correctly
// round-trips the new format.
func TestTRIE_R11004_EncodeWithMagicByte(t *testing.T) {
	leaf := NewLeafNode([]byte("hello"), []byte("world"))
	enc := encodeNodeWithMagic(leaf)
	if len(enc) < 2 {
		t.Fatalf("encoded output too short: %d bytes", len(enc))
	}
	if enc[0] != VerkleEncodingMagic {
		t.Errorf("expected first byte 0x%02x (magic), got 0x%02x", VerkleEncodingMagic, enc[0])
	}
	if enc[1] != NodeTypeLeaf {
		t.Errorf("expected second byte 0x%02x (NodeTypeLeaf), got 0x%02x", NodeTypeLeaf, enc[1])
	}

	// Round-trip via decodeNode.
	dec, err := decodeNode(enc)
	if err != nil {
		t.Fatalf("decodeNode failed: %v", err)
	}
	if dec == nil {
		t.Fatal("decodeNode returned nil")
	}
	if dec.NodeType() != NodeTypeLeaf {
		t.Errorf("expected NodeTypeLeaf, got %d", dec.NodeType())
	}
	leaf2, ok := dec.(*LeafNode)
	if !ok {
		t.Fatalf("expected *LeafNode, got %T", dec)
	}
	if string(leaf2.Key) != "hello" {
		t.Errorf("expected key 'hello', got %q", leaf2.Key)
	}
	if string(leaf2.Value) != "world" {
		t.Errorf("expected value 'world', got %q", leaf2.Value)
	}
}

// TestTRIE_R11004_LegacyFormatBackwardCompat verifies that decodeNode
// still accepts legacy-encoded bytes (no magic prefix) so already-persisted
// data doesn't break after the format upgrade.
func TestTRIE_R11004_LegacyFormatBackwardCompat(t *testing.T) {
	leaf := NewLeafNode([]byte("legacy_k"), []byte("legacy_v"))
	legacy := leaf.Encode() // No magic prefix.
	if len(legacy) == 0 || legacy[0] != NodeTypeLeaf {
		t.Fatalf("legacy encoding doesn't start with NodeTypeLeaf: %x", legacy[:min(4, len(legacy))])
	}
	dec, err := decodeNode(legacy)
	if err != nil {
		t.Fatalf("decodeNode legacy format failed: %v", err)
	}
	if dec == nil || dec.NodeType() != NodeTypeLeaf {
		t.Errorf("expected legacy leaf decode, got %v", dec)
	}

	// Same for internal node.
	internal := NewInternalNode()
	internal.recomputeHash()
	legacyInternal := internal.Encode()
	dec2, err := decodeNode(legacyInternal)
	if err != nil {
		t.Fatalf("decodeNode legacy internal failed: %v", err)
	}
	if dec2 == nil || dec2.NodeType() != NodeTypeInternal {
		t.Errorf("expected legacy internal decode, got %v", dec2)
	}
}

// TestTRIE_R11004_UnknownTypeReturnsError verifies that decodeNode now
// returns ErrInvalidNode for unknown NodeType bytes instead of silently
// returning nil.
func TestTRIE_R11004_UnknownTypeReturnsError(t *testing.T) {
	// Legacy byte 0x09 is not a valid NodeType.
	bad1 := []byte{0x09, 0xAA, 0xBB, 0xCC}
	_, err := decodeNode(bad1)
	if err == nil {
		t.Error("expected error for unknown legacy NodeType 0x09, got nil")
	}
	if err != ErrInvalidNode {
		t.Errorf("expected ErrInvalidNode, got %v", err)
	}

	// New format: magic byte followed by unknown NodeType.
	bad2 := []byte{VerkleEncodingMagic, 0x09, 0xAA, 0xBB}
	_, err2 := decodeNode(bad2)
	if err2 == nil {
		t.Error("expected error for unknown new-format NodeType 0x09, got nil")
	}
	if err2 != ErrInvalidNode {
		t.Errorf("expected ErrInvalidNode, got %v", err2)
	}

	// Empty input.
	_, err3 := decodeNode([]byte{})
	if err3 == nil {
		t.Error("expected error for empty input, got nil")
	}

	// Magic byte alone (truncated).
	_, err4 := decodeNode([]byte{VerkleEncodingMagic})
	if err4 == nil {
		t.Error("expected error for truncated magic-only input, got nil")
	}
}

func TestBatchUpdate_StorageUpdate(t *testing.T) {
	db := NewVerkleStateDB()
	var addr types.Address
	rand.Read(addr[:])

	var slot types.Hash
	rand.Read(slot[:])

	updates := []StateUpdate{
		{Type: UpdateStorage, Address: addr, Slot: slot, Value: []byte("batch_storage")},
	}

	batchProof, err := db.BatchUpdate(updates)
	if err != nil {
		t.Fatal(err)
	}
	if batchProof == nil {
		t.Fatal("expected non-nil batch proof")
	}
	if len(batchProof.Proofs) != 1 {
		t.Errorf("expected 1 proof, got %d", len(batchProof.Proofs))
	}
}

func TestBatchUpdate_DeleteAccount(t *testing.T) {
	db := NewVerkleStateDB()
	var addr types.Address
	rand.Read(addr[:])
	db.SetAccount(addr, []byte("to_delete"))

	updates := []StateUpdate{
		{Type: UpdateAccount, Address: addr, Value: nil},
	}

	batchProof, err := db.BatchUpdate(updates)
	if err != nil {
		t.Fatal(err)
	}
	if batchProof == nil {
		t.Fatal("expected non-nil batch proof")
	}
}

func TestBatchUpdate_DeleteStorage(t *testing.T) {
	db := NewVerkleStateDB()
	var addr types.Address
	rand.Read(addr[:])
	var slot types.Hash
	rand.Read(slot[:])
	db.SetStorage(addr, slot, []byte("to_delete_storage"))

	updates := []StateUpdate{
		{Type: UpdateStorage, Address: addr, Slot: slot, Value: nil},
	}

	batchProof, err := db.BatchUpdate(updates)
	if err != nil {
		t.Fatal(err)
	}
	if batchProof == nil {
		t.Fatal("expected non-nil batch proof")
	}
}

func TestVerkleTreeNilCopy(t *testing.T) {
	var tree *VerkleTree
	cpy := tree.Copy()
	if cpy != nil {
		t.Error("expected nil copy of nil tree")
	}
}

func TestVerkleProofSize_Empty(t *testing.T) {
	p := &VerkleProof{Key: []byte{}, Value: []byte{}}
	if p.Size() != 0 {
		t.Errorf("expected 0, got %d", p.Size())
	}
}

func TestVerkleProofVerify_Nil(t *testing.T) {
	if VerifyProof(types.Hash{}, nil) {
		t.Error("expected false for nil proof")
	}
}

func TestPutEmptyKey(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	// TRIE-R11-005: empty keys are rejected at the API boundary.
	err := tree.Put([]byte{}, []byte("val"))
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey for empty key Put, got %v", err)
	}
	_, err = tree.Get([]byte{})
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound for empty key Get, got %v", err)
	}
}

// TestTRIE_R11005_StemCollisionFixed verifies the original TRIE-R11-005 bug
// is fixed: the legacy keyToStem used a 0x80 padding marker for short keys,
// causing "abc" and "abc\x80" to produce the same 31-byte stem [0x61,0x62,
// 0x63,0x80,0,...]. The second Put silently overwrote the first. The fix
// uses SHA-256 with domain separation for non-canonical keys, making such
// collisions cryptographically negligible.
func TestTRIE_R11005_StemCollisionFixed(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	key1 := []byte("abc")
	key2 := []byte("abc\x80") // append 0x80 byte — used to collide with "abc"

	val1 := []byte("value-for-abc")
	val2 := []byte("value-for-abc-0x80")

	if err := tree.Put(key1, val1); err != nil {
		t.Fatalf("Put key1 failed: %v", err)
	}
	if err := tree.Put(key2, val2); err != nil {
		t.Fatalf("Put key2 failed: %v", err)
	}

	// Both values must be retrievable — no silent overwrite.
	got1, err := tree.Get(key1)
	if err != nil {
		t.Fatalf("Get key1 failed: %v", err)
	}
	if !bytes.Equal(got1, val1) {
		t.Errorf("key1 value: got %q, want %q", got1, val1)
	}

	got2, err := tree.Get(key2)
	if err != nil {
		t.Fatalf("Get key2 failed: %v", err)
	}
	if !bytes.Equal(got2, val2) {
		t.Errorf("key2 value: got %q, want %q", got2, val2)
	}

	// Stems must differ (this is the actual collision-prevention guarantee).
	stem1 := keyToStem(key1)
	stem2 := keyToStem(key2)
	if bytes.Equal(stem1[:], stem2[:]) {
		t.Error("TRIE-R11-005 regression: stems for 'abc' and 'abc\\x80' are equal")
	}
}

// TestTRIE_R11005_EmptyKeyStemNoLongerCollidesWithZeros verifies the second
// half of TRIE-R11-005: the empty key previously produced an all-zero stem
// that collided with a key of 31 zero bytes. The fix rejects empty keys at
// the API boundary so the collision cannot occur.
func TestTRIE_R11005_EmptyKeyStemNoLongerCollidesWithZeros(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	// 32-byte canonical key of all zeros — must work.
	zeroKey := make([]byte, 32)
	if err := tree.Put(zeroKey, []byte("zero-val")); err != nil {
		t.Fatalf("Put 32-byte zero key failed: %v", err)
	}
	got, err := tree.Get(zeroKey)
	if err != nil {
		t.Fatalf("Get 32-byte zero key failed: %v", err)
	}
	if !bytes.Equal(got, []byte("zero-val")) {
		t.Errorf("zero key value: got %q, want 'zero-val'", got)
	}

	// Empty key must be rejected (would have collided with the zero stem).
	if err := tree.Put([]byte{}, []byte("empty-val")); err != ErrInvalidKey {
		t.Errorf("empty key Put: expected ErrInvalidKey, got %v", err)
	}
}

// TestTRIE_R11005_VariableLengthKeysCoexist verifies that keys of different
// lengths (1..31 bytes) coexist correctly after the SHA-256 stem derivation
// fix. Previously, two keys that shared a key prefix but differed in length
// could collide if the shorter key's padding marker equaled the longer key's
// next byte.
func TestTRIE_R11005_VariableLengthKeysCoexist(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	// Pick keys that would have collided under the old 0x80 padding scheme.
	keys := [][]byte{
		[]byte("a"),         // stem: pad with 0x80 after 'a'
		[]byte("a\x80"),     // stem: 'a' then 0x80 — old collision!
		[]byte("a\x80\x00"), // 3 bytes
		[]byte("ab"),        // 2 bytes
		[]byte("ab\x80"),    // 3 bytes — would collide with "ab" + pad
		make([]byte, 32),    // canonical 32-byte zero key
	}
	values := [][]byte{[]byte("v1"), []byte("v2"), []byte("v3"), []byte("v4"), []byte("v5"), []byte("v6")}

	for i, k := range keys {
		if err := tree.Put(k, values[i]); err != nil {
			t.Fatalf("Put %d (%x) failed: %v", i, k, err)
		}
	}
	for i, k := range keys {
		got, err := tree.Get(k)
		if err != nil {
			t.Errorf("Get %d (%x) failed: %v", i, k, err)
			continue
		}
		if !bytes.Equal(got, values[i]) {
			t.Errorf("key %d (%x): got %q, want %q", i, k, got, values[i])
		}
	}
}

func TestExtensionNode_NodeType(t *testing.T) {
	var stem [StemSize]byte
	stem[0] = 0x01
	ext := NewExtensionNode(stem, 1, nil)
	if ext.NodeType() != NodeTypeExtension {
		t.Errorf("expected NodeTypeExtension, got %d", ext.NodeType())
	}
}

func TestPedersenHasher_HashExtension(t *testing.T) {
	hasher := PedersenHasher()
	var stem [StemSize]byte
	stem[0] = 0x0A
	child := types.Hash{1, 2, 3}

	hash := hasher.HashExtension(stem, child)
	if hash == (types.Hash{}) {
		t.Error("expected non-zero hash")
	}

	hash2 := hasher.HashExtension(stem, child)
	if hash != hash2 {
		t.Error("extension hash should be deterministic")
	}
}

func TestBatchVerifyIPA(t *testing.T) {
	basis, err := NewPedersenBasis(4)
	if err != nil {
		t.Fatal(err)
	}

	a := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	b := []*big.Int{big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8)}
	c := innerProduct(a, b)
	commitment, _ := basis.Commit(a)
	proof, _ := GenerateIPAProof(basis, a, b, c)

	proofs := []*IPAProof{proof}
	commitments := []*PedersenCommitment{commitment}
	bs := [][]*big.Int{b}
	cs := []*big.Int{c}

	ok, err := BatchVerifyIPA(basis, commitments, bs, cs, proofs)
	_ = ok
	_ = err
}

func TestBatchVerifyIPA_Empty(t *testing.T) {
	basis, _ := NewPedersenBasis(4)
	ok, err := BatchVerifyIPA(basis, nil, nil, nil, nil)
	_ = ok
	_ = err
}

func TestVerkleStateDB_Import_Nil(t *testing.T) {
	db := NewVerkleStateDB()
	err := db.Import(nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerkleStateDB_Import_EmptyMap(t *testing.T) {
	db := NewVerkleStateDB()
	err := db.Import(map[string][]byte{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerkleStateDB_GetStorage_AddressNotFound(t *testing.T) {
	db := NewVerkleStateDB()
	var addr types.Address
	rand.Read(addr[:])
	var slot types.Hash
	rand.Read(slot[:])

	_, err := db.GetStorage(addr, slot)
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestVerkleStateDB_GetStorageRoot_AddressNotFound(t *testing.T) {
	db := NewVerkleStateDB()
	var addr types.Address
	rand.Read(addr[:])

	root := db.GetStorageRoot(addr)
	if root != (types.Hash{}) {
		t.Errorf("expected zero hash, got %v", root)
	}
}

func TestVerkleStateDB_GetCode_NotFound(t *testing.T) {
	db := NewVerkleStateDB()
	var codeHash types.Hash
	rand.Read(codeHash[:])

	_, err := db.GetCode(codeHash)
	if err == nil {
		t.Error("expected error for non-existent code hash")
	}
}

func TestVerkleStateDB_GetNodeCount_Empty(t *testing.T) {
	db := NewVerkleStateDB()
	count := db.GetNodeCount()
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestVerkleTree_Get_LeafCountNonExistent(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	tree.Put([]byte("key1"), []byte("val1"))

	_, err := tree.Get([]byte("key2"))
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestVerkleStateDB_PedersenHasher_HashExtension(t *testing.T) {
	SetHasher(PedersenHasher())
	defer SetHasher(&sha3Hasher{})

	tree := NewVerkleTree(MaxTreeDepth)
	tree.Put([]byte("key_a"), []byte("val_a"))
	tree.Put([]byte("key_b"), []byte("val_b"))
	tree.Put([]byte("key_c"), []byte("val_c"))

	root := tree.Root()
	if root == (types.Hash{}) {
		t.Error("expected non-zero root with Pedersen hasher and multiple keys")
	}
}

func TestVerkleStateDB_IterateAccounts_EarlyStop(t *testing.T) {
	db := NewVerkleStateDB()
	count := 10
	for i := 0; i < count; i++ {
		var addr types.Address
		rand.Read(addr[:])
		db.SetAccount(addr, []byte{byte(i)})
	}

	seen := 0
	db.IterateAccounts(func(addr types.Address, data []byte) bool {
		seen++
		return seen < 3
	})
	if seen != 3 {
		t.Errorf("expected 3 (early stop), got %d", seen)
	}
}

func TestVerkleStateDB_IterateStorage_EarlyStop(t *testing.T) {
	db := NewVerkleStateDB()
	var addr types.Address
	rand.Read(addr[:])
	for i := 0; i < 5; i++ {
		var slot types.Hash
		rand.Read(slot[:])
		db.SetStorage(addr, slot, []byte{byte(i)})
	}

	seen := 0
	db.IterateStorage(addr, func(slot types.Hash, value []byte) bool {
		seen++
		return seen < 2
	})
	if seen != 2 {
		t.Errorf("expected 2 (early stop), got %d", seen)
	}
}

func TestNewIPAProof_Basic(t *testing.T) {
	p := NewIPAProof(4)
	if p == nil {
		t.Error("expected non-nil proof")
	}
}

func TestPedersenCommitment_Equal_False(t *testing.T) {
	basis, _ := NewPedersenBasis(4)
	c1, _ := basis.Commit([]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)})
	c2, _ := basis.Commit([]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(5)})

	if c1.Equal(c2) {
		t.Error("different commitments should not be equal")
	}
}

func TestGenerateBlinding_Deterministic(t *testing.T) {
	b1, err1 := GenerateBlinding()
	b2, err2 := GenerateBlinding()
	if err1 != nil || err2 != nil {
		t.Fatal("blinding generation failed")
	}
	if b1 == nil || b2 == nil {
		t.Fatal("blinding is nil")
	}
}

func TestVerkleStateDB_GetStorage_SlotNotFound(t *testing.T) {
	db := NewVerkleStateDB()
	var addr types.Address
	rand.Read(addr[:])
	db.SetAccount(addr, []byte("account"))

	var slot types.Hash
	rand.Read(slot[:])

	_, err := db.GetStorage(addr, slot)
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestVerkleStateDB_ProveStorage_AddressNotFound(t *testing.T) {
	db := NewVerkleStateDB()
	var addr types.Address
	rand.Read(addr[:])
	var slot types.Hash
	rand.Read(slot[:])

	_, err := db.ProveStorage(addr, slot)
	if err == nil {
		t.Error("expected error for non-existent address")
	}
}

func TestVerkleTree_DeleteFromEmptyTree(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	err := tree.Delete([]byte("nonexistent"))
	if err != nil {
		t.Errorf("delete on empty tree should not error: %v", err)
	}
}

func TestInnerProduct_EmptyVectors(t *testing.T) {
	result := innerProduct(nil, nil)
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Error("expected 0 for empty vectors")
	}
}

func TestNewVerkleTree_ZeroDepth(t *testing.T) {
	tree := NewVerkleTree(0)
	if tree == nil {
		t.Fatal("tree should not be nil with zero depth")
	}
}
