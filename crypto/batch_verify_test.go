// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"testing"
)

func generateKeyPairs(t *testing.T, n int) []*KeyPair {
	t.Helper()
	pairs := make([]*KeyPair, n)
	for i := 0; i < n; i++ {
		var err error
		pairs[i], err = GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
	}
	return pairs
}

func makeSignatureItems(pairs []*KeyPair, msgPrefix string) []SignatureItem {
	items := make([]SignatureItem, len(pairs))
	for i, kp := range pairs {
		msg := []byte(msgPrefix + string(byte(i)))
		sig, _ := kp.Private.Sign(msg)
		items[i] = SignatureItem{
			PublicKey: kp.Public,
			Message:   msg,
			Signature: sig,
		}
	}
	return items
}

func TestNewBatchVerifierWithConfig(t *testing.T) {
	bv := NewBatchVerifierWithConfig(0, 0)
	if bv == nil {
		t.Fatal("expected non-nil verifier")
	}
	if bv.numWorkers <= 0 {
		t.Error("numWorkers should be positive")
	}
	if bv.parallelThreshold <= 0 {
		t.Error("parallelThreshold should be positive")
	}
}

func TestNewBatchVerifier_Default(t *testing.T) {
	bv := NewBatchVerifier()
	if bv == nil {
		t.Fatal("expected non-nil verifier")
	}
	if bv.numWorkers <= 0 {
		t.Error("numWorkers should be positive")
	}
}

func TestBatchVerifier_VerifyBatch_Empty(t *testing.T) {
	bv := NewBatchVerifier()
	result := bv.VerifyBatch(nil)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.AllValid {
		t.Error("empty batch should be all valid")
	}
}

func TestBatchVerifier_VerifyBatch_Valid(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 3)
	items := makeSignatureItems(pairs, "batch message ")

	result := bv.VerifyBatch(items)
	if !result.AllValid {
		t.Error("expected all valid")
	}
	if result.ValidCount != 3 {
		t.Errorf("expected 3 valid, got %d", result.ValidCount)
	}
	if result.InvalidCount != 0 {
		t.Errorf("expected 0 invalid, got %d", result.InvalidCount)
	}
	if len(result.Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(result.Results))
	}
}

func TestBatchVerifier_VerifyBatch_Invalid(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 3)
	items := makeSignatureItems(pairs, "batch msg ")

	items[1].Signature = make([]byte, Dilithium3SignatureSize)

	result := bv.VerifyBatch(items)
	if result.AllValid {
		t.Error("expected NOT all valid with tampered sig")
	}
	if result.InvalidCount < 1 {
		t.Error("expected at least 1 invalid")
	}
}

func TestBatchVerifier_VerifyBatch_Single(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 1)
	items := makeSignatureItems(pairs, "single")

	result := bv.VerifyBatch(items)
	if !result.AllValid {
		t.Error("single should be valid")
	}
	if len(result.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(result.Results))
	}
}

func TestBatchVerifier_VerifyBatch_Oversized(t *testing.T) {
	bv := NewBatchVerifier()
	maxPlusOne := MaxBatchSize + 1
	items := make([]SignatureItem, maxPlusOne)

	result := bv.VerifyBatch(items)
	if result.AllValid {
		t.Error("oversized batch should not be all valid")
	}
	if result.InvalidCount != maxPlusOne {
		t.Errorf("expected all invalid, got %d invalid", result.InvalidCount)
	}
}

func TestBatchVerifier_VerifyBatch_NilPubKey(t *testing.T) {
	bv := NewBatchVerifier()
	items := []SignatureItem{
		{PublicKey: nil, Message: []byte("msg"), Signature: make([]byte, Dilithium3SignatureSize)},
	}

	result := bv.VerifyBatch(items)
	// Nil public key should cause verification to fail
	if result.AllValid {
		t.Error("expected invalid with nil pubkey")
	}
}

func TestBatchVerifier_VerifyBatch_WrongSigSize(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 1)
	items := []SignatureItem{
		{PublicKey: pairs[0].Public, Message: []byte("msg"), Signature: []byte("short")},
	}

	result := bv.VerifyBatch(items)
	if result.AllValid {
		t.Error("expected invalid with wrong sig size")
	}
}

func TestBatchVerifier_VerifyBatch_ParallelPath(t *testing.T) {
	pairs := generateKeyPairs(t, 6)
	items := makeSignatureItems(pairs, "parallel batch ")

	bv := NewBatchVerifier()
	result := bv.VerifyBatch(items)
	if !result.AllValid {
		t.Error("expected all valid in parallel path")
	}
	if result.ValidCount != 6 {
		t.Errorf("expected 6 valid, got %d", result.ValidCount)
	}
}

func TestBatchVerifier_VerifyBatchStrict_Valid(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 2)
	items := makeSignatureItems(pairs, "strict ")

	err := bv.VerifyBatchStrict(items)
	if err != nil {
		t.Fatalf("VerifyBatchStrict failed: %v", err)
	}
}

func TestBatchVerifier_VerifyBatchStrict_Invalid(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 2)
	items := makeSignatureItems(pairs, "strict inv ")
	items[0].Signature = make([]byte, Dilithium3SignatureSize)

	err := bv.VerifyBatchStrict(items)
	if err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestBatchVerifier_VerifyBatchStrict_Empty(t *testing.T) {
	bv := NewBatchVerifier()
	err := bv.VerifyBatchStrict(nil)
	if err != ErrBatchEmpty {
		t.Errorf("expected ErrBatchEmpty, got %v", err)
	}
}

func TestBatchVerifier_VerifyBatchAll_Valid(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 2)
	items := makeSignatureItems(pairs, "all ")

	if !bv.VerifyBatchAll(items) {
		t.Error("expected all valid")
	}
}

func TestBatchVerifier_VerifyBatchAll_Invalid(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 2)
	items := makeSignatureItems(pairs, "all inv ")
	items[0].Signature = make([]byte, Dilithium3SignatureSize)

	if bv.VerifyBatchAll(items) {
		t.Error("should not be all valid")
	}
}

func TestBatchVerifier_VerifyBatchAll_Empty(t *testing.T) {
	bv := NewBatchVerifier()
	if !bv.VerifyBatchAll(nil) {
		t.Error("empty batch should be all valid")
	}
}

func TestBatchVerifier_VerifyBatchAny_Valid(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 3)
	items := makeSignatureItems(pairs, "any ")
	items[0].Signature = make([]byte, Dilithium3SignatureSize)
	items[1].Signature = make([]byte, Dilithium3SignatureSize)

	if !bv.VerifyBatchAny(items) {
		t.Error("expected at least one valid")
	}
}

func TestBatchVerifier_VerifyBatchAny_None(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 2)
	items := makeSignatureItems(pairs, "any none ")
	items[0].Signature = make([]byte, Dilithium3SignatureSize)
	items[1].Signature = make([]byte, Dilithium3SignatureSize)

	if bv.VerifyBatchAny(items) {
		t.Error("should have no valid")
	}
}

func TestBatchVerifier_VerifyBatchAny_Empty(t *testing.T) {
	bv := NewBatchVerifier()
	if bv.VerifyBatchAny(nil) {
		t.Error("empty batch should not have any valid")
	}
}

func TestBatchVerifier_VerifyBatchThreshold_Met(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 5)
	items := makeSignatureItems(pairs, "threshold ")
	items[0].Signature = make([]byte, Dilithium3SignatureSize)
	items[1].Signature = make([]byte, Dilithium3SignatureSize)

	if !bv.VerifyBatchThreshold(items, 3) {
		t.Error("expected threshold met (3 valid out of 5)")
	}
}

func TestBatchVerifier_VerifyBatchThreshold_NotMet(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 3)
	items := makeSignatureItems(pairs, "threshold fail ")
	items[0].Signature = make([]byte, Dilithium3SignatureSize)
	items[1].Signature = make([]byte, Dilithium3SignatureSize)

	if bv.VerifyBatchThreshold(items, 2) {
		t.Error("expected threshold not met (1 valid, need 2)")
	}
}

func TestBatchVerifier_VerifyBatchThreshold_Zero(t *testing.T) {
	bv := NewBatchVerifier()
	pairs := generateKeyPairs(t, 2)
	items := makeSignatureItems(pairs, "threshold zero ")

	if !bv.VerifyBatchThreshold(items, 0) {
		t.Error("zero threshold should be met")
	}
}

func TestBatchVerifier_VerifyBatchThreshold_Empty(t *testing.T) {
	bv := NewBatchVerifier()
	if bv.VerifyBatchThreshold(nil, 1) {
		t.Error("empty batch should not meet threshold")
	}
	if !bv.VerifyBatchThreshold(nil, 0) {
		t.Error("empty batch should meet zero threshold")
	}
}

func TestVerifyBatch_PackageLevel(t *testing.T) {
	pairs := generateKeyPairs(t, 2)
	items := makeSignatureItems(pairs, "package level ")

	result := VerifyBatch(items)
	if !result.AllValid {
		t.Error("expected all valid")
	}
}

func TestVerifyBatchStrict_PackageLevel(t *testing.T) {
	pairs := generateKeyPairs(t, 2)
	items := makeSignatureItems(pairs, "strict pkg ")

	err := VerifyBatchStrict(items)
	if err != nil {
		t.Fatalf("VerifyBatchStrict failed: %v", err)
	}
}

func TestVerifyBatchStrict_PackageLevel_Invalid(t *testing.T) {
	pairs := generateKeyPairs(t, 2)
	items := makeSignatureItems(pairs, "strict pkg inv ")
	items[0].Signature = make([]byte, Dilithium3SignatureSize)

	err := VerifyBatchStrict(items)
	if err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestVerifyBatchAll_PackageLevel(t *testing.T) {
	pairs := generateKeyPairs(t, 2)
	items := makeSignatureItems(pairs, "all pkg ")

	if !VerifyBatchAll(items) {
		t.Error("expected all valid")
	}
}

func TestSignBatch_Valid(t *testing.T) {
	pairs := generateKeyPairs(t, 1)
	kp := pairs[0]

	msgs := [][]byte{
		[]byte("signbatch 1"),
		[]byte("signbatch 2"),
		[]byte("signbatch 3"),
	}

	result := SignBatch(kp.Private, msgs)
	if result.SuccessCount != 3 {
		t.Errorf("expected 3 successes, got %d", result.SuccessCount)
	}
	if result.FailureCount != 0 {
		t.Errorf("expected 0 failures, got %d", result.FailureCount)
	}
	if len(result.Signatures) != 3 {
		t.Errorf("expected 3 signatures, got %d", len(result.Signatures))
	}

	for i := range msgs {
		ok := kp.Public.Verify(msgs[i], result.Signatures[i])
		if !ok {
			t.Errorf("signature %d verification failed", i)
		}
	}
}

func TestSignBatch_Empty(t *testing.T) {
	pairs := generateKeyPairs(t, 1)
	result := SignBatch(pairs[0].Private, nil)
	if result.SuccessCount != 0 {
		t.Error("expected 0 successes for empty")
	}
	if len(result.Signatures) != 0 {
		t.Error("expected empty signatures")
	}
}

func TestSignBatch_NilKey(t *testing.T) {
	result := SignBatch(nil, [][]byte{[]byte("msg")})
	if result.FailureCount != 1 {
		t.Errorf("expected 1 failure, got %d", result.FailureCount)
	}
}

func TestSignBatchParallel_Valid(t *testing.T) {
	pairs := generateKeyPairs(t, 3)
	items := make([]SignItem, 3)
	for i, kp := range pairs {
		items[i] = SignItem{
			PrivateKey: kp.Private,
			Message:    []byte("parallel " + string(byte(i))),
		}
	}

	result := SignBatchParallel(items, 0)
	if result.SuccessCount != 3 {
		t.Errorf("expected 3 successes, got %d", result.SuccessCount)
	}
	if len(result.Signatures) != 3 {
		t.Errorf("expected 3 signatures, got %d", len(result.Signatures))
	}

	for i := range items {
		ok := pairs[i].Public.Verify(items[i].Message, result.Signatures[i])
		if !ok {
			t.Errorf("signature %d verification failed", i)
		}
	}
}

func TestSignBatchParallel_Empty(t *testing.T) {
	result := SignBatchParallel(nil, 0)
	if result.SuccessCount != 0 {
		t.Error("expected 0 successes for empty")
	}
}

func TestSignBatchParallel_NilKey(t *testing.T) {
	items := []SignItem{
		{PrivateKey: nil, Message: []byte("msg")},
	}
	result := SignBatchParallel(items, 0)
	if result.FailureCount != 1 {
		t.Errorf("expected 1 failure, got %d", result.FailureCount)
	}
}

func TestBatchVerifier_ErrVariables(t *testing.T) {
	errors := []error{ErrBatchTooLarge, ErrBatchEmpty, ErrBatchPartialFailure, ErrBatchSizeMismatch, ErrBatchVerifyFailed}
	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error %T has empty message", e)
		}
	}
}

func TestBatchVerifier_VerifyBatch_ParallelThreshold(t *testing.T) {
	pairs := generateKeyPairs(t, 5)
	items := makeSignatureItems(pairs, "thresh ")

	bv := NewBatchVerifierWithConfig(2, 3)
	result := bv.VerifyBatch(items)
	if !result.AllValid {
		t.Error("expected all valid with custom config")
	}
}

func TestBatchVerifier_VerifyBatch_SequentialPath(t *testing.T) {
	pairs := generateKeyPairs(t, 2)
	items := makeSignatureItems(pairs, "seq ")

	bv := NewBatchVerifierWithConfig(2, 10)
	result := bv.VerifyBatch(items)
	if !result.AllValid {
		t.Error("expected all valid in sequential path")
	}
}
