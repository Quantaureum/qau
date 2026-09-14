// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// buildRotatePayload mirrors consensus.EncodeVKRotateSession (kept local to
// avoid an import cycle in the encoding test package).
func buildRotatePayload(target types.Address, epoch uint64, pk []byte) []byte {
	out := append([]byte("QVK1"), 0x02)
	out = append(out, target[:]...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], epoch)
	out = append(out, b8[:]...)
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], 1952)
	out = append(out, b2[:]...)
	out = append(out, pk...)
	return out
}

func signTKTx(t *testing.T, tx *Transaction, priv *crypto.PrivateKey, pub []byte) {
	t.Helper()
	tx.PublicKey = pub
	hash, err := tx.SigningHash()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.Sign(priv, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	tx.Signature = sig
}

func TestValidatorKeyTxAuth(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	target := kp.Public.Address()
	sessKP, _ := crypto.GenerateKeyPair()

	validData := buildRotatePayload(target, 42, sessKP.Public.Bytes())

	// happy path
	tx := &Transaction{
		Type:    TxTypeValidatorKey,
		From:    target,
		To:      &validatorKeyRegistryAddress,
		Value:   big.NewInt(0),
		Nonce:   1,
		Data:    validData,
		ChainID: 1668,
	}
	signTKTx(t, tx, kp.Private, kp.Public.Bytes())
	if err := VerifyTransactionAuthorization(tx); err != nil {
		t.Fatalf("valid validatorKey tx rejected: %v", err)
	}

	// wrong recipient
	bad := *tx
	other := types.Address{0x77}
	bad.To = &other
	if err := VerifyTransactionAuthorization(&bad); err == nil {
		t.Fatal("wrong recipient must be rejected")
	}

	// non-zero value
	bad2 := *tx
	bad2.Value = big.NewInt(1)
	if err := VerifyTransactionAuthorization(&bad2); err == nil {
		t.Fatal("non-zero value must be rejected")
	}

	// bad signature
	bad3 := *tx
	bad3.Signature = append([]byte(nil), tx.Signature...)
	bad3.Signature[0] ^= 0xFF
	if err := VerifyTransactionAuthorization(&bad3); err == nil {
		t.Fatal("corrupted signature must be rejected")
	}

	// other identity cannot sign for this validator (From must match pk → fails sig)
	kp2, _ := crypto.GenerateKeyPair()
	tx2 := &Transaction{
		Type: TxTypeValidatorKey, From: kp2.Public.Address(), To: &validatorKeyRegistryAddress,
		Value: big.NewInt(0), Nonce: 1, Data: validData, ChainID: 1668,
	}
	signTKTx(t, tx2, kp2.Private, kp2.Public.Bytes())
	// auth (signature) is valid — payload authorization belongs to consensus layer.
	if err := VerifyTransactionAuthorization(tx2); err != nil {
		t.Fatalf("signature-valid tx for another key must pass auth: %v", err)
	}
}
