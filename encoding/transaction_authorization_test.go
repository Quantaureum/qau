// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// makeStakeAuthTx builds an encoding.Transaction for a canonical
// TxTypeStake operation with commission(4 BE) + nonceLen(2 BE) +
// nonce(nonceLen) in tx.Data, signed by priv over the canonical
// ComputeStakeAuthorizationHash. This is exactly the shape the V2
// builder will produce and exactly what VerifyTransactionAuthorization
// verifies.
func makeStakeAuthTx(t *testing.T, chainID uint64, from types.Address, recipient types.Address,
	value *big.Int, commission uint32, nonce string, priv *crypto.PrivateKey) *Transaction {
	t.Helper()
	txData := encodeStakeAuthData(commission, nonce)

	pub, err := priv.PublicKeySafe()
	if err != nil {
		t.Fatalf("derive pub key: %v", err)
	}
	if pub.Address() != from {
		t.Fatalf("test harness: provided from != priv-derived addr")
	}

	hash, err := types.ComputeStakeAuthorizationHash(chainID, from, recipient, types.StakeAuthTypeStake, value, commission, nonce)
	if err != nil {
		t.Fatalf("compute auth hash: %v", err)
	}
	signature, err := priv.Sign(hash[:])
	if err != nil {
		t.Fatalf("sign auth hash: %v", err)
	}

	return &Transaction{
		Type:      TxTypeStake,
		Nonce:     1,
		ChainID:   chainID,
		From:      from,
		To:        &recipient,
		Value:     new(big.Int).Set(value),
		Data:      txData,
		GasLimit:  100000,
		GasPrice:  big.NewInt(1),
		PublicKey: pub.Bytes(),
		Signature: signature,
	}
}

func encodeStakeAuthData(commission uint32, nonce string) []byte {
	out := make([]byte, 4+2+len(nonce))
	out[0] = byte(commission >> 24)
	out[1] = byte(commission >> 16)
	out[2] = byte(commission >> 8)
	out[3] = byte(commission)
	out[4] = byte(len(nonce) >> 8)
	out[5] = byte(len(nonce))
	copy(out[6:], []byte(nonce))
	return out
}

// TestR38P002_VerifyTransactionAuthorization_StakeHappyPath asserts the
// canonical stake transaction verifies end-to-end as valid. This is the
// GREEN anchor — if this fails, the entire V2 stake auth contract is
// broken at the encoding boundary.
func TestR38P002_VerifyTransactionAuthorization_StakeHappyPath(t *testing.T) {
	chainID := uint64(1668)
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	priv := kp.Private
	pub, err := priv.PublicKeySafe()
	if err != nil {
		t.Fatalf("pub key: %v", err)
	}
	from := pub.Address()
	recipient := types.Address{18: 0x10, 19: 0x01}
	value := big.NewInt(1_000_000_000_000_000_000) // 1 QAU
	tx := makeStakeAuthTx(t, chainID, from, recipient, value, 1000, "1700000000", priv)

	if err := VerifyTransactionAuthorization(tx); err != nil {
		t.Errorf("R38-P0-02 happy path: VerifyTransactionAuthorization rejected a canonical stake tx: %v", err)
	}
}

// TestR38P002_VerifyTransactionAuthorization_StakeRejectsTamperedFields
// asserts that mutating ANY consensus-affecting field after signature
// makes VerifyTransactionAuthorization reject the tx. This is the R38-P0-02
// core invariant: post-signature tampering must be caught.
func TestR38P002_VerifyTransactionAuthorization_StakeRejectsTamperedFields(t *testing.T) {
	chainID := uint64(1668)
	kp, _ := crypto.GenerateKeyPair()
	priv := kp.Private
	pub, _ := priv.PublicKeySafe()
	from := pub.Address()
	recipient := types.Address{18: 0x10, 19: 0x01}
	value := big.NewInt(1_000_000_000_000_000_000)
	base := makeStakeAuthTx(t, chainID, from, recipient, value, 1000, "1700000000", priv)
	if err := VerifyTransactionAuthorization(base); err != nil {
		t.Fatalf("base verify: %v", err)
	}

	// Tamper tx.To → attacker-controlled address. Verify MUST reject.
	t.Run("tampered recipient", func(t *testing.T) {
		tx := *base
		evilTo := types.Address{19: 0x33}
		tx.To = &evilTo
		if err := VerifyTransactionAuthorization(&tx); err == nil {
			t.Error("R38-P0-02 invariant broken: tx.To tamper not rejected")
		} else if err != ErrAuthStakeBadRecipient {
			t.Errorf("want ErrAuthStakeBadRecipient, got %v", err)
		}
	})

	// Tamper tx.Value by +1. The signature no longer covers the new
	// value; the canonical hash recomputed inside Verify MUST differ.
	t.Run("tampered value", func(t *testing.T) {
		tx := *base
		tx.Value = new(big.Int).Add(base.Value, big.NewInt(1))
		if err := VerifyTransactionAuthorization(&tx); err == nil {
			t.Error("R38-P0-02 invariant broken: tx.Value tamper not rejected")
		} else if err != ErrAuthInvalidSignature {
			t.Errorf("want ErrAuthInvalidSignature, got %v", err)
		}
	})

	// Tamper commission in tx.Data. The new commission is included in
	// the canonical hash, so Verify MUST catch it.
	t.Run("tampered commission in Data", func(t *testing.T) {
		tx := *base
		tx.Data = encodeStakeAuthData(1001, "1700000000")
		if err := VerifyTransactionAuthorization(&tx); err == nil {
			t.Error("R38-P0-02 invariant broken: commission tamper not rejected")
		} else if err != ErrAuthInvalidSignature {
			t.Errorf("want ErrAuthInvalidSignature, got %v", err)
		}
	})

	// Tamper staking nonce in tx.Data.
	t.Run("tampered nonce in Data", func(t *testing.T) {
		tx := *base
		tx.Data = encodeStakeAuthData(1000, "1700000001")
		if err := VerifyTransactionAuthorization(&tx); err == nil {
			t.Error("R38-P0-02 invariant broken: nonce tamper not rejected")
		} else if err != ErrAuthInvalidSignature {
			t.Errorf("want ErrAuthInvalidSignature, got %v", err)
		}
	})

	// Tamper tx.ChainID. Cross-chain replay must be caught by the
	// canonical hash — chainID is a field of it.
	t.Run("tampered ChainID", func(t *testing.T) {
		tx := *base
		tx.ChainID = 1669
		if err := VerifyTransactionAuthorization(&tx); err == nil {
			t.Error("R38-P0-02 invariant broken: ChainID tamper not rejected")
		} else if err != ErrAuthInvalidSignature {
			t.Errorf("want ErrAuthInvalidSignature, got %v", err)
		}
	})

	// Tamper tx.From. PublicKey-derived address no longer matches.
	t.Run("tampered From", func(t *testing.T) {
		tx := *base
		tx.From = types.Address{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		if err := VerifyTransactionAuthorization(&tx); err == nil {
			t.Error("R38-P0-02 invariant broken: From tamper not rejected")
		} else if err != ErrAuthPubKeyAddrMismatch {
			t.Errorf("want ErrAuthPubKeyAddrMismatch, got %v", err)
		}
	})

	// Tamper tx.PublicKey — replace with another valid keypair's pubkey.
	// Address check forces failure, and signature over original hash
	// with wrong pubkey also fails.
	t.Run("tampered PublicKey", func(t *testing.T) {
		otherKp, _ := crypto.GenerateKeyPair()
		tx := *base
		otherPubKey, otherErr := otherKp.Private.PublicKeySafe()
		if otherErr != nil {
			t.Fatalf("other pub: %v", otherErr)
		}
		tx.PublicKey = otherPubKey.Bytes()
		if err := VerifyTransactionAuthorization(&tx); err == nil {
			t.Error("R38-P0-02 invariant broken: PublicKey tamper not rejected")
		}
	})

	// Tamper tx.Signature — flip one bit of byte 0. crypto.Verify fails.
	t.Run("tampered Signature", func(t *testing.T) {
		tx := *base
		badSig := make([]byte, len(base.Signature))
		copy(badSig, base.Signature)
		badSig[0] ^= 0x01
		tx.Signature = badSig
		if err := VerifyTransactionAuthorization(&tx); err == nil {
			t.Error("R38-P0-02 invariant broken: Signature tamper not rejected")
		} else if err != ErrAuthInvalidSignature {
			t.Errorf("want ErrAuthInvalidSignature, got %v", err)
		}
	})
}

// TestR38P002_VerifyTransactionAuthorization_StakeRejectsStructuralErrors
// asserts structurally bad stake txs are rejected BEFORE crypto. These
// are the "no pubkey / wrong length / missing recipient / malformed
// Data" categories — quick rejections that don't even reach the
// canonical hash computation.
func TestR38P002_VerifyTransactionAuthorization_StakeRejectsStructuralErrors(t *testing.T) {
	chainID := uint64(1668)
	kp, _ := crypto.GenerateKeyPair()
	priv := kp.Private
	pub, _ := priv.PublicKeySafe()
	from := pub.Address()
	recipient := types.Address{18: 0x10, 19: 0x01}
	value := big.NewInt(1_000_000_000_000_000_000)
	base := makeStakeAuthTx(t, chainID, from, recipient, value, 1000, "1700000000", priv)

	t.Run("nil tx", func(t *testing.T) {
		if err := VerifyTransactionAuthorization(nil); err != ErrAuthNilTx {
			t.Errorf("want ErrAuthNilTx, got %v", err)
		}
	})
	t.Run("no public key", func(t *testing.T) {
		tx := *base
		tx.PublicKey = nil
		if err := VerifyTransactionAuthorization(&tx); err != ErrAuthNoPublicKey {
			t.Errorf("want ErrAuthNoPublicKey, got %v", err)
		}
	})
	t.Run("no signature", func(t *testing.T) {
		tx := *base
		tx.Signature = nil
		if err := VerifyTransactionAuthorization(&tx); err != ErrAuthNoSignature {
			t.Errorf("want ErrAuthNoSignature, got %v", err)
		}
	})
	t.Run("bad pubkey length", func(t *testing.T) {
		tx := *base
		tx.PublicKey = []byte{0x01}
		if err := VerifyTransactionAuthorization(&tx); !errors.Is(err, ErrAuthBadPubKeyLength) {
			t.Errorf("want ErrAuthBadPubKeyLength, got %v", err)
		}
	})
	t.Run("bad sig length", func(t *testing.T) {
		tx := *base
		tx.Signature = []byte{0x01}
		if err := VerifyTransactionAuthorization(&tx); !errors.Is(err, ErrAuthBadSigLength) {
			t.Errorf("want ErrAuthBadSigLength, got %v", err)
		}
	})
	t.Run("missing To", func(t *testing.T) {
		tx := *base
		tx.To = nil
		if err := VerifyTransactionAuthorization(&tx); err != ErrAuthStakeMissingTo {
			t.Errorf("want ErrAuthStakeMissingTo, got %v", err)
		}
	})
	t.Run("bad recipient (unstake contract instead of staking contract)", func(t *testing.T) {
		tx := *base
		addr := types.Address{18: 0x10, 19: 0x02} // unstaking contract, not staking
		tx.To = &addr
		if err := VerifyTransactionAuthorization(&tx); err != ErrAuthStakeBadRecipient {
			t.Errorf("want ErrAuthStakeBadRecipient, got %v", err)
		}
	})
	t.Run("bad Data (truncated)", func(t *testing.T) {
		tx := *base
		tx.Data = []byte{0x01, 0x02} // too short
		if err := VerifyTransactionAuthorization(&tx); err != ErrAuthStakeBadData {
			t.Errorf("want ErrAuthStakeBadData, got %v", err)
		}
	})
	t.Run("bad Data (nonceLen oversize)", func(t *testing.T) {
		tx := *base
		// commission(4) + nonceLen claims 200, but only 0 bytes follow.
		tx.Data = []byte{0, 0, 0, 200, 0, 200}
		if err := VerifyTransactionAuthorization(&tx); err != ErrAuthStakeBadData {
			t.Errorf("want ErrAuthStakeBadData, got %v", err)
		}
	})
}

// TestR38P002_VerifyTransactionAuthorization_OrdinaryTx asserts that
// ordinary transfer txs verify through the SigningHash() path
// (so we know adding V2 didn't regress the legacy verify route).
func TestR38P002_VerifyTransactionAuthorization_OrdinaryTx(t *testing.T) {
	chainID := uint64(1668)
	kp, _ := crypto.GenerateKeyPair()
	priv := kp.Private
	pub, _ := priv.PublicKeySafe()
	from := pub.Address()
	to := types.Address{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

	tx := &Transaction{
		Type:      TxTypeTransfer,
		Nonce:     1,
		ChainID:   chainID,
		From:      from,
		To:        &to,
		Value:     big.NewInt(1_000_000),
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		PublicKey: pub.Bytes(),
	}
	hash, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("signing hash: %v", err)
	}
	sig, err := priv.Sign(hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	tx.Signature = sig

	if err := VerifyTransactionAuthorization(tx); err != nil {
		t.Errorf("R38-P0-02 regression: ordinary tx rejected: %v", err)
	}

	// Tamper value; verify MUST reject.
	tx.Value = big.NewInt(2_000_000)
	if err := VerifyTransactionAuthorization(tx); err == nil {
		t.Error("R38-P0-02 regression: ordinary tx value tamper not rejected")
	}
}
