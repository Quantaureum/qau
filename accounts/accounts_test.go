// Quantaureum Node source, version 1.0.0.
package accounts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

func TestDefaultKeystoreParams(t *testing.T) {
	params := DefaultKeystoreParams()
	if params.N != 262144 {
		t.Errorf("expected 262144, got %d", params.N)
	}
	if params.R != 8 {
		t.Errorf("expected 8, got %d", params.R)
	}
	if params.P != 1 {
		t.Errorf("expected 1, got %d", params.P)
	}
	if params.DKLen != 32 {
		t.Errorf("expected 32, got %d", params.DKLen)
	}
}

func TestLightKeystoreParams(t *testing.T) {
	params := LightKeystoreParams()
	if params.N == 0 {
		t.Error("expected non-zero N")
	}
	if params.R != 8 {
		t.Errorf("expected 8, got %d", params.R)
	}
	if params.DKLen != 32 {
		t.Errorf("expected 32, got %d", params.DKLen)
	}
}

func TestNewAccountFromPrivateKey_Nil(t *testing.T) {
	_, err := NewAccountFromPrivateKey(nil)
	if err != ErrInvalidPrivateKey {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestValidateKeystore_Invalid(t *testing.T) {
	err := ValidateKeystore([]byte{})
	if err != ErrInvalidKeystore {
		t.Errorf("expected ErrInvalidKeystore, got %v", err)
	}
}

func TestValidateKeystore_InvalidJSON(t *testing.T) {
	err := ValidateKeystore([]byte("{not json}"))
	if err != ErrInvalidKeystore {
		t.Errorf("expected ErrInvalidKeystore, got %v", err)
	}
}

func TestValidateKeystore_WrongVersion(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"version": 2,
		"address": "0x0000000000000000000000000000000000000001",
		"crypto": map[string]string{
			"cipher": "aes-256-gcm",
			"kdf":    "scrypt",
		},
	})
	err := ValidateKeystore(data)
	if err == nil {
		t.Error("expected error for wrong version")
	}
}

func TestValidateKeystore_WrongCipher(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"version": 1,
		"address": "0x0000000000000000000000000000000000000001",
		"crypto": map[string]string{
			"cipher": "aes-128-cbc",
			"kdf":    "scrypt",
		},
	})
	err := ValidateKeystore(data)
	if err == nil {
		t.Error("expected error for wrong cipher")
	}
}

func TestValidateKeystore_WrongKDF(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"version": 1,
		"address": "0x0000000000000000000000000000000000000001",
		"crypto": map[string]string{
			"cipher": "aes-256-gcm",
			"kdf":    "pbkdf2",
		},
	})
	err := ValidateKeystore(data)
	if err == nil {
		t.Error("expected error for wrong KDF")
	}
}

func TestValidateKeystore_Valid(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"version": 1,
		"address": "0x0000000000000000000000000000000000000001",
		"crypto": map[string]string{
			"cipher": "aes-256-gcm",
			"kdf":    "scrypt",
		},
	})
	err := ValidateKeystore(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGetKeystoreAddress_RejectsOversizedInput(t *testing.T) {
	data := []byte(`{"address":"0x0000000000000000000000000000000000000001","padding":"` + strings.Repeat("a", 16*1024) + `"}`)
	_, err := GetKeystoreAddress(data)
	if err != ErrInvalidKeystore {
		t.Fatalf("expected ErrInvalidKeystore for oversized input, got %v", err)
	}
}

func TestGetKeystoreAddress_Invalid(t *testing.T) {
	_, err := GetKeystoreAddress([]byte{})
	if err != ErrInvalidKeystore {
		t.Errorf("expected ErrInvalidKeystore, got %v", err)
	}
}

func TestGetKeystoreAddress_Valid(t *testing.T) {
	addr := types.BytesToAddress([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	data := []byte(`{"address":"` + addr.String() + `"}`)
	res, err := GetKeystoreAddress(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if res != addr {
		t.Errorf("expected %s, got %s", addr.String(), res.String())
	}
}

func TestAccount_Lock_IsLocked(t *testing.T) {
	a := &Account{}

	if !a.IsLocked() {
		t.Error("expected locked for nil private key")
	}

	_, err := a.Sign([]byte("hello"))
	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}

	if a.Verify([]byte("hello"), nil) {
		t.Error("expected false for nil public key")
	}

	a.Lock()
	if !a.IsLocked() {
		t.Error("expected locked after Lock")
	}
}

func TestExportKeystore_LockedAccount(t *testing.T) {
	a := &Account{}
	_, err := ExportKeystore(a, "password")
	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}

	_, err = ExportKeystore(nil, "password")
	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}
}

func TestImportKeystore_InvalidData(t *testing.T) {
	_, err := ImportKeystore([]byte{}, "password")
	if err == nil {
		t.Error("expected error")
	}
}

func TestImportKeystore_StringPasswordPath(t *testing.T) {
	account, err := NewAccount()
	if err != nil {
		t.Fatalf("NewAccount failed: %v", err)
	}
	keystore, err := ExportKeystore(account, "password")
	if err != nil {
		t.Fatalf("ExportKeystore failed: %v", err)
	}
	imported, err := ImportKeystore(keystore, "password")
	if err != nil {
		t.Fatalf("ImportKeystore failed: %v", err)
	}
	if imported.Address != account.Address {
		t.Fatalf("imported address %s, want %s", imported.Address, account.Address)
	}
}

func TestImportKeystore_InvalidJSON(t *testing.T) {
	_, err := ImportKeystore([]byte("{bad}"), "password")
	if err == nil {
		t.Error("expected error")
	}
}

func TestAccount_CreatedAt(t *testing.T) {
	a := &Account{
		CreatedAt: time.Now().UTC(),
	}
	if a.CreatedAt.IsZero() {
		t.Error("expected non-zero creation time")
	}
}

func TestKeystoreParams_DefaultValues(t *testing.T) {
	params := KeystoreParams{}
	if params.N != 0 {
		t.Errorf("expected 0, got %d", params.N)
	}
	if params.DKLen != 0 {
		t.Errorf("expected 0, got %d", params.DKLen)
	}
}

func TestNewAccount(t *testing.T) {
	acc, err := NewAccount()
	if err != nil {
		t.Fatalf("NewAccount failed: %v", err)
	}
	if acc == nil {
		t.Fatal("expected non-nil account")
	}
	if acc.IsLocked() {
		t.Error("new account should not be locked")
	}
	if acc.Address == (types.Address{}) {
		t.Error("address should not be zero")
	}
	if acc.PrivateKey == nil {
		t.Error("private key should not be nil")
	}
	if acc.PublicKey == nil {
		t.Error("public key should not be nil")
	}
	if acc.CreatedAt.IsZero() {
		t.Error("creation time should not be zero")
	}
}

func TestNewAccountFromPrivateKey_Valid(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	acc, err := NewAccountFromPrivateKey(kp.Private)
	if err != nil {
		t.Fatalf("NewAccountFromPrivateKey failed: %v", err)
	}
	if acc == nil {
		t.Fatal("expected non-nil account")
	}
	if acc.PrivateKey != kp.Private {
		t.Error("private key mismatch")
	}
}

func TestAccount_SignVerify(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	acc := &Account{
		PrivateKey: kp.Private,
		PublicKey:  kp.Public,
	}

	msg := []byte("hello quantaureum")
	sig, err := acc.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Error("signature should not be empty")
	}

	if !acc.Verify(msg, sig) {
		t.Error("signature verification failed")
	}

	if acc.Verify([]byte("wrong message"), sig) {
		t.Error("verification should fail for wrong message")
	}
}

func TestAccount_Lock_WithKey(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	acc := &Account{
		PrivateKey: kp.Private,
		PublicKey:  kp.Public,
	}

	if acc.IsLocked() {
		t.Error("should not be locked")
	}

	acc.Lock()
	if !acc.IsLocked() {
		t.Error("should be locked after Lock")
	}
	if acc.PrivateKey != nil {
		t.Error("private key should be nil after lock")
	}

	_, err = acc.Sign([]byte("test"))
	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}
}

func TestExportImport_Roundtrip(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	acc := &Account{
		PrivateKey: kp.Private,
		PublicKey:  kp.Public,
		Address:    kp.Public.Address(),
	}

	password := "test_password_123"

	keystoreJSON, err := ExportKeystore(acc, password)
	if err != nil {
		t.Fatalf("ExportKeystore failed: %v", err)
	}

	importedAcc, err := ImportKeystore(keystoreJSON, password)
	if err != nil {
		t.Fatalf("ImportKeystore failed: %v", err)
	}

	if importedAcc.Address != acc.Address {
		t.Errorf("address mismatch: %s vs %s", acc.Address.String(), importedAcc.Address.String())
	}
}

func TestImportKeystore_WrongPassword(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	acc := &Account{
		PrivateKey: kp.Private,
		PublicKey:  kp.Public,
		Address:    kp.Public.Address(),
	}

	keystoreJSON, _ := ExportKeystore(acc, "correct_password")
	_, err = ImportKeystore(keystoreJSON, "wrong_password")
	if err != ErrInvalidPassword {
		t.Errorf("expected ErrInvalidPassword, got %v", err)
	}
}

func TestExportKeystoreBytes_LockedAccount(t *testing.T) {
	a := &Account{}
	_, err := ExportKeystoreBytes(a, []byte("password"))
	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}
}

func TestExportKeystoreWithParams_LockedAccount(t *testing.T) {
	a := &Account{}
	_, err := ExportKeystoreWithParams(a, "password", LightKeystoreParams())
	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}
}

func TestExportKeystoreWithParamsBytes_LockedAccount(t *testing.T) {
	a := &Account{}
	_, err := ExportKeystoreWithParamsBytes(a, []byte("password"), LightKeystoreParams())
	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}
}

func TestExportKeystoreWithParams_Roundtrip(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	acc := &Account{
		PrivateKey: kp.Private,
		PublicKey:  kp.Public,
		Address:    kp.Public.Address(),
	}

	params := LightKeystoreParams()
	keystoreJSON, err := ExportKeystoreWithParams(acc, "pwd", params)
	if err != nil {
		t.Fatalf("ExportKeystoreWithParams failed: %v", err)
	}

	importedAcc, err := ImportKeystore(keystoreJSON, "pwd")
	if err != nil {
		t.Fatalf("ImportKeystore failed: %v", err)
	}
	if importedAcc.Address != acc.Address {
		t.Error("address mismatch")
	}
}

func TestExportKeystoreWithParamsBytes_Roundtrip(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	acc := &Account{
		PrivateKey: kp.Private,
		PublicKey:  kp.Public,
		Address:    kp.Public.Address(),
	}

	params := LightKeystoreParams()
	pwd := []byte("bytes_pwd")
	keystoreJSON, err := ExportKeystoreWithParamsBytes(acc, pwd, params)
	if err != nil {
		t.Fatalf("ExportKeystoreWithParamsBytes failed: %v", err)
	}

	importedAcc, err := ImportKeystoreBytes(keystoreJSON, pwd)
	if err != nil {
		t.Fatalf("ImportKeystoreBytes failed: %v", err)
	}
	if importedAcc.Address != acc.Address {
		t.Error("address mismatch")
	}
}

func TestImportKeystoreBytes_InvalidData(t *testing.T) {
	_, err := ImportKeystoreBytes([]byte{}, []byte("pwd"))
	if err == nil {
		t.Error("expected error")
	}
}

func TestGetKeystoreAddress_InvalidJSON(t *testing.T) {
	_, err := GetKeystoreAddress([]byte("{bad"))
	if err != ErrInvalidKeystore {
		t.Errorf("expected ErrInvalidKeystore, got %v", err)
	}
}

func TestErrorConstants(t *testing.T) {
	errors := []error{
		ErrAccountNotFound, ErrInvalidPassword, ErrInvalidKeystore,
		ErrKeystoreCorrupted, ErrAccountLocked, ErrInvalidPrivateKey,
	}
	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error %T has empty message", e)
		}
	}
}

func TestAccount_Verify_NilPubKey(t *testing.T) {
	acc := &Account{}
	if acc.Verify([]byte("msg"), []byte("sig")) {
		t.Error("should return false for nil public key")
	}
}
