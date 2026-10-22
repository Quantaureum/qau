// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"reflect"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

type kyberFieldSpec struct {
	name string
	kind reflect.Kind
}

// F-09: zeroInternalKeyState locates circl's secret fields by name (sk/pk/
// hpk/z) and zeroValue walks their contents via reflection + unsafe. A circl
// upgrade that renames or retypes those fields would not fail compilation
// (the concrete type assertions above still hold), but would silently fall
// back to zero-all and corrupt the paired public key — or skip secret
// material. Pin the layout in a test so dependency bumps fail CI loudly and
// force zeroInternalKeyState to be re-reviewed.
func TestKYBER_F09_CirclKeyLayoutPinned(t *testing.T) {
	pinKyberFields(t, "kem PrivateKey", reflect.TypeOf(kyber768.PrivateKey{}), []kyberFieldSpec{
		{name: "sk", kind: reflect.Ptr},
		{name: "pk", kind: reflect.Ptr},
		{name: "hpk", kind: reflect.Array},
		{name: "z", kind: reflect.Array},
	})

	pinKyberFields(t, "kem PublicKey", reflect.TypeOf(kyber768.PublicKey{}), []kyberFieldSpec{
		{name: "pk", kind: reflect.Ptr},
		{name: "hpk", kind: reflect.Array},
	})

	privType := reflect.TypeOf(kyber768.PrivateKey{})
	skField, ok := privType.FieldByName("sk")
	if !ok || skField.Type.Kind() != reflect.Ptr || skField.Type.Elem().Kind() != reflect.Struct {
		t.Fatalf("circl kem PrivateKey.sk is no longer a pointer to a struct: %v", skField.Type)
	}
	// zeroValue recurses into sk's element struct and zeros its polynomial
	// vector. Losing the "sh" field means either the secret moved elsewhere
	// (zeroization must be updated) or the layout is no longer what
	// zeroInternalKeyState was reviewed against.
	if _, ok := skField.Type.Elem().FieldByName("sh"); !ok {
		t.Fatalf("circl cpapke PrivateKey no longer has an 'sh' field; review zeroInternalKeyState against the new circl layout")
	}
}

func pinKyberFields(t *testing.T, label string, typ reflect.Type, want []kyberFieldSpec) {
	t.Helper()
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		t.Fatalf("%s: expected struct, got %v", label, typ.Kind())
	}
	if typ.NumField() != len(want) {
		t.Fatalf("%s: field count changed: got %d, want %d — review zeroInternalKeyState against the new circl layout", label, typ.NumField(), len(want))
	}
	for i, w := range want {
		f := typ.Field(i)
		if f.Name != w.name || f.Type.Kind() != w.kind {
			t.Fatalf("%s: field %d is %s (%v), want %s (%v) — review zeroInternalKeyState against the new circl layout",
				label, i, f.Name, f.Type.Kind(), w.name, w.kind)
		}
	}
}
