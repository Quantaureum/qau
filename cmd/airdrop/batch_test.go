// Quantaureum Node source, version 1.0.0.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTB(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "batch.csv")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadBatchCSV_HappyPath(t *testing.T) {
	p := writeTB(t, "# comment\n\n0x1111111111111111111111111111111111111111,100,B1-tranche\n0x2222222222222222222222222222222222222222,200\n")
	items, err := readBatchCSV(p)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d", len(items))
	}
	if items[0].Amount != 100 || items[0].Label != "B1-tranche" {
		t.Fatalf("row0 wrong: %+v", items[0])
	}
	if items[1].Label != "0x2222222222222222222222222222222222222222#200" {
		t.Fatalf("default label wrong: %s", items[1].Label)
	}
}

func TestReadBatchCSV_RejectsBad(t *testing.T) {
	cases := map[string]string{
		"no 0x":     "1111111111111111111111111111111111111111,100\n",
		"zero amt":  "0x1111111111111111111111111111111111111111,0\n",
		"neg amt":   "0x1111111111111111111111111111111111111111,-5\n",
		"non-int":   "0x1111111111111111111111111111111111111111,abc\n",
		"one field": "0x1111111111111111111111111111111111111111\n",
		"empty":     "# only comments\n",
	}
	for name, content := range cases {
		p := writeTB(t, content)
		if _, err := readBatchCSV(p); err == nil {
			t.Fatalf("%s: expected error, got nil", name)
		}
	}
}

func TestReadBatchCSV_RejectsDuplicateAddress(t *testing.T) {
	p := writeTB(t, "0x1111111111111111111111111111111111111111,100\n0X1111111111111111111111111111111111111111,100\n")
	if _, err := readBatchCSV(p); err == nil {
		t.Fatal("duplicate (case-insensitive) must be rejected")
	}
}
