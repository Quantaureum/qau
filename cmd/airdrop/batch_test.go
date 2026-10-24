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
	p := writeTB(t, "# comment\n\n0x619ed75fb3262f491688b6d6dd7591ee72fbf6da,100,B1-tranche\n0x607c2d725c87d033698b35c627dbfb9266d5d8b3,200\n")
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
	if items[1].Label != "0x607c2d725c87d033698b35c627dbfb9266d5d8b3#200" {
		t.Fatalf("default label wrong: %s", items[1].Label)
	}
}

func TestReadBatchCSV_RejectsBad(t *testing.T) {
	cases := map[string]string{
		"no 0x":     "619ed75fb3262f491688b6d6dd7591ee72fbf6da,100\n",
		"zero amt":  "0x619ed75fb3262f491688b6d6dd7591ee72fbf6da,0\n",
		"neg amt":   "0x619ed75fb3262f491688b6d6dd7591ee72fbf6da,-5\n",
		"non-int":   "0x619ed75fb3262f491688b6d6dd7591ee72fbf6da,abc\n",
		"one field": "0x619ed75fb3262f491688b6d6dd7591ee72fbf6da\n",
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
	p := writeTB(t, "0x619ed75fb3262f491688b6d6dd7591ee72fbf6da,100\n0X619ED75FB3262F491688B6D6DD7591EE72FBF6DA,100\n")
	if _, err := readBatchCSV(p); err == nil {
		t.Fatal("duplicate (case-insensitive) must be rejected")
	}
}
