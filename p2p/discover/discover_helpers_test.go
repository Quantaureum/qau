// Quantaureum Node source, version 1.0.0.
package discover

import "github.com/quantaureum/qau/p2p/enode"

// newTestTable builds a Table with SkipIDValidation enabled for tests.
// It lives in a tracked test helper so CI can compile the audited regression
// tests that reference it (the local-only coverage file previously defining
// it is excluded by .gitignore's *_cover* pattern).
func newTestTable() *Table {
	cfg := &Config{SkipIDValidation: true}
	tab, _ := NewTable(cfg)
	return tab
}

func newTestTableWithSelf(selfID enode.ID) *Table {
	cfg := &Config{SelfID: selfID, SkipIDValidation: true}
	tab, _ := NewTable(cfg)
	return tab
}
