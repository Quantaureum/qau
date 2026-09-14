// Quantaureum Node source, version 1.0.0.
package simulation

import (
	"os"
	"testing"
)

// R123-SCALE-GATE (2026-09-05): scale simulations are opt-in only.
//
// Background: TestSim_200KNodes allocates ~108 GB of virtual memory on a
// 64 GB machine when run without -short, which OOM-killed the machine
// outright (Windows event 2004 → Kernel-Power 41 hard reboot). The repo
// convention (see ci.yml "Test (simulation)" step) has been to run heavy
// simulations with -short since R42, but nothing enforced it for bare
// `go test ./...` runs — the gate lives only in workflow files.
//
// Now the default is inverted: scale tests are DISABLED unless the
// operator explicitly opts in via QAU_SCALE_TESTS=1 on a machine with
// adequate RAM (>= 32 GB free recommended for the 200K node run),
// or by passing -short (which the Makefile / CI already use).
//
// Usage:
//
//	go test ./... -short                # safe everywhere (gate closed)
//	go test ./...                       # ALSO safe now (gate closed by default)
//	QAU_SCALE_TESTS=1 go test -v -run TestSim_200KNodes ./simulation/
//	                                    # explicit opt-in, dedicated machine only
func scaleTestEnabled(t *testing.T) bool {
	if testing.Short() {
		t.Skip("skipping scale simulation in short mode")
		return false
	}
	if os.Getenv("QAU_SCALE_TESTS") != "1" {
		t.Skip("skipping scale simulation: set QAU_SCALE_TESTS=1 on a >=32GB RAM machine to run it")
		return false
	}
	return true
}
