// Quantaureum Node source, version 1.0.0.
//go:build windows

package visor

import (
	"os"
	"os/exec"
)

func setProcessGroupID(cmd *exec.Cmd) {
	// Windows doesn't support Setpgid, but process management still works
	// via os.Process.Kill() which terminates the entire job object
}

func sendTerminationSignal(proc *os.Process) {
	// Windows doesn't have SIGTERM, use Kill for immediate termination
	// In production, qaud runs on Linux (ARM64 servers)
	_ = proc.Kill()
}
