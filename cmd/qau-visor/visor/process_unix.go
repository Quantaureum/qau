//go:build linux || darwin

// Quantaureum Node source, version 1.0.0.
package visor

import (
	"os"
	"os/exec"
	"syscall"
)

func setProcessGroupID(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}

func sendTerminationSignal(proc *os.Process) {
	_ = proc.Signal(syscall.SIGTERM)
}
