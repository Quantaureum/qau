// Quantaureum Node source, version 1.0.0.
package node

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/bbolt"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestThresholdShareStoreWaitsForExternalFileLock(t *testing.T) {
	base := filepath.Join(t.TempDir(), "shares.enc")
	paths, err := newThresholdProtocolPaths(base, protocol.ThresholdProtocolDilithium3V1, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.Root, 0700); err != nil {
		t.Fatal(err)
	}
	blocker, err := bbolt.Open(filepath.Join(paths.Root, "store.lock.db"), 0600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	done := make(chan error, 1)
	go func() {
		_, loadErr := newThresholdShareStore(base).LoadCandidate(1, 1, []byte("DEVNET ONLY store lock test"))
		done <- loadErr
	}()
	select {
	case err := <-done:
		t.Fatalf("external lock was bypassed: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := blocker.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("missing candidate loaded after release")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("share store did not resume after external lock release")
	}
}

func TestThresholdShareStoreLockAcrossProcesses(t *testing.T) {
	if os.Getenv("QAU_TEST_THRESHOLD_LOCK_HELPER") == "1" {
		lock, err := bbolt.Open(os.Getenv("QAU_TEST_THRESHOLD_LOCK_PATH"), 0600, &bbolt.Options{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(os.Stdout, "locked")
		_, _ = io.Copy(io.Discard, os.Stdin)
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	base := filepath.Join(t.TempDir(), "shares.enc")
	paths, err := newThresholdProtocolPaths(base, protocol.ThresholdProtocolDilithium3V1, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.Root, 0700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(paths.Root, "store.lock.db")
	command := exec.Command(os.Args[0], "-test.run=^TestThresholdShareStoreLockAcrossProcesses$")
	command.Env = append(os.Environ(), "QAU_TEST_THRESHOLD_LOCK_HELPER=1", "QAU_TEST_THRESHOLD_LOCK_PATH="+lockPath)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = input.Close()
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	ready, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || ready != "locked\n" {
		t.Fatalf("helper did not acquire the file lock: %q: %v", ready, err)
	}
	done := make(chan error, 1)
	go func() {
		_, loadErr := newThresholdShareStore(base).LoadCandidate(1, 1, []byte("DEVNET ONLY cross-process lock test"))
		done <- loadErr
	}()
	select {
	case err := <-done:
		t.Fatalf("another process's lock was bypassed: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed lock holder exited successfully")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("missing candidate loaded after lock holder crashed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("share store did not resume after lock holder crashed")
	}
}
