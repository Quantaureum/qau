// Quantaureum Node source, version 1.0.0.
package main

import (
	"fmt"
	"os"
)

// openSecureOutput opens path for writing without following a symlink in the
// final path component. Platform variants implement the actual open: Unix uses
// O_NOFOLLOW, Windows uses Lstat (no O_NOFOLLOW equivalent).
func openSecureOutput(path string) (*os.File, error) {
	return openSecureOutputPlatform(path)
}

// verifyRegularFile rejects devices, FIFOs, and directories after the open so
// a pre-planted special file cannot receive the plaintext key.
func verifyRegularFile(f *os.File, path string) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat output %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("output %s is not a regular file", path)
	}
	return nil
}
