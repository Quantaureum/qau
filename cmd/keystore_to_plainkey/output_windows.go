// Quantaureum Node source, version 1.0.0.
//go:build windows

package main

import (
	"fmt"
	"os"
)

// openSecureOutputPlatform rejects symlinks and non-regular files before
// opening. Windows has no O_NOFOLLOW, so a narrow Lstat-to-open race remains;
// the documented mitigation is a private output directory.
func openSecureOutputPlatform(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to write through symlink %s", path)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("output %s is not a regular file", path)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	if err := verifyRegularFile(f, path); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
