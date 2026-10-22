// Quantaureum Node source, version 1.0.0.
//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openSecureOutputPlatform uses O_NOFOLLOW so a symlink planted in a shared
// output directory is rejected atomically instead of redirecting the write.
// O_NONBLOCK keeps a planted FIFO from blocking the open; verifyRegularFile
// then rejects anything that is not a regular file.
func openSecureOutputPlatform(path string) (*os.File, error) {
	fd, err := unix.Open(path,
		unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC,
		0600)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("refusing to write through symlink %s", path)
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("invalid file descriptor for %s", path)
	}
	if err := verifyRegularFile(f, path); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
