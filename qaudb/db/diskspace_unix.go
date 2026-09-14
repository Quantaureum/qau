// Quantaureum Node source, version 1.0.0.
//go:build !windows

// Package db — POSIX disk space implementation.
//
// DB-R11-003 (2026-07-20): provides diskFreeBytes for Linux/Darwin/BSD
// using unix.Statfs. See diskspace.go for the full rationale.
package db

import "golang.org/x/sys/unix"

// diskFreeBytes returns the number of bytes available to non-root users on
// the filesystem holding `path`. The path must exist (caller responsibility).
// Returns an error if Statfs fails (e.g., path does not exist, permission
// denied). A successful return with free==0 indicates a completely full disk.
func diskFreeBytes(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	// stat.Bavail is the number of 512-byte blocks available to non-root
	// (i.e., what an unprivileged process can actually allocate). Multiply
	// by the block size (stat.Bsize) to get bytes.
	//
	// On Linux: Bsize is the "preferred" block size (filesystem block size,
	// typically 4096). Bavail * Bsize = free bytes available to user.
	// On Darwin: same semantics.
	return stat.Bavail * uint64(stat.Bsize), nil
}
