// Quantaureum Node source, version 1.0.0.
//go:build windows

// Package db — Windows disk space implementation.
//
// DB-R11-003 (2026-07-20): provides diskFreeBytes for Windows using
// windows.GetDiskFreeSpaceEx. See diskspace.go for the full rationale.
package db

import "golang.org/x/sys/windows"

// diskFreeBytes returns the number of bytes available to the calling user
// on the filesystem holding `path`. The path must exist.
// Returns an error if GetDiskFreeSpaceEx fails (e.g., path does not exist,
// permission denied).
func diskFreeBytes(path string) (uint64, error) {
	var freeBytes uint64
	// GetDiskFreeSpaceEx returns bytes available to the calling user
	// (analogous to POSIX Bavail, NOT the total free blocks).
	utf16Path, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	if err := windows.GetDiskFreeSpaceEx(utf16Path, &freeBytes, nil, nil); err != nil {
		return 0, err
	}
	return freeBytes, nil
}
