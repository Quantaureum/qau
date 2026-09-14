// Quantaureum Node source, version 1.0.0.
// Package db — disk space precheck helpers.
//
// DB-R11-003 (2026-07-20) FIX: Before any batch Write (or single Put that
// could itself grow the database file), verify that the underlying filesystem
// has at least MinFreeDiskBytes of free space. Writing when the disk is full
// can leave bbolt's freelist in an inconsistent state on some filesystems
// (especially network-attached storage where ENOSPC may surface mid-transaction
// rather than at open time). Rejecting the write up-front keeps the database
// consistent: the caller sees a clear "disk full" error and can retry after
// freeing space, instead of receiving a partial-write corruption.
//
// The threshold is intentionally generous (1 GiB) because:
//   - bbolt grows the file in 32MB-ish increments, so a single Put may need
//     up to ~32MB of free space just for file growth.
//   - A typical batch Write may touch hundreds of pages.
//   - Leaving a 1GB buffer ensures the OS page cache and bbolt's own
//     internal structures have ample headroom.
package db

import "errors"

// MinFreeDiskBytes is the minimum free disk space required before any
// write to BoltDB. 1 GiB.
const MinFreeDiskBytes uint64 = 1 << 30 // 1,073,741,824 bytes

// ErrInsufficientDiskSpace is returned when the filesystem holding the
// database has less than MinFreeDiskBytes free.
// Defined here (not in db.go) so it lives next to its only producers.
// Use errors.Is(err, ErrInsufficientDiskSpace) to test for it.
var ErrInsufficientDiskSpace = errors.New("insufficient disk space: less than 1 GiB free")
