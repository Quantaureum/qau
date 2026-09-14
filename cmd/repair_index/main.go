// Quantaureum Node source, version 1.0.0.
// repair_index: Rebuilds the numberPrefix index in the block database.
// Usage: repair_index <blocks_data.db_path>
//
// This tool fixes corrupted block databases where the numberPrefix index
// has missing or incorrect entries. It follows the parent hash chain
// backward from the latest block and writes numberPrefix+height=hash
// for every block.
package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

var (
	blockPrefix    = []byte("b")
	numberPrefix   = []byte("n")
	latestBlockKey = []byte("latest")
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <blocks_data.db_path>\n", os.Args[0])
		os.Exit(1)
	}
	dbPath := os.Args[1]

	fmt.Printf("Opening database: %s\n", dbPath)
	database, err := db.NewFileDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	// Get latest block hash
	latestHashData, err := database.Get(latestBlockKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get latest block key: %v\n", err)
		os.Exit(1)
	}
	var latestHash types.Hash
	copy(latestHash[:], latestHashData)
	fmt.Printf("Latest block hash: %x\n", latestHash[:8])

	// Follow parent hash chain backward, rebuilding numberPrefix index
	currentHash := latestHash
	repaired := 0
	totalBlocks := 0

	for {
		// Get block data
		blockData, err := database.Get(append(blockPrefix, currentHash[:]...))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get block %x: %v\n", currentHash[:8], err)
			break
		}

		// Unmarshal block
		block, err := encoding.UnmarshalBlock(blockData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal block %x: %v\n", currentHash[:8], err)
			break
		}

		height := block.Header.Height
		totalBlocks++

		// Check if numberPrefix index exists and is correct
		numberKey := make([]byte, 8)
		binary.BigEndian.PutUint64(numberKey, height)
		existingHash, err := database.Get(append(numberPrefix, numberKey...))

		if err != nil || !bytesEqual(existingHash, currentHash[:]) {
			// Missing or incorrect — repair it
			batch := database.NewBatch()
			if err := batch.Put(append(numberPrefix, numberKey...), currentHash[:]); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write numberPrefix for height %d: %v\n", height, err)
				break
			}
			if err := batch.Write(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to commit batch for height %d: %v\n", height, err)
				break
			}
			repaired++
			if repaired <= 10 || repaired%100 == 0 {
				fmt.Printf("  Repaired: height=%d hash=%x\n", height, currentHash[:8])
			}
		}

		// Move to parent
		if height == 0 {
			fmt.Printf("Reached genesis block (height=0), chain verified.\n")
			break
		}
		currentHash = block.Header.ParentHash
	}

	fmt.Printf("\nDone. Total blocks scanned: %d, index entries repaired: %d\n", totalBlocks, repaired)

	// Verify: scan from 1 to latestHeight and check continuity
	fmt.Printf("\nVerifying chain continuity...\n")
	latestHeight := uint64(0)
	{
		numberKey := make([]byte, 8)
		for h := uint64(1); h <= 100000; h++ {
			binary.BigEndian.PutUint64(numberKey, h)
			_, err := database.Get(append(numberPrefix, numberKey...))
			if err != nil {
				break
			}
			latestHeight = h
		}
	}

	// Check continuity
	gaps := 0
	for h := uint64(1); h <= latestHeight; h++ {
		numberKey := make([]byte, 8)
		binary.BigEndian.PutUint64(numberKey, h)
		hashData, err := database.Get(append(numberPrefix, numberKey...))
		if err != nil {
			fmt.Printf("  GAP at height %d\n", h)
			gaps++
			continue
		}
		if h > 1 {
			// Verify parent hash chain
			blkData, err := database.Get(append(blockPrefix, hashData...))
			if err != nil {
				fmt.Printf("  MISSING block data at height %d\n", h)
				gaps++
				continue
			}
			blk, err := encoding.UnmarshalBlock(blkData)
			if err != nil {
				fmt.Printf("  CORRUPT block data at height %d\n", h)
				gaps++
				continue
			}
			parentKey := make([]byte, 8)
			binary.BigEndian.PutUint64(parentKey, h-1)
			parentHash, err := database.Get(append(numberPrefix, parentKey...))
			if err != nil {
				fmt.Printf("  MISSING parent index at height %d\n", h-1)
				gaps++
				continue
			}
			if blk.Header.ParentHash != types.BytesToHash(parentHash) {
				fmt.Printf("  FORK at height %d: parent mismatch\n", h)
				gaps++
			}
		}
	}

	if gaps == 0 {
		fmt.Printf("  Chain is continuous from 0 to %d. No gaps found!\n", latestHeight)
	} else {
		fmt.Printf("  Found %d gaps in chain up to height %d\n", gaps, latestHeight)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
