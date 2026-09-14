// Quantaureum Node source, version 1.0.0.
package main

import (
	"fmt"
	"github.com/quantaureum/qau/node"
)

func main() {
	g := node.DefaultGenesis()
	fmt.Printf("MainnetGenesisTimestamp from DefaultGenesis: %d\n", g.Timestamp)
	fmt.Printf("Expected: 1785934768\n")
	if g.Timestamp == 1785934768 {
		fmt.Println("MATCH: binary contains correct timestamp")
	} else {
		fmt.Println("MISMATCH: binary contains WRONG timestamp!")
	}
}
