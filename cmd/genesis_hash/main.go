// Quantaureum Node source, version 1.0.0.
package main

import (
	"fmt"
	"os"

	"github.com/quantaureum/qau/node"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: genesis_hash <genesis.json>")
		os.Exit(1)
	}
	g, err := node.LoadGenesis(os.Args[1])
	if err != nil {
		fmt.Printf("load error: %v\n", err)
		os.Exit(1)
	}
	h := g.ConfigurationHash()
	fmt.Printf("ConfigurationHash: %s\n", h.String())
	fmt.Printf("Timestamp: %d\n", g.Timestamp)
}
