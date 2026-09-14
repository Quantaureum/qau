// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/quantaureum/qau/node"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: compute_hash <genesis.json>")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		os.Exit(1)
	}
	var g node.Genesis
	if err := json.Unmarshal(data, &g); err != nil {
		fmt.Fprintf(os.Stderr, "error unmarshaling genesis: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(g.ConfigurationHash().String())
}
