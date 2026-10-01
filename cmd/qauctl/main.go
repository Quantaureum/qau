// Quantaureum Node source, version 1.0.0.
// Package main provides the CLI management tool for Quantaureum nodes.
package main

import (
	"fmt"
	"os"

	"github.com/quantaureum/qau/cmd/qauctl/cmd"
)

var (
	version = "1.0.0"
	commit  = "unknown"
)

func main() {
	rootCmd := cmd.NewRootCmd(version, commit)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
