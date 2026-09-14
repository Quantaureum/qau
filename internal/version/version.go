// Quantaureum Node source, version 1.0.0.
// Package version provides the shared build and protocol version metadata.
package version

import "fmt"

// ProtocolVersion is the on-chain protocol identity exposed by clients.
const ProtocolVersion = "1.0.0"

var (
	// Version is the source release version. It is overridden by ldflags.
	Version = "1.0.0"
	// GitCommit is the source revision used for the build.
	GitCommit = "unknown"
	// BuildTime is the UTC build timestamp in RFC 3339 format.
	BuildTime = "unknown"
)

// String returns the compact client version string.
func String() string {
	return fmt.Sprintf("%s (commit: %s, built: %s)", Version, GitCommit, BuildTime)
}
