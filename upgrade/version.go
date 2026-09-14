// Quantaureum Node source, version 1.0.0.
// Package upgrade implements the upgrade mechanism for Quantaureum blockchain.
package upgrade

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/quantaureum/qau/crypto"
)

// Version errors
var (
	ErrInvalidVersion      = errors.New("invalid version format")
	ErrIncompatibleVersion = errors.New("incompatible version")
	ErrVersionTooOld       = errors.New("version too old")
	ErrVersionTooNew       = errors.New("version too new")
)

// Current protocol version
const (
	// ProtocolVersionMajor is the major version of the protocol
	ProtocolVersionMajor = 1

	// ProtocolVersionMinor is the minor version of the protocol
	ProtocolVersionMinor = 0

	// ProtocolVersionPatch is the patch version of the protocol
	ProtocolVersionPatch = 0

	// MinCompatibleMajor is the minimum compatible major version
	MinCompatibleMajor = 1

	// MinCompatibleMinor is the minimum compatible minor version for the current major
	MinCompatibleMinor = 0
)

// Version represents a semantic version
type Version struct {
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`
	Patch uint32 `json:"patch"`
}

// CurrentVersion returns the current protocol version
func CurrentVersion() Version {
	return Version{
		Major: ProtocolVersionMajor,
		Minor: ProtocolVersionMinor,
		Patch: ProtocolVersionPatch,
	}
}

// MinCompatibleVersion returns the minimum compatible version
func MinCompatibleVersion() Version {
	return Version{
		Major: MinCompatibleMajor,
		Minor: MinCompatibleMinor,
		Patch: 0,
	}
}

// String returns the string representation of the version
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// ParseVersion parses a version string (e.g., "1.2.3")
func ParseVersion(s string) (Version, error) {
	var v Version

	// Remove leading 'v' if present
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")

	// Validate format
	pattern := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	matches := pattern.FindStringSubmatch(s)
	if matches == nil {
		return v, ErrInvalidVersion
	}

	major, err := strconv.ParseUint(matches[1], 10, 32)
	if err != nil {
		return v, ErrInvalidVersion
	}

	minor, err := strconv.ParseUint(matches[2], 10, 32)
	if err != nil {
		return v, ErrInvalidVersion
	}

	patch, err := strconv.ParseUint(matches[3], 10, 32)
	if err != nil {
		return v, ErrInvalidVersion
	}

	v.Major = uint32(major)
	v.Minor = uint32(minor)
	v.Patch = uint32(patch)

	return v, nil
}

// Compare compares two versions.
// Returns -1 if v < other, 0 if v == other, 1 if v > other
func (v Version) Compare(other Version) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	return 0
}

// Equal returns true if the versions are equal
func (v Version) Equal(other Version) bool {
	return v.Compare(other) == 0
}

// LessThan returns true if v < other
func (v Version) LessThan(other Version) bool {
	return v.Compare(other) < 0
}

// GreaterThan returns true if v > other
func (v Version) GreaterThan(other Version) bool {
	return v.Compare(other) > 0
}

// VersionCompatibility handles version compatibility checks
type VersionCompatibility struct {
	// CurrentVersion is the current protocol version
	CurrentVersion Version

	// MinCompatible is the minimum compatible version
	MinCompatible Version

	// MaxCompatible is the maximum compatible version (optional, 0.0.0 means no limit)
	MaxCompatible Version
}

// NewVersionCompatibility creates a new version compatibility checker
func NewVersionCompatibility() *VersionCompatibility {
	return &VersionCompatibility{
		CurrentVersion: CurrentVersion(),
		MinCompatible:  MinCompatibleVersion(),
		MaxCompatible:  Version{}, // No upper limit by default
	}
}

// IsCompatible checks if a version is compatible with the current version
func (vc *VersionCompatibility) IsCompatible(v Version) bool {
	// Check minimum version
	if v.LessThan(vc.MinCompatible) {
		return false
	}

	// Check maximum version if set
	if vc.MaxCompatible.Major > 0 || vc.MaxCompatible.Minor > 0 || vc.MaxCompatible.Patch > 0 {
		if v.GreaterThan(vc.MaxCompatible) {
			return false
		}
	}

	// Major version must match for compatibility
	if v.Major != vc.CurrentVersion.Major {
		return false
	}

	return true
}

// CheckCompatibility checks if a version is compatible and returns an error if not
func (vc *VersionCompatibility) CheckCompatibility(v Version) error {
	if v.LessThan(vc.MinCompatible) {
		return fmt.Errorf("%w: version %s is below minimum %s",
			ErrVersionTooOld, v.String(), vc.MinCompatible.String())
	}

	if vc.MaxCompatible.Major > 0 || vc.MaxCompatible.Minor > 0 || vc.MaxCompatible.Patch > 0 {
		if v.GreaterThan(vc.MaxCompatible) {
			return fmt.Errorf("%w: version %s is above maximum %s",
				ErrVersionTooNew, v.String(), vc.MaxCompatible.String())
		}
	}

	if v.Major != vc.CurrentVersion.Major {
		return fmt.Errorf("%w: major version mismatch (got %d, expected %d)",
			ErrIncompatibleVersion, v.Major, vc.CurrentVersion.Major)
	}

	return nil
}

// SetMinCompatible sets the minimum compatible version
func (vc *VersionCompatibility) SetMinCompatible(v Version) {
	vc.MinCompatible = v
}

// SetMaxCompatible sets the maximum compatible version
func (vc *VersionCompatibility) SetMaxCompatible(v Version) {
	vc.MaxCompatible = v
}

// VersionNegotiator handles version negotiation between peers
type VersionNegotiator struct {
	compatibility    *VersionCompatibility
	trustedPublicKey []byte // Dilithium3 public key for signature verification
	signingVerifier  *crypto.SigningVerifier
}

// NewVersionNegotiator creates a new version negotiator
func NewVersionNegotiator() *VersionNegotiator {
	return &VersionNegotiator{
		compatibility:   NewVersionCompatibility(),
		signingVerifier: crypto.NewSigningVerifier(),
	}
}

// SetTrustedPublicKey sets the Dilithium3 public key used to verify version signatures.
// CRITICAL: Without this, version negotiation is vulnerable to downgrade attacks.
func (vn *VersionNegotiator) SetTrustedPublicKey(pubKey []byte) error {
	if len(pubKey) != crypto.Dilithium3PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d bytes", crypto.Dilithium3PublicKeySize)
	}
	vn.trustedPublicKey = make([]byte, len(pubKey))
	copy(vn.trustedPublicKey, pubKey)
	return nil
}

// signatureSize is the size of a Dilithium3 signature
const signatureSize = crypto.Dilithium3SignatureSize

// NegotiateVersion negotiates a common version between local and remote.
// CRITICAL: Requires signature verification to prevent downgrade attacks.
// The remoteVersion must have been cryptographically signed and the signature
// must be provided separately for verification against the trusted public key.
func (vn *VersionNegotiator) NegotiateVersion(remoteVersion Version, signature []byte) (Version, error) {
	// SECURITY: Refuse to negotiate if no trusted public key is configured
	if len(vn.trustedPublicKey) == 0 {
		return Version{}, fmt.Errorf("version negotiation requires trusted public key to be configured")
	}

	// SECURITY: Verify signature to prevent downgrade attacks
	// The signature must be over the serialized remote version
	message := []byte(remoteVersion.String())
	if err := vn.signingVerifier.VerifyMessageSignature(vn.trustedPublicKey, message, signature); err != nil {
		return Version{}, fmt.Errorf("version signature verification failed: %w", err)
	}

	// Check if remote version is compatible
	if err := vn.compatibility.CheckCompatibility(remoteVersion); err != nil {
		return Version{}, err
	}

	// Use the lower version for compatibility
	localVersion := vn.compatibility.CurrentVersion
	if remoteVersion.LessThan(localVersion) {
		return remoteVersion, nil
	}
	return localVersion, nil
}

// GetLocalVersion returns the local version
func (vn *VersionNegotiator) GetLocalVersion() Version {
	return vn.compatibility.CurrentVersion
}

// IsRemoteCompatible checks if a remote version is compatible
func (vn *VersionNegotiator) IsRemoteCompatible(remoteVersion Version) bool {
	return vn.compatibility.IsCompatible(remoteVersion)
}

// VersionInfo contains version information for a node
type VersionInfo struct {
	// ProtocolVersion is the protocol version
	ProtocolVersion Version `json:"protocolVersion"`

	// ClientVersion is the client software version
	ClientVersion string `json:"clientVersion"`

	// NetworkID is the network identifier
	NetworkID uint64 `json:"networkId"`

	// ChainID is the chain identifier
	ChainID uint64 `json:"chainId"`

	// GenesisHash is the genesis block hash
	GenesisHash string `json:"genesisHash"`

	// Signature is the Dilithium3 signature over the version info
	// This must be present for secure version negotiation
	Signature []byte `json:"signature,omitempty"`
}

// NewVersionInfo creates a new version info
func NewVersionInfo(networkID, chainID uint64, genesisHash string) *VersionInfo {
	return &VersionInfo{
		ProtocolVersion: CurrentVersion(),
		ClientVersion:   fmt.Sprintf("qau/%s", CurrentVersion().String()),
		NetworkID:       networkID,
		ChainID:         chainID,
		GenesisHash:     genesisHash,
	}
}

// IsCompatibleWith checks if this version info is compatible with another
func (vi *VersionInfo) IsCompatibleWith(other *VersionInfo) bool {
	if other == nil {
		return false
	}

	// Network ID must match
	if vi.NetworkID != other.NetworkID {
		return false
	}

	// Chain ID must match
	if vi.ChainID != other.ChainID {
		return false
	}

	// Genesis hash must match
	if vi.GenesisHash != other.GenesisHash {
		return false
	}

	// Check protocol version compatibility
	vc := NewVersionCompatibility()
	return vc.IsCompatible(other.ProtocolVersion)
}
