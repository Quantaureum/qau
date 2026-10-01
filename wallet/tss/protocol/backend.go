// Quantaureum Node source, version 1.0.0.
package protocol

import (
	"crypto/subtle"
	"errors"
	"fmt"

	qcrypto "github.com/quantaureum/qau/crypto"
)

var (
	ErrInvalidSignRequest    = errors.New("invalid threshold sign request")
	ErrInvalidDKGRequest     = errors.New("invalid threshold DKG request")
	ErrInvalidReshareRequest = errors.New("invalid threshold reshare request")
)

// SignRequest contains every value bound into a threshold signing session.
type SignRequest struct {
	Protocol     ThresholdProtocol
	Key          ThresholdKeyID
	Committee    CommitteeID
	ChainID      uint64
	Epoch        uint64
	Slot         uint64
	Domain       SigningDomain
	Message      []byte
	Context      []byte
	AttemptNonce [32]byte
}

func (request SignRequest) Validate() error {
	if err := request.Protocol.ValidateAlgorithm(request.Key.Algorithm); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignRequest, err)
	}
	if err := request.Key.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignRequest, err)
	}
	profile, err := request.Protocol.Profile()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignRequest, err)
	}
	if err := profile.ValidateCommittee(request.Committee); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignRequest, err)
	}
	if request.ChainID == 0 {
		return fmt.Errorf("%w: zero chain ID", ErrInvalidSignRequest)
	}
	if request.Slot == 0 {
		return fmt.Errorf("%w: zero slot", ErrInvalidSignRequest)
	}
	switch request.Domain {
	case SigningDomainBlock, SigningDomainVote, SigningDomainFinality:
	default:
		return fmt.Errorf("%w: unknown domain", ErrInvalidSignRequest)
	}
	if len(request.Message) == 0 {
		return fmt.Errorf("%w: empty message", ErrInvalidSignRequest)
	}
	if request.Key.Algorithm == qcrypto.SignatureAlgorithmDilithium3Legacy && len(request.Context) != 0 {
		return fmt.Errorf("%w: legacy algorithm does not support context", ErrInvalidSignRequest)
	}
	if len(request.Context) > 255 {
		return fmt.Errorf("%w: context exceeds 255 bytes", ErrInvalidSignRequest)
	}
	var zeroNonce [32]byte
	if subtle.ConstantTimeCompare(request.AttemptNonce[:], zeroNonce[:]) == 1 {
		return fmt.Errorf("%w: zero attempt nonce", ErrInvalidSignRequest)
	}
	return nil
}

func (request SignRequest) Clone() SignRequest {
	request.Key = request.Key.Clone()
	request.Committee = request.Committee.Clone()
	request.Message = append([]byte(nil), request.Message...)
	request.Context = append([]byte(nil), request.Context...)
	return request
}

type SigningMessage struct {
	SessionID [32]byte
	SenderID  uint32
	Sequence  uint32
	Kind      uint16
	Payload   []byte
}

type SigningAction struct {
	Outbound       []SigningMessage
	FinalSignature []byte
	Complete       bool
	BurnSession    bool
}

type DKGRequest struct {
	Protocol   ThresholdProtocol
	Algorithm  qcrypto.SignatureAlgorithm
	Generation uint64
	Committee  CommitteeID
	ChainID    uint64
	Epoch      uint64
}

// Validate rejects DKG requests that do not match a supported fixed profile.
func (request DKGRequest) Validate() error {
	if err := request.Protocol.ValidateAlgorithm(request.Algorithm); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDKGRequest, err)
	}
	if request.Generation == 0 {
		return fmt.Errorf("%w: zero generation", ErrInvalidDKGRequest)
	}
	profile, err := request.Protocol.Profile()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDKGRequest, err)
	}
	if err := profile.ValidateCommittee(request.Committee); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDKGRequest, err)
	}
	if request.ChainID == 0 {
		return fmt.Errorf("%w: zero chain ID", ErrInvalidDKGRequest)
	}
	if request.Epoch == 0 {
		return fmt.Errorf("%w: zero activation epoch", ErrInvalidDKGRequest)
	}
	return nil
}

type DKGMessage struct {
	SessionID [32]byte
	SenderID  uint32
	Sequence  uint32
	Kind      uint16
	Payload   []byte
}

type DKGAction struct {
	Outbound []DKGMessage
	Key      *ThresholdKeyID
	Complete bool
	Abort    bool
}

type ReshareRequest struct {
	Protocol     ThresholdProtocol
	Key          ThresholdKeyID
	OldCommittee CommitteeID
	NewCommittee CommitteeID
	ChainID      uint64
	Epoch        uint64
}

// Validate rejects reshare requests that cross protocols or committee versions.
func (request ReshareRequest) Validate() error {
	if err := request.Protocol.ValidateAlgorithm(request.Key.Algorithm); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidReshareRequest, err)
	}
	if err := request.Key.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidReshareRequest, err)
	}
	profile, err := request.Protocol.Profile()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidReshareRequest, err)
	}
	if err := profile.ValidateTransition(request.OldCommittee, request.NewCommittee); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidReshareRequest, err)
	}
	if request.ChainID == 0 {
		return fmt.Errorf("%w: zero chain ID", ErrInvalidReshareRequest)
	}
	if request.Epoch == 0 {
		return fmt.Errorf("%w: zero activation epoch", ErrInvalidReshareRequest)
	}
	return nil
}

type ReshareMessage struct {
	SessionID [32]byte
	SenderID  uint32
	Sequence  uint32
	Kind      uint16
	Payload   []byte
}

type ReshareAction struct {
	Outbound []ReshareMessage
	Complete bool
	Abort    bool
}

// ThresholdBackend isolates consensus and networking from a replaceable
// threshold cryptographic implementation.
type ThresholdBackend interface {
	Protocol() ThresholdProtocol
	Algorithm() qcrypto.SignatureAlgorithm
	PublicKey() ThresholdKeyID
	StartSigning(SignRequest) (SigningAction, error)
	HandleSigningMessage(SigningMessage) (SigningAction, error)
	StartDKG(DKGRequest) (DKGAction, error)
	HandleDKGMessage(DKGMessage) (DKGAction, error)
	StartReshare(ReshareRequest) (ReshareAction, error)
	HandleReshareMessage(ReshareMessage) (ReshareAction, error)
	Verify(ThresholdKeyID, []byte, []byte, []byte) error
}
