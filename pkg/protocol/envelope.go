package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/identity"
)

// MaxEnvelopeBytes caps a control message. NKN will carry more, but nothing
// this protocol sends is large, and an unbounded decode is how a signalling
// channel becomes a memory exhaustion bug.
const MaxEnvelopeBytes = 64 * 1024

// MaxClockSkew is how far a message's timestamp may be from local time. It is
// deliberately generous in the past direction and tight in the future: a NAS
// with a bad RTC is common, a peer claiming to be from the future is not.
const (
	MaxClockSkewPast   = 2 * time.Minute
	MaxClockSkewFuture = 30 * time.Second
)

// Errors this package returns for a rejected envelope.
var (
	ErrTooLarge      = errors.New("protocol: envelope exceeds size limit")
	ErrBadSignature  = errors.New("protocol: envelope signature does not verify")
	ErrWrongNetwork  = errors.New("protocol: envelope is for another network")
	ErrNotAddressed  = errors.New("protocol: envelope is addressed to another device")
	ErrClockSkew     = errors.New("protocol: envelope timestamp is outside the accepted window")
	ErrReplay        = errors.New("protocol: envelope has already been seen")
	ErrUnsupportedPV = errors.New("protocol: unsupported protocol version")
)

// Envelope wraps every control message. It is signed by the sender's root key,
// so a relay node, a DHT record, or anything else that carries it can be
// completely untrusted without weakening the protocol.
type Envelope struct {
	ProtocolVersion uint32 `json:"protocol_version"`
	MessageID       string `json:"message_id"`
	NetworkID       string `json:"network_id"`

	FromDeviceID  string `json:"from_device_id"`
	FromPublicKey []byte `json:"from_public_key"`
	ToDeviceID    string `json:"to_device_id"`

	Type      MessageType `json:"type"`
	Timestamp int64       `json:"timestamp_unix_milli"`
	Nonce     []byte      `json:"nonce"`

	Payload json.RawMessage `json:"payload,omitempty"`

	Signature []byte `json:"signature,omitempty"`
}

func (e Envelope) signingBytes() ([]byte, error) {
	unsigned := e
	unsigned.Signature = nil
	return json.Marshal(unsigned)
}

// Seal builds a signed envelope carrying payload.
func Seal(sender *identity.DeviceIdentity, networkID, toDeviceID string, messageType MessageType, payload any) (Envelope, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("protocol: nonce: %w", err)
	}
	var encoded json.RawMessage
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return Envelope{}, fmt.Errorf("protocol: encode payload: %w", err)
		}
		encoded = raw
	}
	envelope := Envelope{
		ProtocolVersion: Version,
		MessageID:       newMessageID(nonce),
		NetworkID:       networkID,
		FromDeviceID:    sender.DeviceID(),
		FromPublicKey:   sender.PublicKey(),
		ToDeviceID:      toDeviceID,
		Type:            messageType,
		Timestamp:       time.Now().UnixMilli(),
		Nonce:           nonce,
		Payload:         encoded,
	}
	signable, err := envelope.signingBytes()
	if err != nil {
		return Envelope{}, fmt.Errorf("protocol: encode envelope: %w", err)
	}
	envelope.Signature = sender.Sign(signable)
	return envelope, nil
}

// Marshal encodes an envelope for transmission and enforces the size cap on
// the way out, so a node cannot emit something its own peers must reject.
func (e Envelope) Marshal() ([]byte, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("protocol: marshal envelope: %w", err)
	}
	if len(raw) > MaxEnvelopeBytes {
		return nil, ErrTooLarge
	}
	return raw, nil
}

// Unmarshal decodes an envelope without validating it. Callers use Verify.
func Unmarshal(raw []byte) (Envelope, error) {
	if len(raw) > MaxEnvelopeBytes {
		return Envelope{}, ErrTooLarge
	}
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("protocol: decode envelope: %w", err)
	}
	return envelope, nil
}

// Acceptor holds the local context an envelope is checked against: which
// network we are in, who we are, and what we have already seen.
type Acceptor struct {
	NetworkID     string
	LocalDeviceID string
	Replay        *ReplayCache
	// Now is injectable so tests do not sleep. Nil means time.Now.
	Now func() time.Time
}

func (a *Acceptor) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Verify performs every check that does not need membership state: version,
// signature, device-id binding, network, addressing, clock and replay. It
// returns the first failure, and the caller drops the message — there is no
// partial acceptance.
//
// Authorisation is deliberately NOT here. Knowing a message is authentic is a
// different question from being willing to build a tunnel with its sender, and
// conflating the two is how a discovery system turns into an access grant.
func (a *Acceptor) Verify(e Envelope) error {
	if e.ProtocolVersion < MinVersion || e.ProtocolVersion > Version {
		return ErrUnsupportedPV
	}
	if len(e.FromPublicKey) != ed25519.PublicKeySize {
		return ErrBadSignature
	}
	if e.FromDeviceID != identity.DeviceIDFromKey(e.FromPublicKey) {
		return ErrBadSignature
	}
	if a.NetworkID != "" && e.NetworkID != a.NetworkID {
		return ErrWrongNetwork
	}
	if e.ToDeviceID != "" && a.LocalDeviceID != "" && e.ToDeviceID != a.LocalDeviceID {
		return ErrNotAddressed
	}
	now := a.now()
	stamp := time.UnixMilli(e.Timestamp)
	if stamp.Before(now.Add(-MaxClockSkewPast)) || stamp.After(now.Add(MaxClockSkewFuture)) {
		return ErrClockSkew
	}
	signable, err := e.signingBytes()
	if err != nil {
		return fmt.Errorf("protocol: encode envelope: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(e.FromPublicKey), signable, e.Signature) {
		return ErrBadSignature
	}
	// Replay is checked last, and only for messages that are otherwise valid,
	// so an attacker cannot fill the cache with garbage message ids.
	if a.Replay != nil && !a.Replay.Admit(e.MessageID, now) {
		return ErrReplay
	}
	return nil
}

// DecodePayload unmarshals the envelope payload into target.
func (e Envelope) DecodePayload(target any) error {
	if len(e.Payload) == 0 {
		return errors.New("protocol: envelope has no payload")
	}
	if err := json.Unmarshal(e.Payload, target); err != nil {
		return fmt.Errorf("protocol: decode payload: %w", err)
	}
	return nil
}
