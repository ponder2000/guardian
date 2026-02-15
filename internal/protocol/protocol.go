package protocol

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ponder2000/guardian/internal/crypto"
	"github.com/vmihailenco/msgpack/v5"
)

// MaxMessageSize is the maximum allowed message size (1 MB).
const MaxMessageSize = 1 << 20

// MessageType identifies the kind of protocol message.
type MessageType uint8

const (
	MsgGuardianHello   MessageType = 0x01
	MsgServiceAuth     MessageType = 0x02
	MsgAuthResult      MessageType = 0x03
	MsgLicenseRequest  MessageType = 0x04
	MsgLicenseResponse MessageType = 0x05
	MsgHeartbeatPing   MessageType = 0x06
	MsgHeartbeatPong   MessageType = 0x07
	MsgRevokeNotice    MessageType = 0x08
	MsgError           MessageType = 0xFF
)

// GuardianHello is sent by the guardian daemon after a client connects.
type GuardianHello struct {
	GuardianNonce []byte `msgpack:"guardian_nonce"`
	Signature     []byte `msgpack:"signature"`
}

// ServiceAuth is sent by a service to authenticate itself.
type ServiceAuth struct {
	ServiceID   string `msgpack:"service_id"`
	ClientNonce []byte `msgpack:"client_nonce"`
	HMAC        []byte `msgpack:"hmac"`
}

// AuthResult is the guardian's response to a ServiceAuth message.
type AuthResult struct {
	Status    string `msgpack:"status"`
	SessionID string `msgpack:"session_id"`
	Error     string `msgpack:"error,omitempty"`
}

// LicenseRequest asks the guardian for license information about a module.
type LicenseRequest struct {
	Module string `msgpack:"module"`
}

// LicenseResponse contains the license validation result.
type LicenseResponse struct {
	Valid     bool                   `msgpack:"valid"`
	Module    string                 `msgpack:"module"`
	ExpiresAt string                `msgpack:"expires_at"`
	Features  []string              `msgpack:"features"`
	Limits    map[string]interface{} `msgpack:"limits"`
	Error     string                 `msgpack:"error,omitempty"`
}

// HeartbeatPing is a keepalive ping sent by either side.
type HeartbeatPing struct {
	Timestamp int64 `msgpack:"timestamp"`
}

// HeartbeatPong is the response to a HeartbeatPing.
type HeartbeatPong struct {
	Timestamp     int64  `msgpack:"timestamp"`
	HWStatus      string `msgpack:"hw_status"`
	LicenseStatus string `msgpack:"license_status"`
	ExpiresInDays int    `msgpack:"expires_in_days"`
}

// RevokeNotice is sent by the guardian to inform the service that access is revoked.
type RevokeNotice struct {
	Reason    string `msgpack:"reason"`
	Timestamp int64  `msgpack:"timestamp"`
}

// ErrorMsg represents a generic error message.
type ErrorMsg struct {
	Code    int    `msgpack:"code"`
	Message string `msgpack:"message"`
}

// Encode serializes a struct to msgpack bytes.
func Encode(v interface{}) ([]byte, error) {
	data, err := msgpack.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("msgpack encode: %w", err)
	}
	return data, nil
}

// Decode deserializes msgpack bytes into a struct.
func Decode(data []byte, v interface{}) error {
	if err := msgpack.Unmarshal(data, v); err != nil {
		return fmt.Errorf("msgpack decode: %w", err)
	}
	return nil
}

// WriteMessage writes a framed message to the writer.
//
// Wire format:
//
//	[4 bytes uint32 BE total_length] [1 byte message_type] [N bytes msgpack payload]
//	total_length = 1 (type byte) + N (payload bytes)
func WriteMessage(w io.Writer, msgType MessageType, payload interface{}) error {
	data, err := Encode(payload)
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}

	totalLen := uint32(1 + len(data))
	if totalLen > MaxMessageSize {
		return fmt.Errorf("message too large: %d bytes exceeds max %d", totalLen, MaxMessageSize)
	}

	// Write length prefix (4 bytes, big-endian).
	if err := binary.Write(w, binary.BigEndian, totalLen); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	// Write message type (1 byte).
	if _, err := w.Write([]byte{byte(msgType)}); err != nil {
		return fmt.Errorf("write message type: %w", err)
	}

	// Write payload.
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	return nil
}

// ReadMessage reads a framed message from the reader. Returns the message type
// and raw msgpack bytes.
func ReadMessage(r io.Reader) (MessageType, []byte, error) {
	// Read 4-byte length prefix.
	var totalLen uint32
	if err := binary.Read(r, binary.BigEndian, &totalLen); err != nil {
		return 0, nil, fmt.Errorf("read length: %w", err)
	}

	if totalLen > MaxMessageSize {
		return 0, nil, fmt.Errorf("message too large: %d bytes exceeds max %d", totalLen, MaxMessageSize)
	}

	if totalLen < 1 {
		return 0, nil, fmt.Errorf("message too short: %d bytes", totalLen)
	}

	// Read message type (1 byte).
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, typeBuf); err != nil {
		return 0, nil, fmt.Errorf("read message type: %w", err)
	}
	msgType := MessageType(typeBuf[0])

	// Read payload.
	payloadLen := totalLen - 1
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return msgType, payload, nil
}

// WriteEncryptedMessage writes a message with an AES-GCM encrypted payload.
// The payload struct is first serialized with msgpack, then encrypted with the
// session key before framing.
func WriteEncryptedMessage(w io.Writer, msgType MessageType, payload interface{}, sessionKey []byte) error {
	data, err := Encode(payload)
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}

	encrypted, err := crypto.Encrypt(sessionKey, data)
	if err != nil {
		return fmt.Errorf("encrypt payload: %w", err)
	}

	totalLen := uint32(1 + len(encrypted))
	if totalLen > MaxMessageSize {
		return fmt.Errorf("encrypted message too large: %d bytes exceeds max %d", totalLen, MaxMessageSize)
	}

	// Write length prefix.
	if err := binary.Write(w, binary.BigEndian, totalLen); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	// Write message type.
	if _, err := w.Write([]byte{byte(msgType)}); err != nil {
		return fmt.Errorf("write message type: %w", err)
	}

	// Write encrypted payload.
	if _, err := w.Write(encrypted); err != nil {
		return fmt.Errorf("write encrypted payload: %w", err)
	}

	return nil
}

// ReadEncryptedMessage reads and decrypts a framed message. Returns the message
// type and the decrypted raw msgpack bytes.
func ReadEncryptedMessage(r io.Reader, sessionKey []byte) (MessageType, []byte, error) {
	msgType, encrypted, err := ReadMessage(r)
	if err != nil {
		return 0, nil, err
	}

	plaintext, err := crypto.Decrypt(sessionKey, encrypted)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypt payload: %w", err)
	}

	return msgType, plaintext, nil
}
