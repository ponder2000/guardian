package protocol

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestWriteReadMessage(t *testing.T) {
	var buf bytes.Buffer

	original := GuardianHello{
		GuardianNonce: []byte("test-nonce-1234567890abcdef"),
		Signature:     []byte("test-signature-data"),
	}

	if err := WriteMessage(&buf, MsgGuardianHello, &original); err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	msgType, data, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if msgType != MsgGuardianHello {
		t.Fatalf("expected message type 0x%02x, got 0x%02x", MsgGuardianHello, msgType)
	}

	var decoded GuardianHello
	if err := Decode(data, &decoded); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !bytes.Equal(decoded.GuardianNonce, original.GuardianNonce) {
		t.Errorf("GuardianNonce mismatch: got %q, want %q", decoded.GuardianNonce, original.GuardianNonce)
	}
	if !bytes.Equal(decoded.Signature, original.Signature) {
		t.Errorf("Signature mismatch: got %q, want %q", decoded.Signature, original.Signature)
	}
}

func TestWriteReadServiceAuth(t *testing.T) {
	var buf bytes.Buffer

	original := ServiceAuth{
		ServiceID:   "my-service-01",
		ClientNonce: []byte("client-nonce-abcdef"),
		HMAC:        []byte("hmac-value-0123456789"),
	}

	if err := WriteMessage(&buf, MsgServiceAuth, &original); err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	msgType, data, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if msgType != MsgServiceAuth {
		t.Fatalf("expected message type 0x%02x, got 0x%02x", MsgServiceAuth, msgType)
	}

	var decoded ServiceAuth
	if err := Decode(data, &decoded); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.ServiceID != original.ServiceID {
		t.Errorf("ServiceID mismatch: got %q, want %q", decoded.ServiceID, original.ServiceID)
	}
	if !bytes.Equal(decoded.ClientNonce, original.ClientNonce) {
		t.Errorf("ClientNonce mismatch: got %q, want %q", decoded.ClientNonce, original.ClientNonce)
	}
	if !bytes.Equal(decoded.HMAC, original.HMAC) {
		t.Errorf("HMAC mismatch: got %q, want %q", decoded.HMAC, original.HMAC)
	}
}

func TestWriteReadAuthResult(t *testing.T) {
	var buf bytes.Buffer

	original := AuthResult{
		Status:    "ok",
		SessionID: "session-abc-123",
	}

	if err := WriteMessage(&buf, MsgAuthResult, &original); err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	msgType, data, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if msgType != MsgAuthResult {
		t.Fatalf("expected message type 0x%02x, got 0x%02x", MsgAuthResult, msgType)
	}

	var decoded AuthResult
	if err := Decode(data, &decoded); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Status != original.Status {
		t.Errorf("Status mismatch: got %q, want %q", decoded.Status, original.Status)
	}
	if decoded.SessionID != original.SessionID {
		t.Errorf("SessionID mismatch: got %q, want %q", decoded.SessionID, original.SessionID)
	}
	if decoded.Error != "" {
		t.Errorf("Error should be empty, got %q", decoded.Error)
	}
}

func TestWriteReadLicenseRequest(t *testing.T) {
	var buf bytes.Buffer

	original := LicenseRequest{
		Module: "analytics-pro",
	}

	if err := WriteMessage(&buf, MsgLicenseRequest, &original); err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	msgType, data, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if msgType != MsgLicenseRequest {
		t.Fatalf("expected message type 0x%02x, got 0x%02x", MsgLicenseRequest, msgType)
	}

	var decoded LicenseRequest
	if err := Decode(data, &decoded); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Module != original.Module {
		t.Errorf("Module mismatch: got %q, want %q", decoded.Module, original.Module)
	}
}

func TestWriteReadLicenseResponse(t *testing.T) {
	var buf bytes.Buffer

	original := LicenseResponse{
		Valid:     true,
		Module:    "analytics-pro",
		ExpiresAt: "2026-12-31T23:59:59Z",
		Features:  []string{"dashboard", "export", "api"},
		Metadata: map[string]interface{}{
			"max_users": 100,
			"max_seats": 50,
		},
	}

	if err := WriteMessage(&buf, MsgLicenseResponse, &original); err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	msgType, data, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if msgType != MsgLicenseResponse {
		t.Fatalf("expected message type 0x%02x, got 0x%02x", MsgLicenseResponse, msgType)
	}

	var decoded LicenseResponse
	if err := Decode(data, &decoded); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Valid != original.Valid {
		t.Errorf("Valid mismatch: got %v, want %v", decoded.Valid, original.Valid)
	}
	if decoded.Module != original.Module {
		t.Errorf("Module mismatch: got %q, want %q", decoded.Module, original.Module)
	}
	if decoded.ExpiresAt != original.ExpiresAt {
		t.Errorf("ExpiresAt mismatch: got %q, want %q", decoded.ExpiresAt, original.ExpiresAt)
	}
	if len(decoded.Features) != len(original.Features) {
		t.Errorf("Features length mismatch: got %d, want %d", len(decoded.Features), len(original.Features))
	}
	for i, f := range decoded.Features {
		if f != original.Features[i] {
			t.Errorf("Feature[%d] mismatch: got %q, want %q", i, f, original.Features[i])
		}
	}
	if decoded.Metadata == nil {
		t.Fatal("Limits should not be nil")
	}
	if decoded.Error != "" {
		t.Errorf("Error should be empty, got %q", decoded.Error)
	}
}

func TestWriteReadHeartbeat(t *testing.T) {
	now := time.Now().Unix()

	t.Run("Ping", func(t *testing.T) {
		var buf bytes.Buffer

		original := HeartbeatPing{
			Timestamp: now,
		}

		if err := WriteMessage(&buf, MsgHeartbeatPing, &original); err != nil {
			t.Fatalf("WriteMessage failed: %v", err)
		}

		msgType, data, err := ReadMessage(&buf)
		if err != nil {
			t.Fatalf("ReadMessage failed: %v", err)
		}

		if msgType != MsgHeartbeatPing {
			t.Fatalf("expected message type 0x%02x, got 0x%02x", MsgHeartbeatPing, msgType)
		}

		var decoded HeartbeatPing
		if err := Decode(data, &decoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		if decoded.Timestamp != original.Timestamp {
			t.Errorf("Timestamp mismatch: got %d, want %d", decoded.Timestamp, original.Timestamp)
		}
	})

	t.Run("Pong", func(t *testing.T) {
		var buf bytes.Buffer

		original := HeartbeatPong{
			Timestamp:     now,
			HWStatus:      "ok",
			LicenseStatus: "valid",
			ExpiresInDays: 90,
		}

		if err := WriteMessage(&buf, MsgHeartbeatPong, &original); err != nil {
			t.Fatalf("WriteMessage failed: %v", err)
		}

		msgType, data, err := ReadMessage(&buf)
		if err != nil {
			t.Fatalf("ReadMessage failed: %v", err)
		}

		if msgType != MsgHeartbeatPong {
			t.Fatalf("expected message type 0x%02x, got 0x%02x", MsgHeartbeatPong, msgType)
		}

		var decoded HeartbeatPong
		if err := Decode(data, &decoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		if decoded.Timestamp != original.Timestamp {
			t.Errorf("Timestamp mismatch: got %d, want %d", decoded.Timestamp, original.Timestamp)
		}
		if decoded.HWStatus != original.HWStatus {
			t.Errorf("HWStatus mismatch: got %q, want %q", decoded.HWStatus, original.HWStatus)
		}
		if decoded.LicenseStatus != original.LicenseStatus {
			t.Errorf("LicenseStatus mismatch: got %q, want %q", decoded.LicenseStatus, original.LicenseStatus)
		}
		if decoded.ExpiresInDays != original.ExpiresInDays {
			t.Errorf("ExpiresInDays mismatch: got %d, want %d", decoded.ExpiresInDays, original.ExpiresInDays)
		}
	})
}

func TestWriteReadRevokeNotice(t *testing.T) {
	var buf bytes.Buffer

	original := RevokeNotice{
		Reason:    "license expired",
		Timestamp: time.Now().Unix(),
	}

	if err := WriteMessage(&buf, MsgRevokeNotice, &original); err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	msgType, data, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if msgType != MsgRevokeNotice {
		t.Fatalf("expected message type 0x%02x, got 0x%02x", MsgRevokeNotice, msgType)
	}

	var decoded RevokeNotice
	if err := Decode(data, &decoded); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Reason != original.Reason {
		t.Errorf("Reason mismatch: got %q, want %q", decoded.Reason, original.Reason)
	}
	if decoded.Timestamp != original.Timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d", decoded.Timestamp, original.Timestamp)
	}
}

func TestWriteReadError(t *testing.T) {
	var buf bytes.Buffer

	original := ErrorMsg{
		Code:    403,
		Message: "access denied",
	}

	if err := WriteMessage(&buf, MsgError, &original); err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	msgType, data, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if msgType != MsgError {
		t.Fatalf("expected message type 0x%02x, got 0x%02x", MsgError, msgType)
	}

	var decoded ErrorMsg
	if err := Decode(data, &decoded); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Code != original.Code {
		t.Errorf("Code mismatch: got %d, want %d", decoded.Code, original.Code)
	}
	if decoded.Message != original.Message {
		t.Errorf("Message mismatch: got %q, want %q", decoded.Message, original.Message)
	}
}

func TestEncryptedMessage(t *testing.T) {
	// Generate a 32-byte session key for AES-256.
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatalf("generate session key: %v", err)
	}

	var buf bytes.Buffer

	original := HeartbeatPing{
		Timestamp: time.Now().Unix(),
	}

	if err := WriteEncryptedMessage(&buf, MsgHeartbeatPing, &original, sessionKey); err != nil {
		t.Fatalf("WriteEncryptedMessage failed: %v", err)
	}

	msgType, data, err := ReadEncryptedMessage(&buf, sessionKey)
	if err != nil {
		t.Fatalf("ReadEncryptedMessage failed: %v", err)
	}

	if msgType != MsgHeartbeatPing {
		t.Fatalf("expected message type 0x%02x, got 0x%02x", MsgHeartbeatPing, msgType)
	}

	var decoded HeartbeatPing
	if err := Decode(data, &decoded); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Timestamp != original.Timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d", decoded.Timestamp, original.Timestamp)
	}
}

func TestDecryptedMessageWrongKey(t *testing.T) {
	// Generate two different 32-byte keys.
	correctKey := make([]byte, 32)
	if _, err := rand.Read(correctKey); err != nil {
		t.Fatalf("generate correct key: %v", err)
	}

	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	var buf bytes.Buffer

	original := HeartbeatPing{
		Timestamp: time.Now().Unix(),
	}

	if err := WriteEncryptedMessage(&buf, MsgHeartbeatPing, &original, correctKey); err != nil {
		t.Fatalf("WriteEncryptedMessage failed: %v", err)
	}

	// Attempt to decrypt with wrong key should fail.
	_, _, err := ReadEncryptedMessage(&buf, wrongKey)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key, got nil")
	}
}

func TestWriteReadStatusRequest(t *testing.T) {
	var buf bytes.Buffer

	original := StatusRequest{}

	if err := WriteMessage(&buf, MsgStatusRequest, &original); err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	msgType, data, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if msgType != MsgStatusRequest {
		t.Fatalf("expected message type 0x%02x, got 0x%02x", MsgStatusRequest, msgType)
	}

	var decoded StatusRequest
	if err := Decode(data, &decoded); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
}

func TestWriteReadStatusResponse(t *testing.T) {
	var buf bytes.Buffer

	original := StatusResponse{
		Status:        "ok",
		HWStatus:      "ok",
		LicenseStatus: "ok",
		ExpiresInDays: 364,
		DaemonVersion: "1.2.3",
		Uptime:        3600,
	}

	if err := WriteMessage(&buf, MsgStatusResponse, &original); err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	msgType, data, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if msgType != MsgStatusResponse {
		t.Fatalf("expected message type 0x%02x, got 0x%02x", MsgStatusResponse, msgType)
	}

	var decoded StatusResponse
	if err := Decode(data, &decoded); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Status != original.Status {
		t.Errorf("Status mismatch: got %q, want %q", decoded.Status, original.Status)
	}
	if decoded.HWStatus != original.HWStatus {
		t.Errorf("HWStatus mismatch: got %q, want %q", decoded.HWStatus, original.HWStatus)
	}
	if decoded.LicenseStatus != original.LicenseStatus {
		t.Errorf("LicenseStatus mismatch: got %q, want %q", decoded.LicenseStatus, original.LicenseStatus)
	}
	if decoded.ExpiresInDays != original.ExpiresInDays {
		t.Errorf("ExpiresInDays mismatch: got %d, want %d", decoded.ExpiresInDays, original.ExpiresInDays)
	}
	if decoded.DaemonVersion != original.DaemonVersion {
		t.Errorf("DaemonVersion mismatch: got %q, want %q", decoded.DaemonVersion, original.DaemonVersion)
	}
	if decoded.Uptime != original.Uptime {
		t.Errorf("Uptime mismatch: got %d, want %d", decoded.Uptime, original.Uptime)
	}
}

func TestMessageTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		msgType  MessageType
		expected uint8
	}{
		{"MsgGuardianHello", MsgGuardianHello, 0x01},
		{"MsgServiceAuth", MsgServiceAuth, 0x02},
		{"MsgAuthResult", MsgAuthResult, 0x03},
		{"MsgLicenseRequest", MsgLicenseRequest, 0x04},
		{"MsgLicenseResponse", MsgLicenseResponse, 0x05},
		{"MsgHeartbeatPing", MsgHeartbeatPing, 0x06},
		{"MsgHeartbeatPong", MsgHeartbeatPong, 0x07},
		{"MsgRevokeNotice", MsgRevokeNotice, 0x08},
		{"MsgStatusRequest", MsgStatusRequest, 0x09},
		{"MsgStatusResponse", MsgStatusResponse, 0x0A},
		{"MsgError", MsgError, 0xFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint8(tt.msgType) != tt.expected {
				t.Errorf("%s: got 0x%02x, want 0x%02x", tt.name, uint8(tt.msgType), tt.expected)
			}
		})
	}
}
