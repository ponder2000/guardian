package server

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ponder2000/guardian/internal/auth"
	"github.com/ponder2000/guardian/internal/crypto"
	"github.com/ponder2000/guardian/internal/license"
	"github.com/ponder2000/guardian/internal/protocol"
)

func setupTestServer(t *testing.T) (*Server, string, *crypto.KeyPair, []byte) {
	t.Helper()

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")
	tokenDir := filepath.Join(dir, "tokens")
	os.Mkdir(tokenDir, 0700)

	daemonKP, _ := crypto.GenerateKeyPair()
	tokenStore := auth.NewTokenStore(filepath.Join(dir, "tokens.db"), tokenDir)

	// Register a test service
	tokenStore.Register("test-svc", []string{"rdpms-core"}, "pub")
	st, _ := tokenStore.Lookup("test-svc")

	// Create a test license
	masterKP, _ := crypto.GenerateKeyPair()
	lic := &license.License{
		LicenseID: "LIC-TEST",
		Version:   1,
		IssuedTo:  "Test",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).UTC(),
		Modules: map[string]license.Module{
			"rdpms-core": {
				Enabled:  true,
				Features: []string{"feature-a"},
				Metadata:   map[string]interface{}{"max_users": float64(50)},
			},
		},
	}
	licData, _ := license.CreateSignedFile(lic, masterKP.PrivateKey, "test")
	sl, _ := license.ParseFile(licData)

	logger := log.New(os.Stderr, "test-server: ", 0)

	srv := New(Config{
		SocketPath:      sockPath,
		DaemonKeyPair:   daemonKP,
		TokenStore:      tokenStore,
		License:         sl,
		Logger:          logger,
		MaxConnections:  10,
		MaxAuthAttempts: 3,
		AuthTimeout:     5 * time.Second,
		NonceSize:       32,
		SessionTimeout:  30 * time.Minute,
	})

	return srv, sockPath, daemonKP, st.Token
}

func doClientHandshake(t *testing.T, conn net.Conn, daemonPub []byte, token []byte) []byte {
	t.Helper()

	// Read GUARDIAN_HELLO
	msgType, data, err := protocol.ReadMessage(conn)
	if err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if msgType != protocol.MsgGuardianHello {
		t.Fatalf("expected MsgGuardianHello, got 0x%02x", msgType)
	}

	var hello protocol.GuardianHello
	protocol.Decode(data, &hello)

	// Verify guardian signature
	if !crypto.Verify(daemonPub, hello.GuardianNonce, hello.Signature) {
		t.Fatal("guardian signature invalid")
	}

	// Send SERVICE_AUTH
	clientNonce, _ := crypto.GenerateNonce(32)
	hmacValue := auth.ComputeClientHMAC(hello.GuardianNonce, clientNonce, token)

	svcAuth := protocol.ServiceAuth{
		ServiceID:   "test-svc",
		ClientNonce: clientNonce,
		HMAC:        hmacValue,
	}
	if err := protocol.WriteMessage(conn, protocol.MsgServiceAuth, &svcAuth); err != nil {
		t.Fatalf("write auth: %v", err)
	}

	// Read AUTH_RESULT
	msgType, data, err = protocol.ReadMessage(conn)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	if msgType != protocol.MsgAuthResult {
		t.Fatalf("expected MsgAuthResult, got 0x%02x", msgType)
	}

	var result protocol.AuthResult
	protocol.Decode(data, &result)
	if result.Status != "ok" {
		t.Fatalf("auth failed: %s", result.Error)
	}

	// Derive session key
	sessionKey := crypto.DeriveSessionKey(hello.GuardianNonce, clientNonce, token)
	return sessionKey
}

func TestServerStartStop(t *testing.T) {
	srv, _, _, _ := setupTestServer(t)

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	if srv.ActiveConnections() != 0 {
		t.Errorf("expected 0 connections, got %d", srv.ActiveConnections())
	}

	srv.Stop()
}

func TestServerHandshake(t *testing.T) {
	srv, sockPath, daemonKP, token := setupTestServer(t)

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	sessionKey := doClientHandshake(t, conn, daemonKP.PublicKey, token)
	if len(sessionKey) != 32 {
		t.Errorf("session key length = %d, want 32", len(sessionKey))
	}

	// Wait for server to register the connection
	time.Sleep(50 * time.Millisecond)
	if srv.SessionManager().Count() != 1 {
		t.Errorf("session count = %d, want 1", srv.SessionManager().Count())
	}
}

func TestServerLicenseRequest(t *testing.T) {
	srv, sockPath, daemonKP, token := setupTestServer(t)

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	sessionKey := doClientHandshake(t, conn, daemonKP.PublicKey, token)

	// Send encrypted license request
	req := protocol.LicenseRequest{Module: "rdpms-core"}
	if err := protocol.WriteEncryptedMessage(conn, protocol.MsgLicenseRequest, &req, sessionKey); err != nil {
		t.Fatalf("write license request: %v", err)
	}

	// Read encrypted response
	msgType, data, err := protocol.ReadEncryptedMessage(conn, sessionKey)
	if err != nil {
		t.Fatalf("read license response: %v", err)
	}
	if msgType != protocol.MsgLicenseResponse {
		t.Fatalf("expected MsgLicenseResponse, got 0x%02x", msgType)
	}

	var resp protocol.LicenseResponse
	protocol.Decode(data, &resp)
	if !resp.Valid {
		t.Errorf("license should be valid, error: %s", resp.Error)
	}
	if resp.Module != "rdpms-core" {
		t.Errorf("module = %q, want %q", resp.Module, "rdpms-core")
	}
}

func TestServerHeartbeat(t *testing.T) {
	srv, sockPath, daemonKP, token := setupTestServer(t)

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	sessionKey := doClientHandshake(t, conn, daemonKP.PublicKey, token)

	// Send heartbeat ping
	ping := protocol.HeartbeatPing{Timestamp: time.Now().Unix()}
	if err := protocol.WriteEncryptedMessage(conn, protocol.MsgHeartbeatPing, &ping, sessionKey); err != nil {
		t.Fatalf("write heartbeat: %v", err)
	}

	// Read heartbeat pong
	msgType, data, err := protocol.ReadEncryptedMessage(conn, sessionKey)
	if err != nil {
		t.Fatalf("read heartbeat: %v", err)
	}
	if msgType != protocol.MsgHeartbeatPong {
		t.Fatalf("expected MsgHeartbeatPong, got 0x%02x", msgType)
	}

	var pong protocol.HeartbeatPong
	protocol.Decode(data, &pong)
	if pong.LicenseStatus != "ok" {
		t.Errorf("license status = %q, want %q", pong.LicenseStatus, "ok")
	}
	if pong.HWStatus != "ok" {
		t.Errorf("hw status = %q, want %q", pong.HWStatus, "ok")
	}
}

func TestServerBadAuth(t *testing.T) {
	srv, sockPath, _, _ := setupTestServer(t)

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	// Read GUARDIAN_HELLO
	msgType, data, err := protocol.ReadMessage(conn)
	if err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if msgType != protocol.MsgGuardianHello {
		t.Fatalf("expected MsgGuardianHello, got 0x%02x", msgType)
	}

	var hello protocol.GuardianHello
	protocol.Decode(data, &hello)

	// Send bad SERVICE_AUTH
	svcAuth := protocol.ServiceAuth{
		ServiceID:   "test-svc",
		ClientNonce: []byte("bad-nonce-but-at-least-32-bytes!"),
		HMAC:        []byte("wrong-hmac-value-32-bytes-pad!!!"),
	}
	protocol.WriteMessage(conn, protocol.MsgServiceAuth, &svcAuth)

	// Read AUTH_RESULT - should be error
	msgType, data, err = protocol.ReadMessage(conn)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}

	var result protocol.AuthResult
	protocol.Decode(data, &result)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
}
