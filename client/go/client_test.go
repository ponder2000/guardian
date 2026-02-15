package guardian

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ponder2000/guardian/internal/auth"
	"github.com/ponder2000/guardian/internal/crypto"
	"github.com/ponder2000/guardian/internal/license"
	"github.com/ponder2000/guardian/internal/server"
)

// setupTestClientServer creates a fully wired test environment:
//   - temp directory with token store, license file, and daemon keypair
//   - a running server.Server on a temp Unix domain socket
//   - a Client configured to connect to that socket
//
// Returns the client and a cleanup function that stops the server.
func setupTestClientServer(t *testing.T) (*Client, func()) {
	t.Helper()

	dir := t.TempDir()
	// Use /tmp for socket to avoid macOS path length limits (max ~104 chars)
	sockDir, err := os.MkdirTemp("/tmp", "gtest-*")
	if err != nil {
		t.Fatalf("create sock dir: %v", err)
	}
	sockPath := filepath.Join(sockDir, "g.sock")
	tokenDir := filepath.Join(dir, "tokens")
	os.Mkdir(tokenDir, 0700)

	// Generate daemon key pair.
	daemonKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate daemon key pair: %v", err)
	}
	daemonPubHex := hex.EncodeToString(daemonKP.PublicKey)

	// Create token store and register a test service.
	tokenStore := auth.NewTokenStore(filepath.Join(dir, "tokens.db"), tokenDir)
	_, err = tokenStore.Register("test-svc", []string{"rdpms-core"}, daemonPubHex)
	if err != nil {
		t.Fatalf("register service: %v", err)
	}

	// Create a test license with an enabled module and a disabled module.
	masterKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate master key pair: %v", err)
	}
	lic := &license.License{
		LicenseID: "LIC-TEST-CLIENT",
		Version:   1,
		IssuedTo:  "TestClient",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).UTC(),
		Modules: map[string]license.Module{
			"rdpms-core": {
				Enabled:  true,
				Features: []string{"feature-a", "feature-b"},
				Metadata:   map[string]interface{}{"max_users": float64(100)},
			},
			"rdpms-analytics": {
				Enabled:  false,
				Features: []string{},
				Metadata:   map[string]interface{}{},
			},
		},
	}
	licData, err := license.CreateSignedFile(lic, masterKP.PrivateKey, "test-signer")
	if err != nil {
		t.Fatalf("create signed license: %v", err)
	}
	sl, err := license.ParseFile(licData)
	if err != nil {
		t.Fatalf("parse license file: %v", err)
	}

	// Start the server.
	logger := log.New(os.Stderr, "test-server: ", 0)
	srv := server.New(server.Config{
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

	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	// Build the token file path that Register wrote.
	tokenPath := filepath.Join(tokenDir, "test-svc.token")

	// Create a client pointed at the test server.
	client := NewClient(
		WithSocket(sockPath),
		WithTokenFile(tokenPath),
	)

	cleanup := func() {
		client.Close()
		srv.Stop()
		os.RemoveAll(sockDir)
	}

	return client, cleanup
}

func TestClientConnectAndCheckLicense(t *testing.T) {
	client, cleanup := setupTestClientServer(t)
	defer cleanup()

	// Connect and authenticate.
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	if !client.IsConnected() {
		t.Fatal("expected IsConnected() to be true after Connect()")
	}

	// Check a valid, enabled module.
	info, err := client.CheckLicense("rdpms-core")
	if err != nil {
		t.Fatalf("CheckLicense() error: %v", err)
	}

	if !info.Valid {
		t.Error("expected license to be valid for rdpms-core")
	}
	if info.Module != "rdpms-core" {
		t.Errorf("Module = %q, want %q", info.Module, "rdpms-core")
	}
	if info.ExpiresAt == "" {
		t.Error("ExpiresAt should not be empty")
	}
	if len(info.Features) != 2 {
		t.Errorf("Features count = %d, want 2", len(info.Features))
	}
	if info.Metadata["max_users"] != float64(100) {
		t.Errorf("max_users limit = %v, want 100", info.Metadata["max_users"])
	}
}

func TestClientHeartbeat(t *testing.T) {
	client, cleanup := setupTestClientServer(t)
	defer cleanup()

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	info, err := client.Heartbeat()
	if err != nil {
		t.Fatalf("Heartbeat() error: %v", err)
	}

	if info.HWStatus != "ok" {
		t.Errorf("HWStatus = %q, want %q", info.HWStatus, "ok")
	}
	if info.LicenseStatus != "ok" {
		t.Errorf("LicenseStatus = %q, want %q", info.LicenseStatus, "ok")
	}
	if info.ExpiresInDays <= 0 {
		t.Errorf("ExpiresInDays = %d, expected > 0", info.ExpiresInDays)
	}
}

func TestClientCheckLicenseDisabledModule(t *testing.T) {
	client, cleanup := setupTestClientServer(t)
	defer cleanup()

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	// Check a disabled module — server should return valid=false.
	info, err := client.CheckLicense("rdpms-analytics")
	if err != nil {
		t.Fatalf("CheckLicense() error: %v", err)
	}

	if info.Valid {
		t.Error("expected license to be invalid for disabled module rdpms-analytics")
	}
	if info.Module != "rdpms-analytics" {
		t.Errorf("Module = %q, want %q", info.Module, "rdpms-analytics")
	}
}

func TestClientConnectBadToken(t *testing.T) {
	dir := t.TempDir()
	// Use /tmp for socket to avoid macOS path length limits (max ~104 chars)
	sockDir, err := os.MkdirTemp("/tmp", "gtest-bad-*")
	if err != nil {
		t.Fatalf("create sock dir: %v", err)
	}
	defer os.RemoveAll(sockDir)
	sockPath := filepath.Join(sockDir, "g.sock")
	tokenDir := filepath.Join(dir, "tokens")
	os.Mkdir(tokenDir, 0700)

	// Generate daemon key pair.
	daemonKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate daemon key pair: %v", err)
	}
	daemonPubHex := hex.EncodeToString(daemonKP.PublicKey)

	// Create token store and register the real service.
	tokenStore := auth.NewTokenStore(filepath.Join(dir, "tokens.db"), tokenDir)
	_, err = tokenStore.Register("test-svc", []string{"rdpms-core"}, daemonPubHex)
	if err != nil {
		t.Fatalf("register service: %v", err)
	}

	// Create a license.
	masterKP, _ := crypto.GenerateKeyPair()
	lic := &license.License{
		LicenseID: "LIC-BAD",
		Version:   1,
		IssuedTo:  "Test",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).UTC(),
		Modules: map[string]license.Module{
			"rdpms-core": {Enabled: true, Features: []string{"f1"}, Metadata: map[string]interface{}{}},
		},
	}
	licData, _ := license.CreateSignedFile(lic, masterKP.PrivateKey, "test")
	sl, _ := license.ParseFile(licData)

	// Start server.
	logger := log.New(os.Stderr, "test-server-bad: ", 0)
	srv := server.New(server.Config{
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
	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Stop()

	// Write a token file with a WRONG token but correct service ID and daemon pub.
	badTokenPath := filepath.Join(dir, "bad.token")
	badTokenHex := hex.EncodeToString([]byte("wrong-token-value-32-bytes-pad!!"))
	content := fmt.Sprintf("SERVICE_ID=test-svc\nTOKEN=tok_%s\nDAEMON_PUB=dpub_%s\n",
		badTokenHex, daemonPubHex)
	os.WriteFile(badTokenPath, []byte(content), 0600)

	client := NewClient(
		WithSocket(sockPath),
		WithTokenFile(badTokenPath),
	)
	defer client.Close()

	err = client.Connect()
	if err == nil {
		t.Fatal("Connect() expected error with bad token, got nil")
	}
}

func TestClientDefaultOptions(t *testing.T) {
	// Test that environment variables override built-in defaults.
	customSocket := "/tmp/test-guardian.sock"
	customToken := "/tmp/test-guardian.token"

	t.Setenv("GUARDIAN_SOCKET", customSocket)
	t.Setenv("GUARDIAN_TOKEN_PATH", customToken)

	client := NewClient()

	if client.socketPath != customSocket {
		t.Errorf("socketPath = %q, want %q (from GUARDIAN_SOCKET)", client.socketPath, customSocket)
	}
	if client.tokenPath != customToken {
		t.Errorf("tokenPath = %q, want %q (from GUARDIAN_TOKEN_PATH)", client.tokenPath, customToken)
	}

	// Test that explicit options override env vars.
	explicitSocket := "/run/guardian/override.sock"
	explicitToken := "/etc/guardian/override.token"

	client2 := NewClient(
		WithSocket(explicitSocket),
		WithTokenFile(explicitToken),
	)
	if client2.socketPath != explicitSocket {
		t.Errorf("socketPath = %q, want %q (from WithSocket)", client2.socketPath, explicitSocket)
	}
	if client2.tokenPath != explicitToken {
		t.Errorf("tokenPath = %q, want %q (from WithTokenFile)", client2.tokenPath, explicitToken)
	}

	// Test built-in defaults when no env vars are set.
	t.Setenv("GUARDIAN_SOCKET", "")
	t.Setenv("GUARDIAN_TOKEN_PATH", "")

	client3 := NewClient()
	if client3.socketPath != defaultSocketPath {
		t.Errorf("socketPath = %q, want %q (built-in default)", client3.socketPath, defaultSocketPath)
	}
	if client3.tokenPath != defaultTokenPath {
		t.Errorf("tokenPath = %q, want %q (built-in default)", client3.tokenPath, defaultTokenPath)
	}
}
