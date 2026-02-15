package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ponder2000/guardian/internal/crypto"
)

func TestTokenStoreRegisterAndLookup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tokens.db")
	tokenDir := filepath.Join(dir, "tokens")
	os.Mkdir(tokenDir, 0700)

	store := NewTokenStore(dbPath, tokenDir)

	st, err := store.Register("test-service", []string{"module-a"}, "deadbeef")
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	if st.ServiceID != "test-service" {
		t.Errorf("ServiceID = %q, want %q", st.ServiceID, "test-service")
	}
	if len(st.Token) != 32 {
		t.Errorf("token length = %d, want 32", len(st.Token))
	}

	// Lookup
	found, err := store.Lookup("test-service")
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}
	if !bytes.Equal(found.Token, st.Token) {
		t.Error("looked up token doesn't match registered token")
	}

	// Verify token file was created
	tokenPath := filepath.Join(tokenDir, "test-service.token")
	if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
		t.Error("token file was not created")
	}
}

func TestTokenStoreLookupNotFound(t *testing.T) {
	store := NewTokenStore("", "")
	_, err := store.Lookup("nonexistent")
	if err == nil {
		t.Error("Lookup() expected error for nonexistent service")
	}
}

func TestTokenStoreRevoke(t *testing.T) {
	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	os.Mkdir(tokenDir, 0700)

	store := NewTokenStore(filepath.Join(dir, "tokens.db"), tokenDir)
	store.Register("svc", nil, "pub")

	err := store.Revoke("svc")
	if err != nil {
		t.Fatalf("Revoke() error: %v", err)
	}

	_, err = store.Lookup("svc")
	if err == nil {
		t.Error("Lookup() should fail after revoke")
	}
}

func TestTokenStoreRevokeNotFound(t *testing.T) {
	store := NewTokenStore("", "")
	err := store.Revoke("nonexistent")
	if err == nil {
		t.Error("Revoke() expected error for nonexistent service")
	}
}

func TestTokenStoreRotate(t *testing.T) {
	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	os.Mkdir(tokenDir, 0700)

	store := NewTokenStore(filepath.Join(dir, "tokens.db"), tokenDir)
	st, _ := store.Register("svc", nil, "pub")
	oldToken := make([]byte, len(st.Token))
	copy(oldToken, st.Token)

	err := store.Rotate("svc", "newpub")
	if err != nil {
		t.Fatalf("Rotate() error: %v", err)
	}

	found, _ := store.Lookup("svc")
	if bytes.Equal(found.Token, oldToken) {
		t.Error("token should have changed after rotation")
	}
}

func TestTokenStoreSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tokens.db")
	tokenDir := filepath.Join(dir, "tokens")
	os.Mkdir(tokenDir, 0700)

	store := NewTokenStore(dbPath, tokenDir)
	store.Register("svc-a", []string{"mod1"}, "pub")
	store.Register("svc-b", []string{"mod2"}, "pub")

	if err := store.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Load into new store
	store2 := NewTokenStore(dbPath, tokenDir)
	if err := store2.Load(); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if _, err := store2.Lookup("svc-a"); err != nil {
		t.Errorf("svc-a not found after load: %v", err)
	}
	if _, err := store2.Lookup("svc-b"); err != nil {
		t.Errorf("svc-b not found after load: %v", err)
	}
}

func TestTokenStoreLoadNonexistent(t *testing.T) {
	store := NewTokenStore("/nonexistent/tokens.db", "")
	// Should not error on missing file (fresh DB)
	if err := store.Load(); err != nil {
		t.Errorf("Load() should not error on missing file: %v", err)
	}
}

func TestTokenStoreListServices(t *testing.T) {
	store := NewTokenStore("", "")
	store.tokens["svc-a"] = &ServiceToken{ServiceID: "svc-a", Token: []byte("a")}
	store.tokens["svc-b"] = &ServiceToken{ServiceID: "svc-b", Token: []byte("b")}

	services := store.ListServices()
	if len(services) != 2 {
		t.Errorf("ListServices() count = %d, want 2", len(services))
	}
}

func TestParseTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.token")

	content := `# Guardian credential file for: test-svc
# Generated: 2026-02-15T10:30:00Z

SERVICE_ID=test-svc
TOKEN=tok_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
DAEMON_PUB=dpub_cafebabe
`
	os.WriteFile(path, []byte(content), 0600)

	creds, err := ParseTokenFile(path)
	if err != nil {
		t.Fatalf("ParseTokenFile() error: %v", err)
	}

	if creds.ServiceID != "test-svc" {
		t.Errorf("ServiceID = %q, want %q", creds.ServiceID, "test-svc")
	}
	if len(creds.Token) != 32 {
		t.Errorf("token length = %d, want 32", len(creds.Token))
	}
	if creds.DaemonPub != "cafebabe" {
		t.Errorf("DaemonPub = %q, want %q", creds.DaemonPub, "cafebabe")
	}
}

func TestParseTokenFileInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.token")
	os.WriteFile(path, []byte("no valid fields here\n"), 0600)

	_, err := ParseTokenFile(path)
	if err == nil {
		t.Error("ParseTokenFile() expected error for invalid file")
	}
}

func TestInitHandshake(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}

	state, err := InitHandshake(kp, 32)
	if err != nil {
		t.Fatalf("InitHandshake() error: %v", err)
	}

	if len(state.GuardianNonce) != 32 {
		t.Errorf("nonce length = %d, want 32", len(state.GuardianNonce))
	}

	// Verify the signature
	if !crypto.Verify(kp.PublicKey, state.GuardianNonce, state.Signature) {
		t.Error("signature verification failed")
	}
}

func TestVerifyGuardianHello(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	nonce := []byte("test-nonce-32-bytes-padded-here!")
	sig := kp.Sign(nonce)

	if err := VerifyGuardianHello(nonce, sig, kp.PublicKey); err != nil {
		t.Errorf("VerifyGuardianHello() error: %v", err)
	}

	// Wrong signature
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	if err := VerifyGuardianHello(nonce, badSig, kp.PublicKey); err == nil {
		t.Error("VerifyGuardianHello() expected error for bad signature")
	}
}

func TestHandshakeFullFlow(t *testing.T) {
	// Setup guardian side
	daemonKP, _ := crypto.GenerateKeyPair()
	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	os.Mkdir(tokenDir, 0700)
	tokenStore := NewTokenStore(filepath.Join(dir, "tokens.db"), tokenDir)
	tokenStore.Register("test-svc", nil, "pub")

	st, _ := tokenStore.Lookup("test-svc")
	serviceToken := st.Token

	// Step 1: Guardian sends HELLO
	hsState, err := InitHandshake(daemonKP, 32)
	if err != nil {
		t.Fatalf("InitHandshake: %v", err)
	}

	// Step 2: Client verifies guardian
	if err := VerifyGuardianHello(hsState.GuardianNonce, hsState.Signature, daemonKP.PublicKey); err != nil {
		t.Fatalf("VerifyGuardianHello: %v", err)
	}

	// Step 3: Client computes HMAC
	clientNonce, _ := crypto.GenerateNonce(32)
	clientHMAC := ComputeClientHMAC(hsState.GuardianNonce, clientNonce, serviceToken)

	// Step 4: Guardian verifies client
	sessionKey, err := VerifyServiceAuth(hsState.GuardianNonce, "test-svc", clientNonce, clientHMAC, tokenStore)
	if err != nil {
		t.Fatalf("VerifyServiceAuth: %v", err)
	}

	// Step 5: Both derive the same session key
	clientSessionKey := crypto.DeriveSessionKey(hsState.GuardianNonce, clientNonce, serviceToken)
	if !bytes.Equal(sessionKey, clientSessionKey) {
		t.Error("session keys don't match between guardian and client")
	}
}

func TestVerifyServiceAuthBadHMAC(t *testing.T) {
	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	os.Mkdir(tokenDir, 0700)
	store := NewTokenStore(filepath.Join(dir, "tokens.db"), tokenDir)
	store.Register("svc", nil, "pub")

	gNonce := []byte("guardian-nonce-32-bytes-padded!!")
	cNonce := []byte("client--nonce-32-bytes-padded!!")
	badHMAC := []byte("completely-wrong-hmac-value-here!")

	_, err := VerifyServiceAuth(gNonce, "svc", cNonce, badHMAC, store)
	if err == nil {
		t.Error("VerifyServiceAuth() expected error for bad HMAC")
	}
}

func TestVerifyServiceAuthUnknownService(t *testing.T) {
	store := NewTokenStore("", "")

	_, err := VerifyServiceAuth(nil, "unknown", nil, nil, store)
	if err == nil {
		t.Error("VerifyServiceAuth() expected error for unknown service")
	}
}

func TestSessionManager(t *testing.T) {
	sm := NewSessionManager(30 * time.Minute)

	sess := sm.CreateSession("svc", []byte("session-key"))
	if sess.ServiceID != "svc" {
		t.Errorf("ServiceID = %q", sess.ServiceID)
	}

	found, err := sm.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error: %v", err)
	}
	if found.ID != sess.ID {
		t.Error("session IDs don't match")
	}

	if sm.Count() != 1 {
		t.Errorf("Count() = %d, want 1", sm.Count())
	}

	sm.UpdatePing(sess.ID)

	sm.RemoveSession(sess.ID)
	if sm.Count() != 0 {
		t.Errorf("Count() = %d after remove, want 0", sm.Count())
	}
}

func TestSessionManagerGetNotFound(t *testing.T) {
	sm := NewSessionManager(30 * time.Minute)
	_, err := sm.GetSession("nonexistent")
	if err == nil {
		t.Error("GetSession() expected error for nonexistent session")
	}
}

func TestSessionManagerCleanExpired(t *testing.T) {
	sm := NewSessionManager(1 * time.Millisecond)

	sm.CreateSession("svc", []byte("key"))
	time.Sleep(10 * time.Millisecond)

	removed := sm.CleanExpired()
	if removed != 1 {
		t.Errorf("CleanExpired() = %d, want 1", removed)
	}
	if sm.Count() != 0 {
		t.Errorf("Count() = %d after cleanup, want 0", sm.Count())
	}
}

func TestSessionManagerActiveSessions(t *testing.T) {
	sm := NewSessionManager(30 * time.Minute)
	sm.CreateSession("svc-a", []byte("key-a"))
	sm.CreateSession("svc-b", []byte("key-b"))

	sessions := sm.ActiveSessions()
	if len(sessions) != 2 {
		t.Errorf("ActiveSessions() count = %d, want 2", len(sessions))
	}
}
