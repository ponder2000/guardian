package crypto

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}
	if len(kp.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("private key size = %d, want %d", len(kp.PrivateKey), ed25519.PrivateKeySize)
	}
	if len(kp.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("public key size = %d, want %d", len(kp.PublicKey), ed25519.PublicKeySize)
	}
}

func TestSignAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}

	message := []byte("hello guardian")
	sig := kp.Sign(message)

	if !Verify(kp.PublicKey, message, sig) {
		t.Error("Verify() returned false for valid signature")
	}

	// Tamper with message
	if Verify(kp.PublicKey, []byte("tampered"), sig) {
		t.Error("Verify() returned true for tampered message")
	}

	// Tamper with signature
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	if Verify(kp.PublicKey, message, badSig) {
		t.Error("Verify() returned true for tampered signature")
	}
}

func TestSaveAndLoadKeys(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}

	if err := kp.SavePrivateKey(privPath); err != nil {
		t.Fatalf("SavePrivateKey() error: %v", err)
	}
	if err := kp.SavePublicKey(pubPath); err != nil {
		t.Fatalf("SavePublicKey() error: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("Stat private key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("private key perms = %o, want 0600", perm)
	}

	// Load and compare
	loadedPriv, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey() error: %v", err)
	}
	if !bytes.Equal(kp.PrivateKey, loadedPriv) {
		t.Error("loaded private key doesn't match original")
	}

	loadedPub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey() error: %v", err)
	}
	if !bytes.Equal(kp.PublicKey, loadedPub) {
		t.Error("loaded public key doesn't match original")
	}
}

func TestLoadKeyInvalidPath(t *testing.T) {
	_, err := LoadPrivateKey("/nonexistent/path")
	if err == nil {
		t.Error("LoadPrivateKey() expected error for nonexistent path")
	}
	_, err = LoadPublicKey("/nonexistent/path")
	if err == nil {
		t.Error("LoadPublicKey() expected error for nonexistent path")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("secret license data")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte{}

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptTampered(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("secret data")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Tamper with ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = Decrypt(key, ciphertext)
	if err == nil {
		t.Error("Decrypt() expected error for tampered ciphertext")
	}
}

func TestEncryptInvalidKeySize(t *testing.T) {
	_, err := Encrypt([]byte("short"), []byte("data"))
	if err == nil {
		t.Error("Encrypt() expected error for short key")
	}

	_, err = Decrypt([]byte("short"), []byte("data"))
	if err == nil {
		t.Error("Decrypt() expected error for short key")
	}
}

func TestHMACSHA256(t *testing.T) {
	key := []byte("secret-key")
	message := []byte("hello world")

	mac1 := HMACSHA256(message, key)
	mac2 := HMACSHA256(message, key)

	if !bytes.Equal(mac1, mac2) {
		t.Error("HMACSHA256 not deterministic")
	}

	if len(mac1) != 32 {
		t.Errorf("HMAC length = %d, want 32", len(mac1))
	}

	// Different key produces different HMAC
	mac3 := HMACSHA256(message, []byte("different-key"))
	if bytes.Equal(mac1, mac3) {
		t.Error("different keys should produce different HMACs")
	}

	// Different message produces different HMAC
	mac4 := HMACSHA256([]byte("different message"), key)
	if bytes.Equal(mac1, mac4) {
		t.Error("different messages should produce different HMACs")
	}
}

func TestVerifyHMAC(t *testing.T) {
	key := []byte("secret-key")
	message := []byte("hello world")
	mac := HMACSHA256(message, key)

	if !VerifyHMAC(message, key, mac) {
		t.Error("VerifyHMAC() returned false for valid HMAC")
	}

	// Tampered HMAC
	badMac := make([]byte, len(mac))
	copy(badMac, mac)
	badMac[0] ^= 0xFF
	if VerifyHMAC(message, key, badMac) {
		t.Error("VerifyHMAC() returned true for tampered HMAC")
	}
}

func TestDeriveSessionKey(t *testing.T) {
	gNonce := []byte("guardian-nonce-data-32-bytes-long")
	cNonce := []byte("client--nonce-data-32-bytes-long")
	token := []byte("service-token-32-bytes-long-data")

	key1 := DeriveSessionKey(gNonce, cNonce, token)
	key2 := DeriveSessionKey(gNonce, cNonce, token)

	if !bytes.Equal(key1, key2) {
		t.Error("DeriveSessionKey not deterministic")
	}

	if len(key1) != 32 {
		t.Errorf("session key length = %d, want 32", len(key1))
	}

	// Different nonces produce different keys
	key3 := DeriveSessionKey([]byte("different-nonce-32-bytes-long!!!"), cNonce, token)
	if bytes.Equal(key1, key3) {
		t.Error("different guardian nonces should produce different session keys")
	}
}

func TestGenerateNonce(t *testing.T) {
	n1, err := GenerateNonce(32)
	if err != nil {
		t.Fatalf("GenerateNonce() error: %v", err)
	}
	if len(n1) != 32 {
		t.Errorf("nonce length = %d, want 32", len(n1))
	}

	n2, err := GenerateNonce(32)
	if err != nil {
		t.Fatalf("GenerateNonce() error: %v", err)
	}

	// Two random nonces should differ (probability of collision is negligible)
	if bytes.Equal(n1, n2) {
		t.Error("two random nonces should not be equal")
	}
}

func TestGenerateToken(t *testing.T) {
	tok, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}
	if len(tok) != 32 {
		t.Errorf("token length = %d, want 32", len(tok))
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	message := []byte("test message for round trip")
	sig := kp.Sign(message)

	// Save and reload keys, then verify
	dir := t.TempDir()
	kp.SavePrivateKey(filepath.Join(dir, "priv"))
	kp.SavePublicKey(filepath.Join(dir, "pub"))

	loadedPub, _ := LoadPublicKey(filepath.Join(dir, "pub"))
	if !Verify(loadedPub, message, sig) {
		t.Error("signature should verify with loaded public key")
	}
}
