package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// HMACSHA256 computes HMAC-SHA256 of the message with the given key.
func HMACSHA256(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// VerifyHMAC checks if the provided HMAC matches the expected value.
func VerifyHMAC(message, key, expected []byte) bool {
	computed := HMACSHA256(message, key)
	return hmac.Equal(computed, expected)
}

// DeriveSessionKey derives a session key from guardian_nonce, client_nonce, and token
// using the formula: HMAC-SHA256(guardian_nonce || client_nonce, token || "guardian-session-v1")
func DeriveSessionKey(guardianNonce, clientNonce, token []byte) []byte {
	message := append(guardianNonce, clientNonce...)
	key := append(token, []byte("guardian-session-v1")...)
	return HMACSHA256(message, key)
}

// GenerateNonce creates a cryptographically random nonce of the specified size.
func GenerateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}

// GenerateToken creates a random 256-bit (32-byte) token.
func GenerateToken() ([]byte, error) {
	return GenerateNonce(32)
}
