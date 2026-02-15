package auth

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/ponder2000/guardian/internal/crypto"
)

// Session represents an authenticated connection with a service.
type Session struct {
	ID         string
	ServiceID  string
	SessionKey []byte
	CreatedAt  time.Time
	LastPing   time.Time
}

// SessionManager manages active sessions.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	timeout  time.Duration
}

// NewSessionManager creates a new session manager.
func NewSessionManager(timeout time.Duration) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		timeout:  timeout,
	}
}

// HandshakeParams holds the parameters needed for a handshake.
type HandshakeParams struct {
	DaemonKeyPair *crypto.KeyPair
	TokenStore    *TokenStore
	NonceSize     int
}

// ServerHandshakeState holds server-side handshake state.
type ServerHandshakeState struct {
	GuardianNonce []byte
	Signature     []byte
}

// InitHandshake creates a GUARDIAN_HELLO message.
// Returns the nonce and its signature for the client to verify.
func InitHandshake(daemonKP *crypto.KeyPair, nonceSize int) (*ServerHandshakeState, error) {
	nonce, err := crypto.GenerateNonce(nonceSize)
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	sig := daemonKP.Sign(nonce)

	return &ServerHandshakeState{
		GuardianNonce: nonce,
		Signature:     sig,
	}, nil
}

// VerifyServiceAuth verifies the SERVICE_AUTH message from a client.
// Returns the session key if authentication succeeds.
func VerifyServiceAuth(
	guardianNonce []byte,
	serviceID string,
	clientNonce []byte,
	receivedHMAC []byte,
	tokenStore *TokenStore,
) (sessionKey []byte, err error) {
	st, err := tokenStore.Lookup(serviceID)
	if err != nil {
		return nil, fmt.Errorf("lookup service: %w", err)
	}

	// Compute expected HMAC: HMAC-SHA256(guardian_nonce || client_nonce, token)
	message := append(guardianNonce, clientNonce...)
	if !crypto.VerifyHMAC(message, st.Token, receivedHMAC) {
		return nil, fmt.Errorf("HMAC verification failed for service %q", serviceID)
	}

	// Derive session key
	sessionKey = crypto.DeriveSessionKey(guardianNonce, clientNonce, st.Token)

	tokenStore.UpdateLastSeen(serviceID)

	return sessionKey, nil
}

// VerifyGuardianHello verifies the GUARDIAN_HELLO on the client side.
func VerifyGuardianHello(guardianNonce, signature []byte, daemonPub ed25519.PublicKey) error {
	if !crypto.Verify(daemonPub, guardianNonce, signature) {
		return fmt.Errorf("invalid guardian signature — possible fake guardian")
	}
	return nil
}

// ComputeClientHMAC computes the HMAC for the SERVICE_AUTH message.
func ComputeClientHMAC(guardianNonce, clientNonce, token []byte) []byte {
	message := append(guardianNonce, clientNonce...)
	return crypto.HMACSHA256(message, token)
}

// CreateSession registers a new session in the manager.
func (sm *SessionManager) CreateSession(serviceID string, sessionKey []byte) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	idBytes, _ := crypto.GenerateNonce(16)
	sessionID := fmt.Sprintf("sess_%x", idBytes)

	sess := &Session{
		ID:         sessionID,
		ServiceID:  serviceID,
		SessionKey: sessionKey,
		CreatedAt:  time.Now().UTC(),
		LastPing:   time.Now().UTC(),
	}
	sm.sessions[sessionID] = sess
	return sess
}

// GetSession retrieves a session by ID.
func (sm *SessionManager) GetSession(sessionID string) (*Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sess, ok := sm.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session %q not found", sessionID)
	}
	return sess, nil
}

// UpdatePing updates the last ping time for a session.
func (sm *SessionManager) UpdatePing(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sess, ok := sm.sessions[sessionID]; ok {
		sess.LastPing = time.Now().UTC()
	}
}

// RemoveSession removes a session.
func (sm *SessionManager) RemoveSession(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, sessionID)
}

// ActiveSessions returns all active sessions.
func (sm *SessionManager) ActiveSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// CleanExpired removes sessions that have exceeded the timeout.
func (sm *SessionManager) CleanExpired() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now().UTC()
	removed := 0
	for id, sess := range sm.sessions {
		if now.Sub(sess.LastPing) > sm.timeout {
			delete(sm.sessions, id)
			removed++
		}
	}
	return removed
}

// Count returns the number of active sessions.
func (sm *SessionManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}
