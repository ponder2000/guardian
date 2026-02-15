package auth

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ponder2000/guardian/internal/crypto"
)

// ServiceToken represents a registered service's credentials.
type ServiceToken struct {
	ServiceID   string    `json:"service_id"`
	Token       []byte    `json:"token"`
	Modules     []string  `json:"modules,omitempty"`
	RegisteredAt time.Time `json:"registered_at"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

// TokenStore manages service tokens.
type TokenStore struct {
	mu       sync.RWMutex
	tokens   map[string]*ServiceToken
	dbPath   string
	tokenDir string
}

// NewTokenStore creates a token store backed by a JSON file.
func NewTokenStore(dbPath, tokenDir string) *TokenStore {
	return &TokenStore{
		tokens:   make(map[string]*ServiceToken),
		dbPath:   dbPath,
		tokenDir: tokenDir,
	}
}

// Load reads the token database from disk.
func (ts *TokenStore) Load() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	data, err := os.ReadFile(ts.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Fresh database
		}
		return fmt.Errorf("read token db: %w", err)
	}

	var tokens map[string]*ServiceToken
	if err := json.Unmarshal(data, &tokens); err != nil {
		return fmt.Errorf("parse token db: %w", err)
	}
	ts.tokens = tokens
	return nil
}

// Save persists the token database to disk.
func (ts *TokenStore) Save() error {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	data, err := json.MarshalIndent(ts.tokens, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token db: %w", err)
	}
	return os.WriteFile(ts.dbPath, data, 0600)
}

// Register creates a new service token and writes the credential file.
func (ts *TokenStore) Register(serviceID string, modules []string, daemonPubHex string) (*ServiceToken, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	tok, err := crypto.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	st := &ServiceToken{
		ServiceID:    serviceID,
		Token:        tok,
		Modules:      modules,
		RegisteredAt: time.Now().UTC(),
	}
	ts.tokens[serviceID] = st

	// Write credential file
	if ts.tokenDir != "" {
		if err := ts.writeTokenFile(serviceID, tok, daemonPubHex); err != nil {
			delete(ts.tokens, serviceID)
			return nil, fmt.Errorf("write token file: %w", err)
		}
	}

	return st, nil
}

// Lookup retrieves a service token by service ID.
func (ts *TokenStore) Lookup(serviceID string) (*ServiceToken, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	st, ok := ts.tokens[serviceID]
	if !ok {
		return nil, fmt.Errorf("service %q not registered", serviceID)
	}
	return st, nil
}

// UpdateLastSeen updates the last seen timestamp for a service.
func (ts *TokenStore) UpdateLastSeen(serviceID string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if st, ok := ts.tokens[serviceID]; ok {
		st.LastSeen = time.Now().UTC()
	}
}

// Revoke removes a service and deletes its token file.
func (ts *TokenStore) Revoke(serviceID string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if _, ok := ts.tokens[serviceID]; !ok {
		return fmt.Errorf("service %q not registered", serviceID)
	}

	delete(ts.tokens, serviceID)

	if ts.tokenDir != "" {
		tokenPath := filepath.Join(ts.tokenDir, serviceID+".token")
		os.Remove(tokenPath)
	}

	return nil
}

// Rotate generates a new token for a service.
func (ts *TokenStore) Rotate(serviceID, daemonPubHex string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	st, ok := ts.tokens[serviceID]
	if !ok {
		return fmt.Errorf("service %q not registered", serviceID)
	}

	tok, err := crypto.GenerateToken()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	st.Token = tok

	if ts.tokenDir != "" {
		if err := ts.writeTokenFile(serviceID, tok, daemonPubHex); err != nil {
			return fmt.Errorf("write token file: %w", err)
		}
	}

	return nil
}

// ListServices returns all registered services.
func (ts *TokenStore) ListServices() []*ServiceToken {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	services := make([]*ServiceToken, 0, len(ts.tokens))
	for _, st := range ts.tokens {
		services = append(services, st)
	}
	return services
}

// writeTokenFile writes an INI-style token file for a service.
func (ts *TokenStore) writeTokenFile(serviceID string, token []byte, daemonPubHex string) error {
	tokenPath := filepath.Join(ts.tokenDir, serviceID+".token")
	content := fmt.Sprintf(`# Guardian credential file for: %s
# Generated: %s
# DO NOT EDIT — regenerate with: guardian-cli rotate --service=%s

SERVICE_ID=%s
TOKEN=tok_%s
DAEMON_PUB=dpub_%s
`,
		serviceID,
		time.Now().UTC().Format(time.RFC3339),
		serviceID,
		serviceID,
		hex.EncodeToString(token),
		daemonPubHex,
	)
	return os.WriteFile(tokenPath, []byte(content), 0600)
}

// TokenFileCredentials holds parsed token file data.
type TokenFileCredentials struct {
	ServiceID string
	Token     []byte
	DaemonPub string
}

// ParseTokenFile reads a service token file.
func ParseTokenFile(path string) (*TokenFileCredentials, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open token file: %w", err)
	}
	defer f.Close()

	creds := &TokenFileCredentials{}
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "SERVICE_ID":
			creds.ServiceID = value
		case "TOKEN":
			tokenHex := strings.TrimPrefix(value, "tok_")
			tok, err := hex.DecodeString(tokenHex)
			if err != nil {
				return nil, fmt.Errorf("decode token: %w", err)
			}
			creds.Token = tok
		case "DAEMON_PUB":
			creds.DaemonPub = strings.TrimPrefix(value, "dpub_")
		}
	}

	if creds.ServiceID == "" {
		return nil, fmt.Errorf("missing SERVICE_ID in token file")
	}
	if creds.Token == nil {
		return nil, fmt.Errorf("missing TOKEN in token file")
	}

	return creds, scanner.Err()
}
