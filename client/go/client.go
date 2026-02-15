// Package guardian provides a client SDK for connecting to the Guardian daemon
// and checking licenses over a Unix domain socket.
package guardian

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ponder2000/guardian/internal/auth"
	"github.com/ponder2000/guardian/internal/crypto"
	"github.com/ponder2000/guardian/internal/protocol"
)

const (
	defaultSocketPath = "/var/run/guardian/guardian.sock"
	defaultTokenPath  = "/etc/guardian/token"
	clientNonceSize   = 32
)

// Client connects to a Guardian daemon over a Unix domain socket and provides
// methods to check licenses and send heartbeats.
type Client struct {
	socketPath string
	tokenPath  string
	conn       net.Conn
	sessionKey []byte
	serviceID  string
	mu         sync.Mutex
}

// Option configures a Client.
type Option func(*Client)

// LicenseInfo holds the result of a license check for a specific module.
type LicenseInfo struct {
	Valid     bool
	Module    string
	ExpiresAt string
	Features  []string
	Limits    map[string]interface{}
}

// HeartbeatInfo holds the result of a heartbeat exchange.
type HeartbeatInfo struct {
	HWStatus      string
	LicenseStatus string
	ExpiresInDays int
}

// NewClient creates a new Guardian client with the given options.
// Default socket path is /var/run/guardian/guardian.sock (overridden by
// GUARDIAN_SOCKET env var). Default token path is /etc/guardian/token
// (overridden by GUARDIAN_TOKEN_PATH env var).
func NewClient(opts ...Option) *Client {
	c := &Client{
		socketPath: defaultSocketPath,
		tokenPath:  defaultTokenPath,
	}

	// Environment variables override built-in defaults
	if envSocket := os.Getenv("GUARDIAN_SOCKET"); envSocket != "" {
		c.socketPath = envSocket
	}
	if envToken := os.Getenv("GUARDIAN_TOKEN_PATH"); envToken != "" {
		c.tokenPath = envToken
	}

	// Functional options override everything
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// WithSocket returns an Option that sets the Unix domain socket path.
func WithSocket(path string) Option {
	return func(c *Client) {
		c.socketPath = path
	}
}

// WithTokenFile returns an Option that sets the token file path.
func WithTokenFile(path string) Option {
	return func(c *Client) {
		c.tokenPath = path
	}
}

// Connect establishes a connection to the Guardian daemon and performs the
// mutual authentication handshake. After a successful call the client is
// ready for encrypted communication (CheckLicense, Heartbeat).
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Step 1: Parse the token file to get service credentials.
	creds, err := auth.ParseTokenFile(c.tokenPath)
	if err != nil {
		return fmt.Errorf("guardian: parse token file: %w", err)
	}
	c.serviceID = creds.ServiceID

	// Decode the daemon public key from hex.
	daemonPubBytes, err := hex.DecodeString(creds.DaemonPub)
	if err != nil {
		return fmt.Errorf("guardian: decode daemon public key: %w", err)
	}
	if len(daemonPubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("guardian: invalid daemon public key size: got %d, want %d",
			len(daemonPubBytes), ed25519.PublicKeySize)
	}
	daemonPub := ed25519.PublicKey(daemonPubBytes)

	// Step 2: Dial the Unix domain socket.
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("guardian: connect to %s: %w", c.socketPath, err)
	}

	// Step 3: Read GUARDIAN_HELLO and verify the daemon's signature.
	msgType, data, err := protocol.ReadMessage(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("guardian: read hello: %w", err)
	}
	if msgType != protocol.MsgGuardianHello {
		conn.Close()
		return fmt.Errorf("guardian: expected GUARDIAN_HELLO (0x%02x), got 0x%02x",
			protocol.MsgGuardianHello, msgType)
	}

	var hello protocol.GuardianHello
	if err := protocol.Decode(data, &hello); err != nil {
		conn.Close()
		return fmt.Errorf("guardian: decode hello: %w", err)
	}

	if err := auth.VerifyGuardianHello(hello.GuardianNonce, hello.Signature, daemonPub); err != nil {
		conn.Close()
		return fmt.Errorf("guardian: verify hello: %w", err)
	}

	// Step 4: Generate client nonce, compute HMAC, send SERVICE_AUTH.
	clientNonce, err := crypto.GenerateNonce(clientNonceSize)
	if err != nil {
		conn.Close()
		return fmt.Errorf("guardian: generate nonce: %w", err)
	}

	hmacValue := auth.ComputeClientHMAC(hello.GuardianNonce, clientNonce, creds.Token)

	svcAuth := protocol.ServiceAuth{
		ServiceID:   creds.ServiceID,
		ClientNonce: clientNonce,
		HMAC:        hmacValue,
	}
	if err := protocol.WriteMessage(conn, protocol.MsgServiceAuth, &svcAuth); err != nil {
		conn.Close()
		return fmt.Errorf("guardian: write service auth: %w", err)
	}

	// Step 5: Read AUTH_RESULT and verify status.
	msgType, data, err = protocol.ReadMessage(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("guardian: read auth result: %w", err)
	}
	if msgType != protocol.MsgAuthResult {
		conn.Close()
		return fmt.Errorf("guardian: expected AUTH_RESULT (0x%02x), got 0x%02x",
			protocol.MsgAuthResult, msgType)
	}

	var result protocol.AuthResult
	if err := protocol.Decode(data, &result); err != nil {
		conn.Close()
		return fmt.Errorf("guardian: decode auth result: %w", err)
	}
	if result.Status != "ok" {
		conn.Close()
		return fmt.Errorf("guardian: authentication failed: %s", result.Error)
	}

	// Step 6: Derive the session key.
	sessionKey := crypto.DeriveSessionKey(hello.GuardianNonce, clientNonce, creds.Token)

	// Step 7: Store connection state.
	c.conn = conn
	c.sessionKey = sessionKey

	return nil
}

// Close shuts down the connection to the Guardian daemon.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}

	err := c.conn.Close()
	c.conn = nil
	c.sessionKey = nil
	return err
}

// IsConnected returns true if the client has an active authenticated connection.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil && c.sessionKey != nil
}

// CheckLicense queries the Guardian daemon for the license status of the given
// module. The communication is encrypted with the session key established
// during Connect.
func (c *Client) CheckLicense(module string) (*LicenseInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil || c.sessionKey == nil {
		return nil, fmt.Errorf("guardian: not connected")
	}

	// Send encrypted LicenseRequest.
	req := protocol.LicenseRequest{Module: module}
	if err := protocol.WriteEncryptedMessage(c.conn, protocol.MsgLicenseRequest, &req, c.sessionKey); err != nil {
		return nil, fmt.Errorf("guardian: write license request: %w", err)
	}

	// Read encrypted LicenseResponse.
	msgType, data, err := protocol.ReadEncryptedMessage(c.conn, c.sessionKey)
	if err != nil {
		return nil, fmt.Errorf("guardian: read license response: %w", err)
	}
	if msgType != protocol.MsgLicenseResponse {
		return nil, fmt.Errorf("guardian: expected LICENSE_RESPONSE (0x%02x), got 0x%02x",
			protocol.MsgLicenseResponse, msgType)
	}

	var resp protocol.LicenseResponse
	if err := protocol.Decode(data, &resp); err != nil {
		return nil, fmt.Errorf("guardian: decode license response: %w", err)
	}

	return &LicenseInfo{
		Valid:     resp.Valid,
		Module:    resp.Module,
		ExpiresAt: resp.ExpiresAt,
		Features:  resp.Features,
		Limits:    resp.Limits,
	}, nil
}

// Heartbeat sends a keepalive ping to the Guardian daemon and returns the
// current hardware and license status. The communication is encrypted with
// the session key established during Connect.
func (c *Client) Heartbeat() (*HeartbeatInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil || c.sessionKey == nil {
		return nil, fmt.Errorf("guardian: not connected")
	}

	// Send encrypted HeartbeatPing.
	ping := protocol.HeartbeatPing{Timestamp: time.Now().Unix()}
	if err := protocol.WriteEncryptedMessage(c.conn, protocol.MsgHeartbeatPing, &ping, c.sessionKey); err != nil {
		return nil, fmt.Errorf("guardian: write heartbeat: %w", err)
	}

	// Read encrypted HeartbeatPong.
	msgType, data, err := protocol.ReadEncryptedMessage(c.conn, c.sessionKey)
	if err != nil {
		return nil, fmt.Errorf("guardian: read heartbeat response: %w", err)
	}
	if msgType != protocol.MsgHeartbeatPong {
		return nil, fmt.Errorf("guardian: expected HEARTBEAT_PONG (0x%02x), got 0x%02x",
			protocol.MsgHeartbeatPong, msgType)
	}

	var pong protocol.HeartbeatPong
	if err := protocol.Decode(data, &pong); err != nil {
		return nil, fmt.Errorf("guardian: decode heartbeat response: %w", err)
	}

	return &HeartbeatInfo{
		HWStatus:      pong.HWStatus,
		LicenseStatus: pong.LicenseStatus,
		ExpiresInDays: pong.ExpiresInDays,
	}, nil
}
