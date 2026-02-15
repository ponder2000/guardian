// Package guardian provides a client SDK for connecting to the Guardian daemon
// and checking licenses over a Unix domain socket.
//
// Two usage modes are supported:
//
// Low-level: call Connect(), CheckLicense(), Heartbeat(), Close() directly.
//
// High-level (recommended): configure callbacks and periodic checking, then
// call Start()/Stop():
//
//	client := guardian.NewClient(
//	    guardian.WithModule("my-module"),
//	    guardian.WithCheckInterval(5 * time.Minute),
//	    guardian.WithValidHandler(func(info *guardian.LicenseInfo) {
//	        log.Println("License valid:", info.Features)
//	    }),
//	    guardian.WithInvalidHandler(func(info *guardian.LicenseInfo, err error) {
//	        log.Fatal("License invalid:", err)
//	    }),
//	)
//	if err := client.Start(); err != nil { log.Fatal(err) }
//	defer client.Stop()
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
	defaultSocketPath    = "/var/run/guardian/guardian.sock"
	defaultTokenPath     = "/etc/guardian/token"
	defaultCheckInterval = 5 * time.Minute
	clientNonceSize      = 32
)

// ValidHandler is called when a periodic or forced license check succeeds.
type ValidHandler func(info *LicenseInfo)

// InvalidHandler is called when a periodic or forced license check fails.
type InvalidHandler func(info *LicenseInfo, err error)

// Client connects to a Guardian daemon over a Unix domain socket and provides
// methods to check licenses and send heartbeats.
type Client struct {
	socketPath     string
	tokenPath      string
	module         string
	checkInterval  time.Duration
	validHandler   ValidHandler
	invalidHandler InvalidHandler
	conn           net.Conn
	sessionKey     []byte
	serviceID      string
	mu             sync.Mutex
	stopCh         chan struct{}
	stopped        chan struct{}
	running        bool
}

// Option configures a Client.
type Option func(*Client)

// LicenseInfo holds the result of a license check for a specific module.
type LicenseInfo struct {
	Valid         bool
	Module        string
	ExpiresAt     string
	Features      []string
	Metadata      map[string]interface{}
	HWStatus      string
	LicenseStatus string
	ExpiresInDays int
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
		socketPath:    defaultSocketPath,
		tokenPath:     defaultTokenPath,
		checkInterval: defaultCheckInterval,
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

// WithModule returns an Option that sets the module name for periodic license
// checks (used by Start and ForceCheck).
func WithModule(module string) Option {
	return func(c *Client) {
		c.module = module
	}
}

// WithCheckInterval returns an Option that sets how often the background
// goroutine checks the license. Default is 5 minutes.
func WithCheckInterval(d time.Duration) Option {
	return func(c *Client) {
		c.checkInterval = d
	}
}

// WithValidHandler returns an Option that registers a callback invoked
// whenever a periodic or forced license check succeeds.
func WithValidHandler(h ValidHandler) Option {
	return func(c *Client) {
		c.validHandler = h
	}
}

// WithInvalidHandler returns an Option that registers a callback invoked
// whenever a periodic or forced license check fails.
func WithInvalidHandler(h InvalidHandler) Option {
	return func(c *Client) {
		c.invalidHandler = h
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
		Metadata:  resp.Metadata,
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

// Start connects to the Guardian daemon, performs the initial license check
// for the configured module (see WithModule), and launches a background
// goroutine that re-checks at the interval set by WithCheckInterval.
//
// On each check the registered ValidHandler or InvalidHandler is called.
// If the connection drops, the goroutine attempts to reconnect automatically.
//
// Start returns an error only if the initial connect or license check fails.
func (c *Client) Start() error {
	if c.module == "" {
		return fmt.Errorf("guardian: module not set (use WithModule)")
	}

	// Initial connect + check.
	if err := c.Connect(); err != nil {
		return err
	}

	info, err := c.doCheck()
	if err != nil {
		c.fireInvalid(nil, err)
		c.Close()
		return err
	}
	if !info.Valid {
		checkErr := fmt.Errorf("guardian: license invalid for module %s", c.module)
		c.fireInvalid(info, checkErr)
		c.Close()
		return checkErr
	}
	c.fireValid(info)

	c.mu.Lock()
	c.stopCh = make(chan struct{})
	c.stopped = make(chan struct{})
	c.running = true
	c.mu.Unlock()

	go c.periodicLoop()
	return nil
}

// Stop halts the periodic checking goroutine and closes the connection.
func (c *Client) Stop() {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return
	}
	c.running = false
	close(c.stopCh)
	c.mu.Unlock()

	<-c.stopped
	c.Close()
}

// ForceCheck performs an immediate license check for the configured module
// and returns the result. It also invokes the registered callbacks.
// If the client is not connected, it attempts to reconnect first.
func (c *Client) ForceCheck() (*LicenseInfo, error) {
	if !c.IsConnected() {
		if err := c.Connect(); err != nil {
			c.fireInvalid(nil, err)
			return nil, err
		}
	}

	info, err := c.doCheck()
	if err != nil {
		c.fireInvalid(nil, err)
		return nil, err
	}
	if !info.Valid {
		checkErr := fmt.Errorf("guardian: license invalid for module %s", c.module)
		c.fireInvalid(info, checkErr)
		return info, checkErr
	}
	c.fireValid(info)
	return info, nil
}

// doCheck performs a license check + heartbeat and merges the results.
func (c *Client) doCheck() (*LicenseInfo, error) {
	licInfo, err := c.CheckLicense(c.module)
	if err != nil {
		return nil, err
	}

	hbInfo, err := c.Heartbeat()
	if err != nil {
		return licInfo, nil // license info is still useful
	}

	// Merge heartbeat fields into license info.
	licInfo.HWStatus = hbInfo.HWStatus
	licInfo.LicenseStatus = hbInfo.LicenseStatus
	licInfo.ExpiresInDays = hbInfo.ExpiresInDays
	return licInfo, nil
}

func (c *Client) periodicLoop() {
	defer close(c.stopped)
	ticker := time.NewTicker(c.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.periodicCheck()
		}
	}
}

func (c *Client) periodicCheck() {
	if !c.IsConnected() {
		if err := c.Connect(); err != nil {
			c.fireInvalid(nil, fmt.Errorf("guardian: reconnect failed: %w", err))
			return
		}
	}

	info, err := c.doCheck()
	if err != nil {
		c.fireInvalid(nil, err)
		c.Close() // force reconnect on next tick
		return
	}
	if !info.Valid {
		c.fireInvalid(info, fmt.Errorf("guardian: license invalid for module %s", c.module))
		return
	}
	c.fireValid(info)
}

func (c *Client) fireValid(info *LicenseInfo) {
	if c.validHandler != nil {
		c.validHandler(info)
	}
}

func (c *Client) fireInvalid(info *LicenseInfo, err error) {
	if c.invalidHandler != nil {
		c.invalidHandler(info, err)
	}
}
