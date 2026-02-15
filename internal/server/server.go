package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ponder2000/guardian/internal/auth"
	"github.com/ponder2000/guardian/internal/crypto"
	"github.com/ponder2000/guardian/internal/license"
	"github.com/ponder2000/guardian/internal/protocol"
)

// Server is the Guardian Unix domain socket server.
type Server struct {
	socketPath     string
	listener       net.Listener
	daemonKP       *crypto.KeyPair
	tokenStore     *auth.TokenStore
	sessionMgr     *auth.SessionManager
	license        *license.SignedLicense
	logger         *log.Logger
	maxConns       int
	maxAuthAttempts int
	authTimeout    time.Duration
	nonceSize      int
	mu             sync.Mutex
	connections    map[net.Conn]*connState
	ctx            context.Context
	cancel         context.CancelFunc
}

type connState struct {
	session   *auth.Session
	authed    bool
	authTries int
}

// Config holds server configuration.
type Config struct {
	SocketPath      string
	DaemonKeyPair   *crypto.KeyPair
	TokenStore      *auth.TokenStore
	License         *license.SignedLicense
	Logger          *log.Logger
	MaxConnections  int
	MaxAuthAttempts int
	AuthTimeout     time.Duration
	NonceSize       int
	SessionTimeout  time.Duration
}

// New creates a new server.
func New(cfg Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		socketPath:      cfg.SocketPath,
		daemonKP:        cfg.DaemonKeyPair,
		tokenStore:      cfg.TokenStore,
		sessionMgr:      auth.NewSessionManager(cfg.SessionTimeout),
		license:         cfg.License,
		logger:          cfg.Logger,
		maxConns:        cfg.MaxConnections,
		maxAuthAttempts: cfg.MaxAuthAttempts,
		authTimeout:     cfg.AuthTimeout,
		nonceSize:       cfg.NonceSize,
		connections:     make(map[net.Conn]*connState),
		ctx:             ctx,
		cancel:          cancel,
	}
}

// Start begins listening on the Unix domain socket.
func (s *Server) Start() error {
	// Remove stale socket file
	os.Remove(s.socketPath)

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.socketPath, err)
	}
	s.listener = listener

	// Set socket permissions to 0666 (anyone can connect)
	if err := os.Chmod(s.socketPath, 0666); err != nil {
		listener.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	s.logger.Printf("server: listening on %s", s.socketPath)

	go s.acceptLoop()
	return nil
}

// Stop shuts down the server and disconnects all clients.
func (s *Server) Stop() {
	s.cancel()
	if s.listener != nil {
		s.listener.Close()
	}

	s.mu.Lock()
	for conn := range s.connections {
		conn.Close()
	}
	s.connections = make(map[net.Conn]*connState)
	s.mu.Unlock()

	s.logger.Println("server: stopped")
}

// ActiveConnections returns the number of active connections.
func (s *Server) ActiveConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.connections)
}

// SessionManager returns the session manager.
func (s *Server) SessionManager() *auth.SessionManager {
	return s.sessionMgr
}

// BroadcastRevoke sends a REVOKE_NOTICE to all authenticated connections.
func (s *Server) BroadcastRevoke(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	notice := protocol.RevokeNotice{
		Reason:    reason,
		Timestamp: time.Now().Unix(),
	}

	for conn, state := range s.connections {
		if state.authed && state.session != nil {
			err := protocol.WriteEncryptedMessage(conn, protocol.MsgRevokeNotice, &notice, state.session.SessionKey)
			if err != nil {
				s.logger.Printf("server: failed to send revoke to %s: %v", state.session.ServiceID, err)
			}
		}
	}
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				s.logger.Printf("server: accept error: %v", err)
				continue
			}
		}

		s.mu.Lock()
		if len(s.connections) >= s.maxConns {
			s.mu.Unlock()
			s.logger.Println("server: max connections reached, rejecting")
			protocol.WriteMessage(conn, protocol.MsgError, &protocol.ErrorMsg{
				Code:    503,
				Message: "max connections reached",
			})
			conn.Close()
			continue
		}
		s.connections[conn] = &connState{}
		s.mu.Unlock()

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		state := s.connections[conn]
		if state != nil && state.session != nil {
			s.sessionMgr.RemoveSession(state.session.ID)
		}
		delete(s.connections, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	// Set auth timeout
	conn.SetDeadline(time.Now().Add(s.authTimeout))

	// Step 1: Send GUARDIAN_HELLO
	hsState, err := auth.InitHandshake(s.daemonKP, s.nonceSize)
	if err != nil {
		s.logger.Printf("server: handshake init error: %v", err)
		return
	}

	hello := protocol.GuardianHello{
		GuardianNonce: hsState.GuardianNonce,
		Signature:     hsState.Signature,
	}
	if err := protocol.WriteMessage(conn, protocol.MsgGuardianHello, &hello); err != nil {
		s.logger.Printf("server: write hello error: %v", err)
		return
	}

	// Step 2: Read SERVICE_AUTH
	msgType, data, err := protocol.ReadMessage(conn)
	if err != nil {
		s.logger.Printf("server: read auth error: %v", err)
		return
	}
	if msgType != protocol.MsgServiceAuth {
		s.logger.Printf("server: expected SERVICE_AUTH, got 0x%02x", msgType)
		return
	}

	var svcAuth protocol.ServiceAuth
	if err := protocol.Decode(data, &svcAuth); err != nil {
		s.logger.Printf("server: decode auth error: %v", err)
		return
	}

	// Step 3: Verify and derive session key
	sessionKey, err := auth.VerifyServiceAuth(
		hsState.GuardianNonce,
		svcAuth.ServiceID,
		svcAuth.ClientNonce,
		svcAuth.HMAC,
		s.tokenStore,
	)
	if err != nil {
		s.logger.Printf("server: auth failed for %s: %v", svcAuth.ServiceID, err)
		protocol.WriteMessage(conn, protocol.MsgAuthResult, &protocol.AuthResult{
			Status: "error",
			Error:  "authentication failed",
		})
		return
	}

	// Step 4: Create session and send AUTH_RESULT
	session := s.sessionMgr.CreateSession(svcAuth.ServiceID, sessionKey)

	s.mu.Lock()
	if state, ok := s.connections[conn]; ok {
		state.session = session
		state.authed = true
	}
	s.mu.Unlock()

	authResult := protocol.AuthResult{
		Status:    "ok",
		SessionID: session.ID,
	}
	if err := protocol.WriteMessage(conn, protocol.MsgAuthResult, &authResult); err != nil {
		s.logger.Printf("server: write auth result error: %v", err)
		return
	}

	s.logger.Printf("server: authenticated service %s (session: %s)", svcAuth.ServiceID, session.ID)

	// Clear deadline for authenticated channel
	conn.SetDeadline(time.Time{})

	// Step 5: Handle encrypted messages
	s.handleAuthenticatedConn(conn, session)
}

func (s *Server) handleAuthenticatedConn(conn net.Conn, session *auth.Session) {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Set read deadline for heartbeat timeout
		conn.SetReadDeadline(time.Now().Add(10 * time.Minute))

		msgType, data, err := protocol.ReadEncryptedMessage(conn, session.SessionKey)
		if err != nil {
			s.logger.Printf("server: read error for %s: %v", session.ServiceID, err)
			return
		}

		switch msgType {
		case protocol.MsgLicenseRequest:
			s.handleLicenseRequest(conn, session, data)
		case protocol.MsgHeartbeatPing:
			s.handleHeartbeat(conn, session, data)
		default:
			s.logger.Printf("server: unexpected message type 0x%02x from %s", msgType, session.ServiceID)
		}
	}
}

func (s *Server) handleLicenseRequest(conn net.Conn, session *auth.Session, data []byte) {
	var req protocol.LicenseRequest
	if err := protocol.Decode(data, &req); err != nil {
		s.logger.Printf("server: decode license request error: %v", err)
		return
	}

	resp := protocol.LicenseResponse{
		Module: req.Module,
	}

	mod, err := s.license.GetModule(req.Module)
	if err != nil {
		resp.Valid = false
		resp.Error = err.Error()
	} else {
		resp.Valid = true
		resp.ExpiresAt = s.license.License.ExpiresAt.Format("2006-01-02T15:04:05Z")
		resp.Features = mod.Features
		resp.Limits = mod.Limits
	}

	if err := protocol.WriteEncryptedMessage(conn, protocol.MsgLicenseResponse, &resp, session.SessionKey); err != nil {
		s.logger.Printf("server: write license response error: %v", err)
	}
}

func (s *Server) handleHeartbeat(conn net.Conn, session *auth.Session, data []byte) {
	s.sessionMgr.UpdatePing(session.ID)

	pong := protocol.HeartbeatPong{
		Timestamp:     time.Now().Unix(),
		HWStatus:      "ok",
		LicenseStatus: "ok",
		ExpiresInDays: s.license.DaysUntilExpiry(),
	}

	if err := s.license.CheckExpiry(); err != nil {
		pong.LicenseStatus = "expired"
	}

	if err := protocol.WriteEncryptedMessage(conn, protocol.MsgHeartbeatPong, &pong, session.SessionKey); err != nil {
		s.logger.Printf("server: write heartbeat pong error: %v", err)
	}
}
