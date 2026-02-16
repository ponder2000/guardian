package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User represents an admin panel user.
type User struct {
	ID           int
	Username     string
	Email        string
	PasswordHash string
	Role         string // "admin" or "viewer"
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Session represents a web session.
type Session struct {
	ID        string
	UserID    int
	IPAddress string
	UserAgent string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateUser creates a new user with a bcrypt-hashed password.
func (s *Store) CreateUser(username, email, password, role string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	res, err := s.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		username, email, string(hash), role,
	)
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}

	id, _ := res.LastInsertId()
	return s.GetUser(int(id))
}

// GetUser returns a user by ID.
func (s *Store) GetUser(id int) (*User, error) {
	u := &User{}
	var createdAt, updatedAt string
	var isActive int
	err := s.DB.QueryRow(
		`SELECT id, username, email, password_hash, role, is_active, created_at, updated_at FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role, &isActive, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}
	u.IsActive = isActive == 1
	u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	u.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
	return u, nil
}

// GetUserByUsername returns a user by username.
func (s *Store) GetUserByUsername(username string) (*User, error) {
	u := &User{}
	var createdAt, updatedAt string
	var isActive int
	err := s.DB.QueryRow(
		`SELECT id, username, email, password_hash, role, is_active, created_at, updated_at FROM users WHERE username = ?`, username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role, &isActive, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}
	u.IsActive = isActive == 1
	u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	u.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
	return u, nil
}

// VerifyPassword checks a plaintext password against the user's bcrypt hash.
func VerifyPassword(user *User, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	return err == nil
}

// ListUsers returns all users.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.DB.Query(
		`SELECT id, username, email, password_hash, role, is_active, created_at, updated_at FROM users ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var createdAt, updatedAt string
		var isActive int
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role, &isActive, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		u.IsActive = isActive == 1
		u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		u.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
		users = append(users, u)
	}
	return users, rows.Err()
}

// UpdateUser updates a user's profile fields.
func (s *Store) UpdateUser(id int, username, email, role string, isActive bool) error {
	active := 0
	if isActive {
		active = 1
	}
	_, err := s.DB.Exec(
		`UPDATE users SET username=?, email=?, role=?, is_active=?, updated_at=datetime('now') WHERE id=?`,
		username, email, role, active, id,
	)
	return err
}

// UpdateUserPassword changes a user's password.
func (s *Store) UpdateUserPassword(id int, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = s.DB.Exec(`UPDATE users SET password_hash=?, updated_at=datetime('now') WHERE id=?`, string(hash), id)
	return err
}

// DeleteUser removes a user by ID.
func (s *Store) DeleteUser(id int) error {
	_, err := s.DB.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

// UserCount returns the total number of users.
func (s *Store) UserCount() (int, error) {
	var count int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

// --- Sessions ---

// CreateSession creates a new session for the given user.
func (s *Store) CreateSession(userID int, ip, userAgent string, ttl time.Duration) (*Session, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate session token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	expiresAt := time.Now().UTC().Add(ttl)

	_, err := s.DB.Exec(
		`INSERT INTO sessions (id, user_id, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)`,
		token, userID, ip, userAgent, expiresAt.Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		return nil, fmt.Errorf("insert session: %w", err)
	}

	return &Session{
		ID:        token,
		UserID:    userID,
		IPAddress: ip,
		UserAgent: userAgent,
		ExpiresAt: expiresAt,
	}, nil
}

// GetSession returns a valid (non-expired) session and associated user.
func (s *Store) GetSession(token string) (*Session, *User, error) {
	sess := &Session{}
	var createdAt, expiresAt string
	err := s.DB.QueryRow(
		`SELECT id, user_id, ip_address, user_agent, created_at, expires_at FROM sessions WHERE id = ?`, token,
	).Scan(&sess.ID, &sess.UserID, &sess.IPAddress, &sess.UserAgent, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil, fmt.Errorf("session not found")
	}
	if err != nil {
		return nil, nil, err
	}

	sess.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	sess.ExpiresAt, _ = time.Parse("2006-01-02 15:04:05", expiresAt)

	if time.Now().UTC().After(sess.ExpiresAt) {
		s.DB.Exec(`DELETE FROM sessions WHERE id = ?`, token)
		return nil, nil, fmt.Errorf("session expired")
	}

	user, err := s.GetUser(sess.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("load session user: %w", err)
	}

	if !user.IsActive {
		return nil, nil, fmt.Errorf("user account is disabled")
	}

	return sess, user, nil
}

// DeleteSession removes a session.
func (s *Store) DeleteSession(token string) error {
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE id = ?`, token)
	return err
}

// CleanExpiredSessions removes all expired sessions.
func (s *Store) CleanExpiredSessions() (int64, error) {
	res, err := s.DB.Exec(`DELETE FROM sessions WHERE expires_at < datetime('now')`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
