package store

import (
	"database/sql"
	"fmt"
	"time"
)

// KeyPair represents an Ed25519 key pair stored in the database.
type KeyPair struct {
	ID            int
	Name          string
	PublicKeyHex  string
	PrivateKeyHex string
	Fingerprint   string
	IsDefault     bool
	CreatedAt     time.Time
}

// CreateKeyPair stores a new key pair.
func (s *Store) CreateKeyPair(name, pubHex, privHex, fingerprint string) (*KeyPair, error) {
	res, err := s.DB.Exec(
		`INSERT INTO key_pairs (name, public_key_hex, private_key_hex, fingerprint) VALUES (?, ?, ?, ?)`,
		name, pubHex, privHex, fingerprint,
	)
	if err != nil {
		return nil, fmt.Errorf("insert key pair: %w", err)
	}
	id, _ := res.LastInsertId()

	// If this is the first key pair, make it the default.
	var count int
	s.DB.QueryRow(`SELECT COUNT(*) FROM key_pairs`).Scan(&count)
	if count == 1 {
		s.DB.Exec(`UPDATE key_pairs SET is_default = 1 WHERE id = ?`, id)
	}

	return s.GetKeyPair(int(id))
}

// GetKeyPair returns a key pair by ID.
func (s *Store) GetKeyPair(id int) (*KeyPair, error) {
	kp := &KeyPair{}
	var isDefault int
	var createdAt string
	err := s.DB.QueryRow(
		`SELECT id, name, public_key_hex, private_key_hex, fingerprint, is_default, created_at FROM key_pairs WHERE id = ?`, id,
	).Scan(&kp.ID, &kp.Name, &kp.PublicKeyHex, &kp.PrivateKeyHex, &kp.Fingerprint, &isDefault, &createdAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("key pair not found")
	}
	if err != nil {
		return nil, err
	}
	kp.IsDefault = isDefault == 1
	kp.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	return kp, nil
}

// GetDefaultKeyPair returns the default key pair, or nil if none.
func (s *Store) GetDefaultKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	var isDefault int
	var createdAt string
	err := s.DB.QueryRow(
		`SELECT id, name, public_key_hex, private_key_hex, fingerprint, is_default, created_at FROM key_pairs WHERE is_default = 1`,
	).Scan(&kp.ID, &kp.Name, &kp.PublicKeyHex, &kp.PrivateKeyHex, &kp.Fingerprint, &isDefault, &createdAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no default key pair")
	}
	if err != nil {
		return nil, err
	}
	kp.IsDefault = true
	kp.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	return kp, nil
}

// ListKeyPairs returns all key pairs.
func (s *Store) ListKeyPairs() ([]KeyPair, error) {
	rows, err := s.DB.Query(
		`SELECT id, name, public_key_hex, private_key_hex, fingerprint, is_default, created_at FROM key_pairs ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []KeyPair
	for rows.Next() {
		var kp KeyPair
		var isDefault int
		var createdAt string
		if err := rows.Scan(&kp.ID, &kp.Name, &kp.PublicKeyHex, &kp.PrivateKeyHex, &kp.Fingerprint, &isDefault, &createdAt); err != nil {
			return nil, err
		}
		kp.IsDefault = isDefault == 1
		kp.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		keys = append(keys, kp)
	}
	return keys, rows.Err()
}

// SetDefaultKeyPair sets a key pair as the default (unsets all others).
func (s *Store) SetDefaultKeyPair(id int) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tx.Exec(`UPDATE key_pairs SET is_default = 0`)
	_, err = tx.Exec(`UPDATE key_pairs SET is_default = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteKeyPair removes a key pair by ID.
func (s *Store) DeleteKeyPair(id int) error {
	_, err := s.DB.Exec(`DELETE FROM key_pairs WHERE id = ?`, id)
	return err
}
