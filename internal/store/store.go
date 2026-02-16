package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database connection.
type Store struct {
	DB *sql.DB
}

// Open opens or creates a SQLite database at the given path.
func Open(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Enable WAL mode and foreign keys.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("exec %q: %w", p, err)
		}
	}

	return &Store{DB: db}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.DB.Close()
}

// Migrate creates all required tables if they don't already exist.
func (s *Store) Migrate() error {
	_, err := s.DB.Exec(schema)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'viewer')),
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address  TEXT,
    user_agent  TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    contact     TEXT    NOT NULL DEFAULT '',
    notes       TEXT    NOT NULL DEFAULT '',
    is_active   INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hardware_configs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    label         TEXT    NOT NULL,
    machine_id    TEXT    NOT NULL DEFAULT '',
    cpu           TEXT    NOT NULL DEFAULT '',
    motherboard   TEXT    NOT NULL DEFAULT '',
    disk_serial   TEXT    NOT NULL DEFAULT '',
    nic_mac       TEXT    NOT NULL DEFAULT '',
    notes         TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(project_id, label)
);
CREATE INDEX IF NOT EXISTS idx_hw_project ON hardware_configs(project_id);

CREATE TABLE IF NOT EXISTS key_pairs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    public_key_hex  TEXT    NOT NULL,
    private_key_hex TEXT    NOT NULL,
    fingerprint     TEXT    NOT NULL,
    is_default      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS licenses (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id         TEXT    NOT NULL UNIQUE,
    project_id         INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hardware_config_id INTEGER NOT NULL REFERENCES hardware_configs(id) ON DELETE CASCADE,
    key_pair_id        INTEGER NOT NULL REFERENCES key_pairs(id),
    issued_to          TEXT    NOT NULL,
    issued_at          TEXT    NOT NULL,
    expires_at         TEXT    NOT NULL,
    match_threshold    INTEGER NOT NULL DEFAULT 3,
    modules_json       TEXT    NOT NULL DEFAULT '{}',
    global_limits_json TEXT    NOT NULL DEFAULT '{}',
    license_file_data  TEXT    NOT NULL,
    salt               TEXT    NOT NULL,
    version            INTEGER NOT NULL DEFAULT 1,
    notes              TEXT    NOT NULL DEFAULT '',
    created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at         TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_lic_project ON licenses(project_id);
CREATE INDEX IF NOT EXISTS idx_lic_hardware ON licenses(hardware_config_id);

CREATE TABLE IF NOT EXISTS user_project_access (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    granted_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, project_id)
);
CREATE INDEX IF NOT EXISTS idx_upa_user ON user_project_access(user_id);
CREATE INDEX IF NOT EXISTS idx_upa_project ON user_project_access(project_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username    TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    entity_type TEXT    NOT NULL DEFAULT '',
    entity_id   INTEGER,
    details     TEXT    NOT NULL DEFAULT '',
    ip_address  TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at);
`
