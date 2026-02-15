package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testConfig = `# Guardian Configuration
[daemon]
socket_path = /tmp/test-guardian.sock
log_path = /tmp/test-guardian.log
log_level = debug
pid_file = /tmp/test-guardian.pid

[license]
license_file = /tmp/test.license
master_pub = /tmp/test-master.pub

[crypto]
daemon_key = /tmp/test-daemon.key
daemon_pub = /tmp/test-daemon.pub
token_db = /tmp/test-tokens.db

[watchdog]
hardware_check_interval = 10m
license_check_interval = 2m
session_timeout = 1h

[security]
max_connections = 100
max_auth_attempts = 5
auth_timeout = 30s
nonce_size = 64
`

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardian.conf")
	if err := os.WriteFile(path, []byte(testConfig), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error: %v", err)
	}

	// Daemon
	if cfg.Daemon.SocketPath != "/tmp/test-guardian.sock" {
		t.Errorf("SocketPath = %q", cfg.Daemon.SocketPath)
	}
	if cfg.Daemon.LogPath != "/tmp/test-guardian.log" {
		t.Errorf("LogPath = %q", cfg.Daemon.LogPath)
	}
	if cfg.Daemon.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.Daemon.LogLevel)
	}
	if cfg.Daemon.PIDFile != "/tmp/test-guardian.pid" {
		t.Errorf("PIDFile = %q", cfg.Daemon.PIDFile)
	}

	// License
	if cfg.License.LicenseFile != "/tmp/test.license" {
		t.Errorf("LicenseFile = %q", cfg.License.LicenseFile)
	}
	if cfg.License.MasterPub != "/tmp/test-master.pub" {
		t.Errorf("MasterPub = %q", cfg.License.MasterPub)
	}

	// Crypto
	if cfg.Crypto.DaemonKey != "/tmp/test-daemon.key" {
		t.Errorf("DaemonKey = %q", cfg.Crypto.DaemonKey)
	}
	if cfg.Crypto.TokenDB != "/tmp/test-tokens.db" {
		t.Errorf("TokenDB = %q", cfg.Crypto.TokenDB)
	}

	// Watchdog
	if cfg.Watchdog.HardwareCheckInterval != 10*time.Minute {
		t.Errorf("HardwareCheckInterval = %v", cfg.Watchdog.HardwareCheckInterval)
	}
	if cfg.Watchdog.LicenseCheckInterval != 2*time.Minute {
		t.Errorf("LicenseCheckInterval = %v", cfg.Watchdog.LicenseCheckInterval)
	}
	if cfg.Watchdog.SessionTimeout != 1*time.Hour {
		t.Errorf("SessionTimeout = %v", cfg.Watchdog.SessionTimeout)
	}

	// Security
	if cfg.Security.MaxConnections != 100 {
		t.Errorf("MaxConnections = %d", cfg.Security.MaxConnections)
	}
	if cfg.Security.MaxAuthAttempts != 5 {
		t.Errorf("MaxAuthAttempts = %d", cfg.Security.MaxAuthAttempts)
	}
	if cfg.Security.AuthTimeout != 30*time.Second {
		t.Errorf("AuthTimeout = %v", cfg.Security.AuthTimeout)
	}
	if cfg.Security.NonceSize != 64 {
		t.Errorf("NonceSize = %d", cfg.Security.NonceSize)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Daemon.SocketPath != "/var/run/guardian/guardian.sock" {
		t.Errorf("default SocketPath = %q", cfg.Daemon.SocketPath)
	}
	if cfg.Security.MaxConnections != 50 {
		t.Errorf("default MaxConnections = %d", cfg.Security.MaxConnections)
	}
	if cfg.Watchdog.HardwareCheckInterval != 5*time.Minute {
		t.Errorf("default HardwareCheckInterval = %v", cfg.Watchdog.HardwareCheckInterval)
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := LoadFile("/nonexistent/guardian.conf")
	if err == nil {
		t.Error("LoadFile() expected error for nonexistent file")
	}
}

func TestLoadFileEmptyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.conf")
	os.WriteFile(path, []byte(""), 0644)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error: %v", err)
	}

	// Should have defaults
	if cfg.Daemon.SocketPath != "/var/run/guardian/guardian.sock" {
		t.Errorf("empty config should preserve defaults, got SocketPath = %q", cfg.Daemon.SocketPath)
	}
}

func TestLoadFileWithComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "comments.conf")
	content := `# Full line comment
; Another comment style

[daemon]
# inline section comment
socket_path = /tmp/test.sock
`
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error: %v", err)
	}

	if cfg.Daemon.SocketPath != "/tmp/test.sock" {
		t.Errorf("SocketPath = %q, want /tmp/test.sock", cfg.Daemon.SocketPath)
	}
}
