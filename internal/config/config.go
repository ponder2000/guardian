package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config represents the guardian daemon configuration.
type Config struct {
	Daemon   DaemonConfig
	License  LicenseConfig
	Crypto   CryptoConfig
	Watchdog WatchdogConfig
	Security SecurityConfig
}

type DaemonConfig struct {
	SocketPath string
	LogPath    string
	LogLevel   string
	PIDFile    string
}

type LicenseConfig struct {
	LicenseFile string
	MasterPub   string
}

type CryptoConfig struct {
	DaemonKey string
	DaemonPub string
	TokenDB   string
}

type WatchdogConfig struct {
	HardwareCheckInterval time.Duration
	LicenseCheckInterval  time.Duration
	SessionTimeout        time.Duration
}

type SecurityConfig struct {
	MaxConnections  int
	MaxAuthAttempts int
	AuthTimeout     time.Duration
	NonceSize       int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Daemon: DaemonConfig{
			SocketPath: "/var/run/guardian/guardian.sock",
			LogPath:    "/var/log/guardian/guardian.log",
			LogLevel:   "info",
			PIDFile:    "/var/run/guardian/guardian.pid",
		},
		License: LicenseConfig{
			LicenseFile: "/etc/guardian/guardian.license",
			MasterPub:   "/etc/guardian/master.pub",
		},
		Crypto: CryptoConfig{
			DaemonKey: "/etc/guardian/daemon.key",
			DaemonPub: "/etc/guardian/daemon.pub",
			TokenDB:   "/etc/guardian/tokens.db",
		},
		Watchdog: WatchdogConfig{
			HardwareCheckInterval: 5 * time.Minute,
			LicenseCheckInterval:  1 * time.Minute,
			SessionTimeout:        30 * time.Minute,
		},
		Security: SecurityConfig{
			MaxConnections:  50,
			MaxAuthAttempts: 3,
			AuthTimeout:     10 * time.Second,
			NonceSize:       32,
		},
	}
}

// LoadFile loads a guardian.conf INI-style config file.
func LoadFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	cfg := DefaultConfig()
	section := ""
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch section {
		case "daemon":
			parseDaemon(&cfg.Daemon, key, value)
		case "license":
			parseLicense(&cfg.License, key, value)
		case "crypto":
			parseCrypto(&cfg.Crypto, key, value)
		case "watchdog":
			parseWatchdog(&cfg.Watchdog, key, value)
		case "security":
			parseSecurity(&cfg.Security, key, value)
		}
	}

	return cfg, scanner.Err()
}

func parseDaemon(d *DaemonConfig, key, value string) {
	switch key {
	case "socket_path":
		d.SocketPath = value
	case "log_path":
		d.LogPath = value
	case "log_level":
		d.LogLevel = value
	case "pid_file":
		d.PIDFile = value
	}
}

func parseLicense(l *LicenseConfig, key, value string) {
	switch key {
	case "license_file":
		l.LicenseFile = value
	case "master_pub":
		l.MasterPub = value
	}
}

func parseCrypto(c *CryptoConfig, key, value string) {
	switch key {
	case "daemon_key":
		c.DaemonKey = value
	case "daemon_pub":
		c.DaemonPub = value
	case "token_db":
		c.TokenDB = value
	}
}

func parseWatchdog(w *WatchdogConfig, key, value string) {
	switch key {
	case "hardware_check_interval":
		if d, err := time.ParseDuration(value); err == nil {
			w.HardwareCheckInterval = d
		}
	case "license_check_interval":
		if d, err := time.ParseDuration(value); err == nil {
			w.LicenseCheckInterval = d
		}
	case "session_timeout":
		if d, err := time.ParseDuration(value); err == nil {
			w.SessionTimeout = d
		}
	}
}

func parseSecurity(s *SecurityConfig, key, value string) {
	switch key {
	case "max_connections":
		fmt.Sscanf(value, "%d", &s.MaxConnections)
	case "max_auth_attempts":
		fmt.Sscanf(value, "%d", &s.MaxAuthAttempts)
	case "auth_timeout":
		if d, err := time.ParseDuration(value); err == nil {
			s.AuthTimeout = d
		}
	case "nonce_size":
		fmt.Sscanf(value, "%d", &s.NonceSize)
	}
}
