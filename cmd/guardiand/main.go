package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/ponder2000/guardian/internal/auth"
	"github.com/ponder2000/guardian/internal/config"
	"github.com/ponder2000/guardian/internal/crypto"
	"github.com/ponder2000/guardian/internal/fingerprint"
	"github.com/ponder2000/guardian/internal/license"
	"github.com/ponder2000/guardian/internal/server"
	"github.com/ponder2000/guardian/internal/watchdog"
)

// Set by -ldflags at build time.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
	author    = "unknown"
)

func main() {
	// ── Step 1: Parse --config flag ──────────────────────────────────────
	configPath := flag.String("config", "/etc/guardian/guardian.conf", "path to guardian config file")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("guardiand %s (commit: %s, built: %s, author: %s)\n", version, commit, buildTime, author)
		os.Exit(0)
	}

	// ── Step 2: Load config file ─────────────────────────────────────────
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: load config: %v\n", err)
		os.Exit(1)
	}

	// ── Step 3: Setup logging (to file + stderr) ─────────────────────────
	if err := os.MkdirAll(filepath.Dir(cfg.Daemon.LogPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: create log directory: %v\n", err)
		os.Exit(1)
	}

	logFile, err := os.OpenFile(cfg.Daemon.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: open log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	multiWriter := io.MultiWriter(os.Stderr, logFile)
	logger := log.New(multiWriter, "guardiand: ", log.LstdFlags|log.Lshortfile)

	// Write PID file
	if cfg.Daemon.PIDFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.Daemon.PIDFile), 0755); err != nil {
			logger.Fatalf("create pid directory: %v", err)
		}
		pidData := fmt.Sprintf("%d\n", os.Getpid())
		if err := os.WriteFile(cfg.Daemon.PIDFile, []byte(pidData), 0644); err != nil {
			logger.Fatalf("write pid file: %v", err)
		}
		defer os.Remove(cfg.Daemon.PIDFile)
	}

	// ── Step 4: Load master.pub ──────────────────────────────────────────
	masterPub, err := crypto.LoadPublicKey(cfg.License.MasterPub)
	if err != nil {
		logger.Fatalf("load master public key: %v", err)
	}
	logger.Printf("loaded master public key from %s", cfg.License.MasterPub)

	// ── Step 5: Load and verify license (signature, expiry) ──────────────
	licData, err := os.ReadFile(cfg.License.LicenseFile)
	if err != nil {
		logger.Fatalf("read license file: %v", err)
	}

	signedLic, err := license.ParseFile(licData)
	if err != nil {
		logger.Fatalf("parse license: %v", err)
	}

	if err := signedLic.Verify(masterPub); err != nil {
		logger.Fatalf("license signature verification failed: %v", err)
	}
	logger.Println("license signature verified")

	if err := signedLic.CheckExpiry(); err != nil {
		logger.Fatalf("license expiry check failed: %v", err)
	}
	logger.Printf("license valid, expires at %s (%d days remaining)",
		signedLic.License.ExpiresAt.Format("2006-01-02"), signedLic.DaysUntilExpiry())

	// ── Step 6: Collect hardware fingerprints and validate ────────────────
	// Skip hardware validation on macOS for development.
	if runtime.GOOS != "darwin" {
		hwInfo, err := fingerprint.Collect()
		if err != nil {
			logger.Fatalf("collect hardware fingerprint: %v", err)
		}

		matched, total, err := signedLic.CheckHardware(hwInfo)
		if err != nil {
			logger.Fatalf("hardware validation failed: %v", err)
		}
		logger.Printf("hardware fingerprint validated (%d/%d components matched)", matched, total)
	} else {
		logger.Println("hardware fingerprint check skipped (macOS dev mode)")
	}

	// ── Step 7: Load or generate daemon key pair ─────────────────────────
	var daemonKP *crypto.KeyPair

	if _, err := os.Stat(cfg.Crypto.DaemonKey); os.IsNotExist(err) {
		logger.Println("daemon key not found, generating new key pair")
		daemonKP, err = crypto.GenerateKeyPair()
		if err != nil {
			logger.Fatalf("generate daemon key pair: %v", err)
		}

		if err := os.MkdirAll(filepath.Dir(cfg.Crypto.DaemonKey), 0755); err != nil {
			logger.Fatalf("create key directory: %v", err)
		}

		if err := daemonKP.SavePrivateKey(cfg.Crypto.DaemonKey); err != nil {
			logger.Fatalf("save daemon private key: %v", err)
		}
		if err := daemonKP.SavePublicKey(cfg.Crypto.DaemonPub); err != nil {
			logger.Fatalf("save daemon public key: %v", err)
		}
		logger.Printf("daemon key pair generated and saved to %s", cfg.Crypto.DaemonKey)
	} else {
		privKey, err := crypto.LoadPrivateKey(cfg.Crypto.DaemonKey)
		if err != nil {
			logger.Fatalf("load daemon private key: %v", err)
		}
		pubKey, err := crypto.LoadPublicKey(cfg.Crypto.DaemonPub)
		if err != nil {
			logger.Fatalf("load daemon public key: %v", err)
		}
		daemonKP = &crypto.KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}
		logger.Printf("loaded daemon key pair from %s", cfg.Crypto.DaemonKey)
	}

	// ── Step 8: Load token store ─────────────────────────────────────────
	tokenDir := filepath.Dir(cfg.Crypto.TokenDB)
	tokenStore := auth.NewTokenStore(cfg.Crypto.TokenDB, tokenDir)
	if err := tokenStore.Load(); err != nil {
		logger.Fatalf("load token store: %v", err)
	}
	logger.Printf("token store loaded from %s", cfg.Crypto.TokenDB)

	// ── Step 9: Create and start UDS server ──────────────────────────────
	if err := os.MkdirAll(filepath.Dir(cfg.Daemon.SocketPath), 0755); err != nil {
		logger.Fatalf("create socket directory: %v", err)
	}

	srv := server.New(server.Config{
		SocketPath:      cfg.Daemon.SocketPath,
		DaemonKeyPair:   daemonKP,
		TokenStore:      tokenStore,
		License:         signedLic,
		Logger:          logger,
		MaxConnections:  cfg.Security.MaxConnections,
		MaxAuthAttempts: cfg.Security.MaxAuthAttempts,
		AuthTimeout:     cfg.Security.AuthTimeout,
		NonceSize:       cfg.Security.NonceSize,
		SessionTimeout:  cfg.Watchdog.SessionTimeout,
	})

	if err := srv.Start(); err != nil {
		logger.Fatalf("start server: %v", err)
	}

	// ── Step 10: Setup watchdog checks ───────────────────────────────────
	wd := watchdog.New(logger, func(reason string) {
		logger.Printf("watchdog failure: %s — broadcasting revoke", reason)
		srv.BroadcastRevoke(reason)
	})

	// License expiry re-check
	wd.AddCheck("license-expiry", cfg.Watchdog.LicenseCheckInterval, func() error {
		return signedLic.CheckExpiry()
	})

	// Hardware re-check (only on non-macOS)
	if runtime.GOOS != "darwin" {
		wd.AddCheck("hardware", cfg.Watchdog.HardwareCheckInterval, func() error {
			hwInfo, err := fingerprint.Collect()
			if err != nil {
				return fmt.Errorf("collect hardware: %w", err)
			}
			_, _, err = signedLic.CheckHardware(hwInfo)
			return err
		})
	}

	wd.Start()

	// ── Step 11: Handle OS signals ───────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	// ── Step 12: Log "Guardian daemon started" and block ─────────────────
	logger.Println("Guardian daemon started")

	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGHUP:
			// Reload license file on SIGHUP
			logger.Println("received SIGHUP, reloading license")

			newLicData, err := os.ReadFile(cfg.License.LicenseFile)
			if err != nil {
				logger.Printf("reload license: read file failed: %v", err)
				continue
			}

			newSignedLic, err := license.ParseFile(newLicData)
			if err != nil {
				logger.Printf("reload license: parse failed: %v", err)
				continue
			}

			if err := newSignedLic.Verify(masterPub); err != nil {
				logger.Printf("reload license: signature verification failed: %v", err)
				continue
			}

			if err := newSignedLic.CheckExpiry(); err != nil {
				logger.Printf("reload license: expiry check failed: %v", err)
				continue
			}

			// Swap in the new license
			signedLic = newSignedLic
			logger.Printf("license reloaded successfully, expires at %s (%d days remaining)",
				signedLic.License.ExpiresAt.Format("2006-01-02"), signedLic.DaysUntilExpiry())

		case syscall.SIGTERM, syscall.SIGINT:
			logger.Printf("received %s, shutting down", sig)
			wd.Stop()
			srv.Stop()
			if err := tokenStore.Save(); err != nil {
				logger.Printf("save token store on shutdown: %v", err)
			}
			logger.Println("Guardian daemon stopped")
			return
		}
	}
}
