package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ponder2000/guardian/internal/store"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
	author    = "unknown"
)

// App holds the application dependencies.
type App struct {
	store  *store.Store
	logger *log.Logger
	debDir string
}

func main() {
	dbPath := flag.String("db", "data/guardian-manager.db", "Path to SQLite database file")
	listen := flag.String("listen", ":8080", "HTTP listen address")
	debDir := flag.String("deb-dir", "deb", "Directory containing .deb packages for download")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("guardian-manager %s (commit: %s, built: %s, author: %s)\n", version, commit, buildTime, author)
		os.Exit(0)
	}

	logger := log.New(os.Stderr, "[guardian-manager] ", log.LstdFlags)

	// Open database.
	s, err := store.Open(*dbPath)
	if err != nil {
		logger.Fatalf("open database: %v", err)
	}
	defer s.Close()

	// Run migrations.
	if err := s.Migrate(); err != nil {
		logger.Fatalf("migrate database: %v", err)
	}

	// Seed admin user if no users exist.
	count, _ := s.UserCount()
	if count == 0 {
		_, err := s.CreateUser("admin", "admin@localhost", "changeme", "admin")
		if err != nil {
			logger.Fatalf("seed admin user: %v", err)
		}
		logger.Println("Seeded default admin user (username: admin, password: changeme)")
	}

	// Parse templates.
	tmpl, err := NewTemplates()
	if err != nil {
		logger.Fatalf("parse templates: %v", err)
	}

	app := &App{store: s, logger: logger, debDir: *debDir}
	mw := NewMiddleware(s, logger)

	// Register routes.
	mux := http.NewServeMux()
	registerRoutes(mux, mw, tmpl, app)

	// Start session cleanup goroutine.
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cleaned, err := s.CleanExpiredSessions()
			if err != nil {
				logger.Printf("session cleanup error: %v", err)
			} else if cleaned > 0 {
				logger.Printf("cleaned %d expired sessions", cleaned)
			}
		}
	}()

	// Start HTTP server.
	srv := &http.Server{
		Addr:         *listen,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown.
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Printf("Starting Guardian Manager on %s", *listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("listen: %v", err)
		}
	}()

	<-done
	logger.Println("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatalf("shutdown: %v", err)
	}
	logger.Println("Server stopped")
}
