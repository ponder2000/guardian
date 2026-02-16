package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"github.com/ponder2000/guardian/internal/store"
)

type contextKey string

const (
	ctxUser      contextKey = "user"
	ctxSession   contextKey = "session"
	ctxCSRFToken contextKey = "csrf_token"
)

// Middleware holds dependencies for HTTP middleware.
type Middleware struct {
	store  *store.Store
	logger *log.Logger
}

// NewMiddleware creates a new middleware instance.
func NewMiddleware(s *store.Store, logger *log.Logger) *Middleware {
	return &Middleware{store: s, logger: logger}
}

// Recovery catches panics and returns 500.
func (m *Middleware) Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				m.logger.Printf("PANIC: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Logger logs HTTP requests.
func (m *Middleware) Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(wrapped, r)
		m.logger.Printf("%s %s %d %s", r.Method, r.URL.Path, wrapped.status, time.Since(start).Round(time.Millisecond))
	})
}

// SecureHeaders sets security response headers.
func (m *Middleware) SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// SessionLoader reads the session cookie and attaches user to context.
func (m *Middleware) SessionLoader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("guardian_session")
		if err == nil && cookie.Value != "" {
			sess, user, err := m.store.GetSession(cookie.Value)
			if err == nil {
				ctx := context.WithValue(r.Context(), ctxUser, user)
				ctx = context.WithValue(ctx, ctxSession, sess)
				r = r.WithContext(ctx)
			}
		}

		// Generate CSRF token for forms.
		csrfBytes := make([]byte, 16)
		rand.Read(csrfBytes)
		csrfToken := hex.EncodeToString(csrfBytes)
		ctx := context.WithValue(r.Context(), ctxCSRFToken, csrfToken)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// RequireAuth redirects to /login if not authenticated.
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserFromContext(r.Context()) == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin returns 403 if the user is not an admin.
func (m *Middleware) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if user.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Chain composes multiple middleware functions.
func Chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// UserFromContext returns the authenticated user from context, or nil.
func UserFromContext(ctx context.Context) *store.User {
	u, _ := ctx.Value(ctxUser).(*store.User)
	return u
}

// CSRFTokenFromContext returns the CSRF token from context.
func CSRFTokenFromContext(ctx context.Context) string {
	t, _ := ctx.Value(ctxCSRFToken).(string)
	return t
}

// ClientIP extracts the client IP address.
func ClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}

// statusWriter wraps ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}
