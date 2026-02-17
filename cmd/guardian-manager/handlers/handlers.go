package handlers

import (
	"io"
	"net/http"

	"github.com/ponder2000/guardian/internal/store"
)

// TemplateRenderer renders named templates.
type TemplateRenderer interface {
	Render(w io.Writer, layout string, data interface{}) error
	RenderPage(w io.Writer, page, layout string, data interface{}) error
}

// PageData is the base data passed to all templates.
type PageData struct {
	Title     string
	Active    string // sidebar active item
	User      *store.User
	CSRFToken string
	Flash     string
	Error     string
	Username  string // for login form repopulation
}

// ContextKey is the type used for context keys shared between middleware and handlers.
type ContextKey string

const (
	// CtxUser is the context key for the authenticated user.
	CtxUser ContextKey = "user"
	// CtxCSRFToken is the context key for the CSRF token.
	CtxCSRFToken ContextKey = "csrf_token"
)

// GetUser returns the authenticated user from the request context.
func GetUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(CtxUser).(*store.User)
	return u
}

// GetCSRFToken returns the CSRF token from the request context.
func GetCSRFToken(r *http.Request) string {
	t, _ := r.Context().Value(CtxCSRFToken).(string)
	return t
}

// ClientIP extracts the client IP.
func ClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}
