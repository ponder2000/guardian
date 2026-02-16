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

type contextKey string

// GetUser returns the authenticated user from the request context.
func GetUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(contextKey("user")).(*store.User)
	return u
}

// GetCSRFToken returns the CSRF token from the request context.
func GetCSRFToken(r *http.Request) string {
	t, _ := r.Context().Value(contextKey("csrf_token")).(string)
	return t
}

// ClientIP extracts the client IP.
func ClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}
