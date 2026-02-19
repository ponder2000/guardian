package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/ponder2000/guardian/internal/store"
)

// Auth handles login/logout.
type Auth struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
}

// NewAuth creates a new Auth handler.
func NewAuth(s *store.Store, t TemplateRenderer, l *log.Logger) *Auth {
	return &Auth{store: s, templates: t, logger: l}
}

// LoginPage renders the login form.
func (a *Auth) LoginPage(w http.ResponseWriter, r *http.Request) {
	if GetUser(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	data := PageData{Title: "Login"}
	a.templates.RenderPage(w, "login", "auth", data)
}

// Login handles the login form submission.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := a.store.GetUserByUsername(username)
	if err != nil || !store.VerifyPassword(user, password) {
		ip := ClientIP(r)
		data := PageData{Title: "Login", Error: "Invalid username or password", Username: username}
		w.WriteHeader(http.StatusUnauthorized)
		a.templates.RenderPage(w, "login", "auth", data)
		a.store.LogAction(0, username, "auth.login_failed", "user", 0, "Invalid credentials", ip)
		return
	}

	if !user.IsActive {
		ip := ClientIP(r)
		data := PageData{Title: "Login", Error: "Account is disabled", Username: username}
		w.WriteHeader(http.StatusForbidden)
		a.templates.RenderPage(w, "login", "auth", data)
		a.store.LogAction(user.ID, user.Username, "auth.login_disabled", "user", user.ID, "Account disabled", ip)
		return
	}

	sess, err := a.store.CreateSession(user.ID, ClientIP(r), r.UserAgent(), 24*time.Hour)
	if err != nil {
		a.logger.Printf("create session error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "guardian_session",
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})

	a.store.LogAction(user.ID, user.Username, "auth.login", "user", user.ID, "", ClientIP(r))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Logout handles session logout.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("guardian_session")
	if err == nil {
		a.store.DeleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "guardian_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
