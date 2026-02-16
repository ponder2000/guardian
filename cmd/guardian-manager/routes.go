package main

import (
	"io/fs"
	"net/http"

	"github.com/ponder2000/guardian/cmd/guardian-manager/handlers"
)

func registerRoutes(mux *http.ServeMux, mw *Middleware, tmpl *Templates, app *App) {
	// Static files.
	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Handlers.
	auth := handlers.NewAuth(app.store, tmpl, app.logger)
	dashboard := handlers.NewDashboard(app.store, tmpl, app.logger)

	// Public routes.
	public := func(h http.HandlerFunc) http.Handler {
		return Chain(h, mw.Recovery, mw.Logger, mw.SecureHeaders, mw.SessionLoader)
	}

	// Authenticated routes.
	authed := func(h http.HandlerFunc) http.Handler {
		return Chain(h, mw.Recovery, mw.Logger, mw.SecureHeaders, mw.SessionLoader, mw.RequireAuth)
	}

	// Admin-only routes.
	_ = func(h http.HandlerFunc) http.Handler {
		return Chain(h, mw.Recovery, mw.Logger, mw.SecureHeaders, mw.SessionLoader, mw.RequireAuth, mw.RequireAdmin)
	}

	// Auth.
	mux.Handle("GET /login", public(auth.LoginPage))
	mux.Handle("POST /login", public(auth.Login))
	mux.Handle("POST /logout", authed(auth.Logout))

	// Dashboard.
	mux.Handle("GET /{$}", authed(dashboard.Index))

	// Placeholder routes — will be replaced in subsequent phases.
	placeholder := func(title, active string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			data := handlers.PageData{
				Title:     title,
				Active:    active,
				User:      user,
				CSRFToken: CSRFTokenFromContext(r.Context()),
			}
			tmpl.RenderPage(w, "placeholder", "base", data)
		}
	}

	mux.Handle("GET /projects", authed(placeholder("Projects", "projects")))
	mux.Handle("GET /hardware", authed(placeholder("Hardware", "hardware")))
	mux.Handle("GET /licenses", authed(placeholder("Licenses", "licenses")))
	mux.Handle("GET /users", authed(placeholder("Users", "users")))
	mux.Handle("GET /keys", authed(placeholder("Keys", "keys")))
	mux.Handle("GET /access", authed(placeholder("Access", "access")))
	mux.Handle("GET /audit", authed(placeholder("Audit Log", "audit")))
	mux.Handle("GET /repository", authed(placeholder("Repository", "repository")))
	mux.Handle("GET /export-import", authed(placeholder("Export / Import", "export-import")))
	mux.Handle("GET /docs", authed(placeholder("Documentation", "docs")))
}
