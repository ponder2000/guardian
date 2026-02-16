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
	users := handlers.NewUsers(app.store, tmpl, app.logger)
	keys := handlers.NewKeys(app.store, tmpl, app.logger)
	audit := handlers.NewAudit(app.store, tmpl, app.logger)

	// Route helper functions.
	public := func(h http.HandlerFunc) http.Handler {
		return Chain(h, mw.Recovery, mw.Logger, mw.SecureHeaders, mw.SessionLoader)
	}
	authed := func(h http.HandlerFunc) http.Handler {
		return Chain(h, mw.Recovery, mw.Logger, mw.SecureHeaders, mw.SessionLoader, mw.RequireAuth)
	}
	admin := func(h http.HandlerFunc) http.Handler {
		return Chain(h, mw.Recovery, mw.Logger, mw.SecureHeaders, mw.SessionLoader, mw.RequireAuth, mw.RequireAdmin)
	}

	// --- Auth ---
	mux.Handle("GET /login", public(auth.LoginPage))
	mux.Handle("POST /login", public(auth.Login))
	mux.Handle("POST /logout", authed(auth.Logout))

	// --- Dashboard ---
	mux.Handle("GET /{$}", authed(dashboard.Index))

	// --- Users (admin only) ---
	mux.Handle("GET /users", admin(users.List))
	mux.Handle("GET /users/new", admin(users.NewForm))
	mux.Handle("POST /users", admin(users.Create))
	mux.Handle("GET /users/{id}/edit", admin(users.EditForm))
	mux.Handle("POST /users/{id}", admin(users.Update))
	mux.Handle("POST /users/{id}/delete", admin(users.Delete))

	// --- Keys (admin only) ---
	mux.Handle("GET /keys", admin(keys.List))
	mux.Handle("GET /keys/new", admin(keys.GenerateForm))
	mux.Handle("POST /keys/generate", admin(keys.Generate))
	mux.Handle("POST /keys/import", admin(keys.Import))
	mux.Handle("GET /keys/{id}", admin(keys.Detail))
	mux.Handle("POST /keys/{id}/default", admin(keys.SetDefault))
	mux.Handle("POST /keys/{id}/delete", admin(keys.Delete))
	mux.Handle("GET /keys/{id}/download/public", admin(keys.DownloadPublic))

	// --- Audit (admin only) ---
	mux.Handle("GET /audit", admin(audit.List))
	mux.Handle("GET /audit/search", admin(audit.Search))

	// --- Placeholder routes (to be implemented) ---
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
	mux.Handle("GET /access", authed(placeholder("Access", "access")))
	mux.Handle("GET /repository", authed(placeholder("Repository", "repository")))
	mux.Handle("GET /export-import", authed(placeholder("Export / Import", "export-import")))
	mux.Handle("GET /docs", authed(placeholder("Documentation", "docs")))
}
