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
	projects := handlers.NewProjects(app.store, tmpl, app.logger)
	hardware := handlers.NewHardware(app.store, tmpl, app.logger)
	access := handlers.NewAccess(app.store, tmpl, app.logger)
	licenses := handlers.NewLicenses(app.store, tmpl, app.logger)
	repository := handlers.NewRepository(app.store, tmpl, app.logger)
	exportImport := handlers.NewExportImport(app.store, tmpl, app.logger)

	// Route helpers.
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

	// --- Users (admin) ---
	mux.Handle("GET /users", admin(users.List))
	mux.Handle("GET /users/new", admin(users.NewForm))
	mux.Handle("POST /users", admin(users.Create))
	mux.Handle("GET /users/{id}/edit", admin(users.EditForm))
	mux.Handle("POST /users/{id}", admin(users.Update))
	mux.Handle("POST /users/{id}/delete", admin(users.Delete))

	// --- Keys (admin) ---
	mux.Handle("GET /keys", admin(keys.List))
	mux.Handle("GET /keys/new", admin(keys.GenerateForm))
	mux.Handle("POST /keys/generate", admin(keys.Generate))
	mux.Handle("POST /keys/import", admin(keys.Import))
	mux.Handle("GET /keys/{id}", admin(keys.Detail))
	mux.Handle("POST /keys/{id}/default", admin(keys.SetDefault))
	mux.Handle("POST /keys/{id}/delete", admin(keys.Delete))
	mux.Handle("GET /keys/{id}/download/public", admin(keys.DownloadPublic))

	// --- Audit (admin) ---
	mux.Handle("GET /audit", admin(audit.List))
	mux.Handle("GET /audit/search", admin(audit.Search))

	// --- Projects ---
	mux.Handle("GET /projects", authed(projects.List))
	mux.Handle("GET /projects/new", admin(projects.NewForm))
	mux.Handle("POST /projects", admin(projects.Create))
	mux.Handle("GET /projects/{id}", authed(projects.Detail))
	mux.Handle("GET /projects/{id}/edit", admin(projects.EditForm))
	mux.Handle("POST /projects/{id}", admin(projects.Update))
	mux.Handle("POST /projects/{id}/delete", admin(projects.Delete))

	// --- Hardware ---
	mux.Handle("GET /hardware", authed(hardware.List))
	mux.Handle("GET /hardware/new", admin(hardware.NewForm))
	mux.Handle("GET /projects/{pid}/hardware/new", admin(hardware.NewForm))
	mux.Handle("POST /projects/{pid}/hardware", admin(hardware.Create))
	mux.Handle("GET /hardware/{id}/edit", admin(hardware.EditForm))
	mux.Handle("POST /hardware/{id}", admin(hardware.Update))
	mux.Handle("POST /hardware/{id}/delete", admin(hardware.Delete))
	mux.Handle("POST /hardware/upload-json", admin(hardware.UploadJSON))

	// --- Access (admin) ---
	mux.Handle("GET /access", admin(access.Matrix))
	mux.Handle("POST /access/grant", admin(access.Grant))
	mux.Handle("POST /access/revoke", admin(access.Revoke))

	// --- Licenses ---
	mux.Handle("GET /licenses", authed(licenses.List))
	mux.Handle("GET /licenses/new", admin(licenses.NewForm))
	mux.Handle("GET /licenses/upload", admin(licenses.UploadForm))
	mux.Handle("POST /licenses/upload", admin(licenses.Upload))
	mux.Handle("GET /licenses/hardware", admin(licenses.HardwareForProject))
	mux.Handle("POST /licenses", admin(licenses.Create))
	mux.Handle("GET /licenses/{id}", authed(licenses.Detail))
	mux.Handle("GET /licenses/{id}/edit", admin(licenses.EditForm))
	mux.Handle("POST /licenses/{id}", admin(licenses.Update))
	mux.Handle("GET /licenses/{id}/download", authed(licenses.Download))
	mux.Handle("POST /licenses/{id}/delete", admin(licenses.Delete))

	// --- Repository ---
	mux.Handle("GET /repository", authed(repository.Index))
	mux.Handle("GET /repository/pubkey/{id}", authed(repository.DownloadPubKey))
	mux.Handle("GET /repository/license/{id}", authed(repository.DownloadLicense))

	// --- Export / Import (admin) ---
	mux.Handle("GET /export-import", admin(exportImport.Index))
	mux.Handle("GET /export", admin(exportImport.Export))
	mux.Handle("POST /import", admin(exportImport.Import))

	// --- Docs ---
	docs := handlers.NewDocs(app.store, tmpl, app.logger)
	mux.Handle("GET /docs", authed(docs.Index))
	mux.Handle("GET /docs/cli", authed(docs.CLI))
	mux.Handle("GET /docs/sdk", authed(docs.SDK))
	mux.Handle("GET /docs/architecture", authed(docs.Architecture))
}
