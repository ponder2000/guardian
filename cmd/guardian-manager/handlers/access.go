package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/ponder2000/guardian/internal/store"
)

// AccessData is the template data for the access matrix.
type AccessData struct {
	PageData
	Users    []store.User
	Projects []store.Project
	Access   []store.UserProjectAccess
}

// Access handles user-project access management.
type Access struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
}

// NewAccess creates a new Access handler.
func NewAccess(s *store.Store, t TemplateRenderer, l *log.Logger) *Access {
	return &Access{store: s, templates: t, logger: l}
}

// Matrix renders the access matrix page.
func (a *Access) Matrix(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	users, _ := a.store.ListUsers()
	projects, _ := a.store.ListProjects()
	access, _ := a.store.ListAllAccess()

	data := AccessData{
		PageData: PageData{
			Title: "Access Control", Active: "access", User: user,
			CSRFToken: GetCSRFToken(r), Flash: r.URL.Query().Get("flash"),
		},
		Users:    users,
		Projects: projects,
		Access:   access,
	}
	a.templates.RenderPage(w, "access_matrix", "base", data)
}

// Grant grants access.
func (a *Access) Grant(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	userID, _ := strconv.Atoi(r.FormValue("user_id"))
	projectID, _ := strconv.Atoi(r.FormValue("project_id"))

	if err := a.store.GrantAccess(userID, projectID); err != nil {
		a.logger.Printf("grant access: %v", err)
		http.Error(w, "Failed", http.StatusInternalServerError)
		return
	}

	a.store.LogAction(user.ID, user.Username, "access.grant", "access", 0,
		strconv.Itoa(userID)+"->"+strconv.Itoa(projectID), ClientIP(r))

	http.Redirect(w, r, "/access?flash=Access+granted", http.StatusSeeOther)
}

// Revoke revokes access.
func (a *Access) Revoke(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	userID, _ := strconv.Atoi(r.FormValue("user_id"))
	projectID, _ := strconv.Atoi(r.FormValue("project_id"))

	if err := a.store.RevokeAccess(userID, projectID); err != nil {
		a.logger.Printf("revoke access: %v", err)
		http.Error(w, "Failed", http.StatusInternalServerError)
		return
	}

	a.store.LogAction(user.ID, user.Username, "access.revoke", "access", 0,
		strconv.Itoa(userID)+"->"+strconv.Itoa(projectID), ClientIP(r))

	http.Redirect(w, r, "/access?flash=Access+revoked", http.StatusSeeOther)
}
