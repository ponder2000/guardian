package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/ponder2000/guardian/internal/store"
)

// ProjectsData is the template data for the projects list.
type ProjectsData struct {
	PageData
	Projects []store.Project
}

// ProjectDetailData is the template data for project detail.
type ProjectDetailData struct {
	PageData
	Project  *store.Project
	Hardware []store.HardwareConfig
}

// ProjectFormData is the template data for the project form.
type ProjectFormData struct {
	PageData
	EditProject *store.Project
	IsEdit      bool
}

// Projects handles project CRUD.
type Projects struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
}

// NewProjects creates a new Projects handler.
func NewProjects(s *store.Store, t TemplateRenderer, l *log.Logger) *Projects {
	return &Projects{store: s, templates: t, logger: l}
}

// List renders the projects table.
func (p *Projects) List(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	var projects []store.Project
	var err error

	if user.Role == "admin" {
		projects, err = p.store.ListProjects()
	} else {
		projects, err = p.store.ListProjectsForUser(user.ID)
	}
	if err != nil {
		p.logger.Printf("list projects: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := ProjectsData{
		PageData: PageData{
			Title:     "Projects",
			Active:    "projects",
			User:      user,
			CSRFToken: GetCSRFToken(r),
			Flash:     r.URL.Query().Get("flash"),
		},
		Projects: projects,
	}
	p.templates.RenderPage(w, "projects_list", "base", data)
}

// NewForm renders the create project form.
func (p *Projects) NewForm(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	data := ProjectFormData{
		PageData: PageData{
			Title:     "New Project",
			Active:    "projects",
			User:      user,
			CSRFToken: GetCSRFToken(r),
		},
	}
	p.templates.RenderPage(w, "project_form", "base", data)
}

// Create handles project creation.
func (p *Projects) Create(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	name := r.FormValue("name")
	description := r.FormValue("description")
	contact := r.FormValue("contact")
	notes := r.FormValue("notes")

	if name == "" {
		data := ProjectFormData{
			PageData: PageData{
				Title: "New Project", Active: "projects", User: user,
				CSRFToken: GetCSRFToken(r), Error: "Project name is required",
			},
		}
		w.WriteHeader(http.StatusBadRequest)
		p.templates.RenderPage(w, "project_form", "base", data)
		return
	}

	proj, err := p.store.CreateProject(name, description, contact, notes)
	if err != nil {
		data := ProjectFormData{
			PageData: PageData{
				Title: "New Project", Active: "projects", User: user,
				CSRFToken: GetCSRFToken(r), Error: fmt.Sprintf("Failed: %v", err),
			},
		}
		w.WriteHeader(http.StatusBadRequest)
		p.templates.RenderPage(w, "project_form", "base", data)
		return
	}

	p.store.LogAction(user.ID, user.Username, "project.create", "project", proj.ID,
		fmt.Sprintf(`{"name":%q}`, name), ClientIP(r))

	http.Redirect(w, r, "/projects?flash=Project+created", http.StatusSeeOther)
}

// Detail shows a project with its hardware configs.
func (p *Projects) Detail(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	proj, err := p.store.GetProject(id)
	if err != nil {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}

	// Access check for viewers.
	if user.Role != "admin" && !p.store.HasAccess(user.ID, id) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	hardware, _ := p.store.ListHardwareForProject(id)

	data := ProjectDetailData{
		PageData: PageData{
			Title:     proj.Name,
			Active:    "projects",
			User:      user,
			CSRFToken: GetCSRFToken(r),
			Flash:     r.URL.Query().Get("flash"),
		},
		Project:  proj,
		Hardware: hardware,
	}
	p.templates.RenderPage(w, "project_detail", "base", data)
}

// EditForm renders the edit project form.
func (p *Projects) EditForm(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	proj, err := p.store.GetProject(id)
	if err != nil {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}

	data := ProjectFormData{
		PageData: PageData{
			Title: "Edit Project", Active: "projects", User: user, CSRFToken: GetCSRFToken(r),
		},
		EditProject: proj,
		IsEdit:      true,
	}
	p.templates.RenderPage(w, "project_form", "base", data)
}

// Update handles project updates.
func (p *Projects) Update(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	name := r.FormValue("name")
	description := r.FormValue("description")
	contact := r.FormValue("contact")
	notes := r.FormValue("notes")
	isActive := r.FormValue("is_active") == "on"

	if err := p.store.UpdateProject(id, name, description, contact, notes, isActive); err != nil {
		p.logger.Printf("update project %d: %v", id, err)
		http.Error(w, "Failed to update project", http.StatusInternalServerError)
		return
	}

	p.store.LogAction(user.ID, user.Username, "project.update", "project", id,
		fmt.Sprintf(`{"name":%q}`, name), ClientIP(r))

	http.Redirect(w, r, fmt.Sprintf("/projects/%d?flash=Project+updated", id), http.StatusSeeOther)
}

// Delete handles project deletion.
func (p *Projects) Delete(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	if err := p.store.DeleteProject(id); err != nil {
		http.Error(w, "Failed to delete project", http.StatusInternalServerError)
		return
	}

	p.store.LogAction(user.ID, user.Username, "project.delete", "project", id, "", ClientIP(r))
	http.Redirect(w, r, "/projects?flash=Project+deleted", http.StatusSeeOther)
}
