package handlers

import (
	"log"
	"net/http"

	"github.com/ponder2000/guardian/internal/store"
)

// Docs handles the documentation pages.
type Docs struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
}

// NewDocs creates a new Docs handler.
func NewDocs(s *store.Store, t TemplateRenderer, l *log.Logger) *Docs {
	return &Docs{store: s, templates: t, logger: l}
}

// Index renders the documentation index page.
func (h *Docs) Index(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	data := PageData{Title: "Documentation", Active: "docs", User: user, CSRFToken: GetCSRFToken(r)}
	h.templates.RenderPage(w, "docs_index", "base", data)
}

// CLI renders the guardian-cli reference page.
func (h *Docs) CLI(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	data := PageData{Title: "CLI Reference", Active: "docs", User: user, CSRFToken: GetCSRFToken(r)}
	h.templates.RenderPage(w, "docs_cli", "base", data)
}

// SDK renders the client SDK guide page.
func (h *Docs) SDK(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	data := PageData{Title: "Client SDKs", Active: "docs", User: user, CSRFToken: GetCSRFToken(r)}
	h.templates.RenderPage(w, "docs_sdk", "base", data)
}

// Architecture renders the architecture docs page.
func (h *Docs) Architecture(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	data := PageData{Title: "Architecture", Active: "docs", User: user, CSRFToken: GetCSRFToken(r)}
	h.templates.RenderPage(w, "docs_architecture", "base", data)
}
