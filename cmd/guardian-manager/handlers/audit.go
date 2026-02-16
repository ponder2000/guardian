package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/ponder2000/guardian/internal/store"
)

// AuditData is the template data for the audit log page.
type AuditData struct {
	PageData
	Logs       []store.AuditLog
	Total      int
	Page       int
	TotalPages int
}

// Audit handles audit log viewing.
type Audit struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
}

// NewAudit creates a new Audit handler.
func NewAudit(s *store.Store, t TemplateRenderer, l *log.Logger) *Audit {
	return &Audit{store: s, templates: t, logger: l}
}

const auditPageSize = 50

// List renders the audit log page.
func (a *Audit) List(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	filter := store.AuditFilter{
		Limit:  auditPageSize,
		Offset: (page - 1) * auditPageSize,
	}

	logs, total, err := a.store.ListAuditLogs(filter)
	if err != nil {
		a.logger.Printf("list audit: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	totalPages := (total + auditPageSize - 1) / auditPageSize

	data := AuditData{
		PageData: PageData{
			Title:     "Audit Log",
			Active:    "audit",
			User:      user,
			CSRFToken: GetCSRFToken(r),
		},
		Logs:       logs,
		Total:      total,
		Page:       page,
		TotalPages: totalPages,
	}
	a.templates.RenderPage(w, "audit_log", "base", data)
}

// Search handles HTMX search/filter requests.
func (a *Audit) Search(w http.ResponseWriter, r *http.Request) {
	filter := store.AuditFilter{
		Username: r.URL.Query().Get("q"),
		Action:   r.URL.Query().Get("action_filter"),
		Limit:    auditPageSize,
	}

	logs, _, err := a.store.ListAuditLogs(filter)
	if err != nil {
		a.logger.Printf("search audit: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Render just the table body rows.
	a.templates.RenderPage(w, "audit_log", "audit_body", AuditData{
		PageData: PageData{User: GetUser(r), CSRFToken: GetCSRFToken(r)},
		Logs:     logs,
	})
}
