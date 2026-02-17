package handlers

import (
	"log"
	"net/http"

	"github.com/ponder2000/guardian/internal/store"
)

// DashboardStats holds counts displayed on the dashboard.
type DashboardStats struct {
	Projects int
	Hardware int
	Licenses int
	Keys     int
	Users    int
}

// DashboardData is the template data for the dashboard page.
type DashboardData struct {
	PageData
	Stats      DashboardStats
	RecentLogs []store.AuditLog
}

// Dashboard handles the dashboard page.
type Dashboard struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
}

// NewDashboard creates a new Dashboard handler.
func NewDashboard(s *store.Store, t TemplateRenderer, l *log.Logger) *Dashboard {
	return &Dashboard{store: s, templates: t, logger: l}
}

// Index renders the dashboard.
func (d *Dashboard) Index(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)

	stats := DashboardStats{}
	d.store.DB.QueryRow(`SELECT COUNT(*) FROM projects`).Scan(&stats.Projects)
	d.store.DB.QueryRow(`SELECT COUNT(*) FROM hardware_configs`).Scan(&stats.Hardware)
	d.store.DB.QueryRow(`SELECT COUNT(*) FROM licenses`).Scan(&stats.Licenses)
	d.store.DB.QueryRow(`SELECT COUNT(*) FROM key_pairs`).Scan(&stats.Keys)
	d.store.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&stats.Users)

	var recentLogs []store.AuditLog
	if user.Role == "admin" {
		recentLogs, _, _ = d.store.ListAuditLogs(store.AuditFilter{Limit: 10})
	}

	data := DashboardData{
		PageData: PageData{
			Title:     "Dashboard",
			Active:    "dashboard",
			User:      user,
			CSRFToken: GetCSRFToken(r),
		},
		Stats:      stats,
		RecentLogs: recentLogs,
	}

	d.templates.RenderPage(w, "dashboard", "base", data)
}
