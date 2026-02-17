package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/ponder2000/guardian/internal/store"
)

// ExportImportData is the template data for the export/import page.
type ExportImportData struct {
	PageData
	Result    *store.ImportResult
	ExportURL string
}

// ExportImport handles data export and import.
type ExportImport struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
}

// NewExportImport creates a new ExportImport handler.
func NewExportImport(s *store.Store, t TemplateRenderer, l *log.Logger) *ExportImport {
	return &ExportImport{store: s, templates: t, logger: l}
}

// Index renders the export/import page.
func (h *ExportImport) Index(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	data := ExportImportData{
		PageData: PageData{
			Title: "Export / Import", Active: "export-import", User: user,
			CSRFToken: GetCSRFToken(r), Flash: r.URL.Query().Get("flash"),
		},
	}
	h.templates.RenderPage(w, "export_import", "base", data)
}

// Export serves a JSON export of all data.
func (h *ExportImport) Export(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	exportData, err := h.store.Export()
	if err != nil {
		h.logger.Printf("export: %v", err)
		http.Error(w, "Export failed", http.StatusInternalServerError)
		return
	}

	jsonBytes, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		http.Error(w, "JSON marshal failed", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("guardian-export-%s.json", time.Now().Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Write(jsonBytes)

	h.store.LogAction(user.ID, user.Username, "data.export", "", 0, "", ClientIP(r))
}

// Import handles JSON data import.
func (h *ExportImport) Import(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)

	file, _, err := r.FormFile("import_file")
	if err != nil {
		data := ExportImportData{
			PageData: PageData{
				Title: "Export / Import", Active: "export-import", User: user,
				CSRFToken: GetCSRFToken(r), Error: "No file uploaded",
			},
		}
		h.templates.RenderPage(w, "export_import", "base", data)
		return
	}
	defer file.Close()

	fileData, err := io.ReadAll(file)
	if err != nil {
		data := ExportImportData{
			PageData: PageData{
				Title: "Export / Import", Active: "export-import", User: user,
				CSRFToken: GetCSRFToken(r), Error: "Failed to read file",
			},
		}
		h.templates.RenderPage(w, "export_import", "base", data)
		return
	}

	result, err := h.store.Import(fileData)
	if err != nil {
		data := ExportImportData{
			PageData: PageData{
				Title: "Export / Import", Active: "export-import", User: user,
				CSRFToken: GetCSRFToken(r), Error: fmt.Sprintf("Import failed: %v", err),
			},
		}
		h.templates.RenderPage(w, "export_import", "base", data)
		return
	}

	h.store.LogAction(user.ID, user.Username, "data.import", "", 0,
		fmt.Sprintf(`{"projects":%d,"hardware":%d,"keys":%d,"licenses":%d,"users":%d}`,
			result.Projects, result.Hardware, result.Keys, result.Licenses, result.Users), ClientIP(r))

	data := ExportImportData{
		PageData: PageData{
			Title: "Export / Import", Active: "export-import", User: user,
			CSRFToken: GetCSRFToken(r),
			Flash: fmt.Sprintf("Imported %d projects, %d hardware, %d keys, %d licenses, %d users (%d skipped)",
				result.Projects, result.Hardware, result.Keys, result.Licenses, result.Users, result.Skipped),
		},
		Result: &result,
	}
	h.templates.RenderPage(w, "export_import", "base", data)
}
