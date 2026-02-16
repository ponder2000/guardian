package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/ponder2000/guardian/internal/store"
)

// RepositoryData is the template data for the repository page.
type RepositoryData struct {
	PageData
	Keys     []store.KeyPair
	Licenses []store.LicenseRecord
}

// Repository handles the download repository panel.
type Repository struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
}

// NewRepository creates a new Repository handler.
func NewRepository(s *store.Store, t TemplateRenderer, l *log.Logger) *Repository {
	return &Repository{store: s, templates: t, logger: l}
}

// Index renders the downloads panel.
func (h *Repository) Index(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	keys, _ := h.store.ListKeyPairs()
	licenses, _ := h.store.ListLicenseRecords()

	data := RepositoryData{
		PageData: PageData{
			Title: "Repository", Active: "repository", User: user,
			CSRFToken: GetCSRFToken(r),
		},
		Keys:     keys,
		Licenses: licenses,
	}
	h.templates.RenderPage(w, "repository", "base", data)
}

// DownloadPubKey serves a public key file.
func (h *Repository) DownloadPubKey(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	kp, err := h.store.GetKeyPair(id)
	if err != nil {
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.pub", kp.Name))
	w.Write([]byte(kp.PublicKeyHex))
}

// DownloadLicense serves a license file.
func (h *Repository) DownloadLicense(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	rec, err := h.store.GetLicenseRecord(id)
	if err != nil {
		http.Error(w, "License not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.license", rec.LicenseID))
	w.Write([]byte(rec.LicenseFileData))
}
