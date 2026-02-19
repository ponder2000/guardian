package handlers

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ponder2000/guardian/internal/store"
)

// DebInfo holds metadata about an available .deb package.
type DebInfo struct {
	Filename string
	Size     int64
}

// RepositoryData is the template data for the repository page.
type RepositoryData struct {
	PageData
	Keys     []store.KeyPair
	Licenses []store.LicenseRecord
	DebFiles []DebInfo
}

// Repository handles the download repository panel.
type Repository struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
	debDir    string
}

// NewRepository creates a new Repository handler.
func NewRepository(s *store.Store, t TemplateRenderer, l *log.Logger, debDir string) *Repository {
	return &Repository{store: s, templates: t, logger: l, debDir: debDir}
}

// Index renders the downloads panel.
func (h *Repository) Index(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	keys, _ := h.store.ListKeyPairs()
	licenses, _ := h.store.ListLicenseRecords()

	var debFiles []DebInfo
	if entries, err := os.ReadDir(h.debDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".deb") {
				info, err := e.Info()
				if err != nil {
					continue
				}
				debFiles = append(debFiles, DebInfo{
					Filename: e.Name(),
					Size:     info.Size(),
				})
			}
		}
	}

	data := RepositoryData{
		PageData: PageData{
			Title: "Repository", Active: "repository", User: user,
			CSRFToken: GetCSRFToken(r),
		},
		Keys:     keys,
		Licenses: licenses,
		DebFiles: debFiles,
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

// DownloadDeb serves a .deb package file.
func (h *Repository) DownloadDeb(w http.ResponseWriter, r *http.Request) {
	filename := r.PathValue("filename")

	// Reject path traversal attempts.
	if strings.Contains(filename, "/") || strings.Contains(filename, "..") || !strings.HasSuffix(filename, ".deb") {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	path := filepath.Join(h.debDir, filename)
	info, err := os.Stat(path)
	if err != nil {
		http.Error(w, "Package not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.debian.binary-package")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	http.ServeFile(w, r, path)
}
