package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ponder2000/guardian/internal/fingerprint"
	"github.com/ponder2000/guardian/internal/license"
	"github.com/ponder2000/guardian/internal/store"
)

// LicensesData is the template data for the licenses list.
type LicensesData struct {
	PageData
	Licenses []store.LicenseRecord
}

// LicenseCreateData is the template data for the license creation form.
type LicenseCreateData struct {
	PageData
	Projects []store.Project
	Hardware []store.HardwareConfig
	Keys     []store.KeyPair
}

// LicenseDetailData is the template data for license detail view.
type LicenseDetailData struct {
	PageData
	Record  *store.LicenseRecord
	Decoded *license.License
}

// LicenseEditData is the template data for the license edit form.
type LicenseEditData struct {
	PageData
	Record  *store.LicenseRecord
	Decoded *license.License
}

// LicenseUploadData is the template data for license upload and analysis.
type LicenseUploadData struct {
	PageData
	Decoded    *license.License
	SignerFP   string
	Verified   bool
	VerifyErr  string
	Matches    []HardwareMatch
	FileData   string
}

// HardwareMatch represents the result of matching a license against a hardware config.
type HardwareMatch struct {
	HardwareConfig store.HardwareConfig
	Matched        int
	Total          int
	Pass           bool
}

// Licenses handles license management.
type Licenses struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
}

// NewLicenses creates a new Licenses handler.
func NewLicenses(s *store.Store, t TemplateRenderer, l *log.Logger) *Licenses {
	return &Licenses{store: s, templates: t, logger: l}
}

// List renders all licenses.
func (h *Licenses) List(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	licenses, _ := h.store.ListLicenseRecords()

	data := LicensesData{
		PageData: PageData{
			Title: "Licenses", Active: "licenses", User: user,
			CSRFToken: GetCSRFToken(r), Flash: r.URL.Query().Get("flash"),
		},
		Licenses: licenses,
	}
	h.templates.RenderPage(w, "licenses_list", "base", data)
}

// NewForm renders the license creation form.
func (h *Licenses) NewForm(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	projects, _ := h.store.ListProjects()
	hardware, _ := h.store.ListHardwareConfigs()
	keys, _ := h.store.ListKeyPairs()

	data := LicenseCreateData{
		PageData: PageData{
			Title: "Create License", Active: "licenses", User: user, CSRFToken: GetCSRFToken(r),
		},
		Projects: projects,
		Hardware: hardware,
		Keys:     keys,
	}
	h.templates.RenderPage(w, "license_create", "base", data)
}

// Create handles license creation (mirrors license-gen create).
func (h *Licenses) Create(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	projectID, _ := strconv.Atoi(r.FormValue("project_id"))
	hwConfigID, _ := strconv.Atoi(r.FormValue("hardware_config_id"))
	keyPairID, _ := strconv.Atoi(r.FormValue("key_pair_id"))
	customer := r.FormValue("customer")
	expiresStr := r.FormValue("expires")
	matchThreshold, _ := strconv.Atoi(r.FormValue("match_threshold"))
	notes := r.FormValue("notes")

	if matchThreshold < 1 || matchThreshold > 5 {
		matchThreshold = 3
	}

	// Validate.
	if projectID == 0 || hwConfigID == 0 || keyPairID == 0 || customer == "" || expiresStr == "" {
		h.renderCreateError(w, r, user, "All required fields must be filled")
		return
	}

	// Parse expiry.
	expiresAt, err := time.Parse("2006-01-02", expiresStr)
	if err != nil {
		h.renderCreateError(w, r, user, "Invalid date format (use YYYY-MM-DD)")
		return
	}
	expiresAt = expiresAt.UTC().Add(23*time.Hour + 59*time.Minute + 59*time.Second)

	// Load hardware config from DB.
	hwConfig, err := h.store.GetHardwareConfig(hwConfigID)
	if err != nil {
		h.renderCreateError(w, r, user, "Hardware config not found")
		return
	}

	// Build HardwareInfo.
	hwInfo := &fingerprint.HardwareInfo{
		MachineID:   hwConfig.MachineID,
		CPU:         hwConfig.CPU,
		Motherboard: hwConfig.Motherboard,
		DiskSerial:  hwConfig.DiskSerial,
		NICMac:      hwConfig.NICMac,
	}

	// Generate salt.
	saltBytes := make([]byte, 16)
	rand.Read(saltBytes)
	salt := hex.EncodeToString(saltBytes)

	// Compute fingerprints.
	fps := fingerprint.ComputeFingerprints(hwInfo, salt)

	// Parse modules from form.
	parsedModules := h.parseModulesFromForm(r)

	// Generate license ID.
	idBytes := make([]byte, 8)
	rand.Read(idBytes)
	licenseID := fmt.Sprintf("LIC-%s", strings.ToUpper(hex.EncodeToString(idBytes)))

	// Build license struct.
	lic := &license.License{
		LicenseID: licenseID,
		Version:   1,
		IssuedTo:  customer,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: expiresAt,
		Hardware: license.HardwareSpec{
			Salt:           salt,
			Fingerprints:   fps,
			MatchThreshold: matchThreshold,
		},
		Modules:      parsedModules,
		GlobalLimits: map[string]interface{}{},
	}

	// Load key pair from DB.
	kp, err := h.store.GetKeyPair(keyPairID)
	if err != nil {
		h.renderCreateError(w, r, user, "Key pair not found")
		return
	}

	privBytes, _ := hex.DecodeString(kp.PrivateKeyHex)
	privKey := ed25519.PrivateKey(privBytes)
	pubBytes, _ := hex.DecodeString(kp.PublicKeyHex)
	signerHash := sha256.Sum256(pubBytes)
	signerFP := hex.EncodeToString(signerHash[:])

	// Create signed license file.
	fileContent, err := license.CreateSignedFile(lic, privKey, signerFP)
	if err != nil {
		h.renderCreateError(w, r, user, fmt.Sprintf("Failed to sign license: %v", err))
		return
	}

	// Serialize modules to JSON for DB storage.
	modulesJSON, _ := json.Marshal(parsedModules)
	limitsJSON, _ := json.Marshal(lic.GlobalLimits)

	// Store in DB.
	rec := &store.LicenseRecord{
		LicenseID:        licenseID,
		ProjectID:        projectID,
		HardwareConfigID: hwConfigID,
		KeyPairID:        keyPairID,
		IssuedTo:         customer,
		IssuedAt:         lic.IssuedAt,
		ExpiresAt:        expiresAt,
		MatchThreshold:   matchThreshold,
		ModulesJSON:      string(modulesJSON),
		GlobalLimitsJSON: string(limitsJSON),
		LicenseFileData:  string(fileContent),
		Salt:             salt,
		Version:          1,
		Notes:            notes,
	}

	stored, err := h.store.CreateLicenseRecord(rec)
	if err != nil {
		h.renderCreateError(w, r, user, fmt.Sprintf("Failed to store: %v", err))
		return
	}

	h.store.LogAction(user.ID, user.Username, "license.create", "license", stored.ID,
		fmt.Sprintf(`{"license_id":%q,"customer":%q}`, licenseID, customer), ClientIP(r))

	http.Redirect(w, r, fmt.Sprintf("/licenses/%d?flash=License+created", stored.ID), http.StatusSeeOther)
}

func (h *Licenses) renderCreateError(w http.ResponseWriter, r *http.Request, user *store.User, errMsg string) {
	projects, _ := h.store.ListProjects()
	hardware, _ := h.store.ListHardwareConfigs()
	keys, _ := h.store.ListKeyPairs()
	data := LicenseCreateData{
		PageData: PageData{
			Title: "Create License", Active: "licenses", User: user,
			CSRFToken: GetCSRFToken(r), Error: errMsg,
		},
		Projects: projects, Hardware: hardware, Keys: keys,
	}
	w.WriteHeader(http.StatusBadRequest)
	h.templates.RenderPage(w, "license_create", "base", data)
}

// Detail shows a decoded license.
func (h *Licenses) Detail(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	rec, err := h.store.GetLicenseRecord(id)
	if err != nil {
		http.Error(w, "License not found", http.StatusNotFound)
		return
	}

	// Parse the stored license file.
	sl, err := license.ParseFile([]byte(rec.LicenseFileData))
	if err != nil {
		h.logger.Printf("parse license %d: %v", id, err)
	}

	var decoded *license.License
	if sl != nil {
		decoded = sl.License
	}

	data := LicenseDetailData{
		PageData: PageData{
			Title: rec.LicenseID, Active: "licenses", User: user,
			CSRFToken: GetCSRFToken(r), Flash: r.URL.Query().Get("flash"),
		},
		Record:  rec,
		Decoded: decoded,
	}
	h.templates.RenderPage(w, "license_detail", "base", data)
}

// EditForm renders the license modification form.
func (h *Licenses) EditForm(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	rec, err := h.store.GetLicenseRecord(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	sl, _ := license.ParseFile([]byte(rec.LicenseFileData))
	var decoded *license.License
	if sl != nil {
		decoded = sl.License
	}

	data := LicenseEditData{
		PageData: PageData{
			Title: "Edit " + rec.LicenseID, Active: "licenses", User: user, CSRFToken: GetCSRFToken(r),
		},
		Record:  rec,
		Decoded: decoded,
	}
	h.templates.RenderPage(w, "license_edit", "base", data)
}

// Update handles license modification and re-signing (mirrors license-gen update).
func (h *Licenses) Update(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	rec, err := h.store.GetLicenseRecord(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	sl, err := license.ParseFile([]byte(rec.LicenseFileData))
	if err != nil {
		http.Error(w, "Failed to parse existing license", http.StatusInternalServerError)
		return
	}

	lic := sl.License

	// Apply modifications.
	if expiresStr := r.FormValue("expires"); expiresStr != "" {
		expiresAt, err := time.Parse("2006-01-02", expiresStr)
		if err == nil {
			expiresAt = expiresAt.UTC().Add(23*time.Hour + 59*time.Minute + 59*time.Second)
			lic.ExpiresAt = expiresAt
		}
	}

	if mt := r.FormValue("match_threshold"); mt != "" {
		if v, err := strconv.Atoi(mt); err == nil && v >= 1 && v <= 5 {
			lic.Hardware.MatchThreshold = v
		}
	}

	// Parse modules from form.
	newModules := h.parseModulesFromForm(r)
	if len(newModules) > 0 {
		if lic.Modules == nil {
			lic.Modules = make(map[string]license.Module)
		}
		for name, mod := range newModules {
			if existing, ok := lic.Modules[name]; ok {
				existing.Enabled = true
				if existing.Metadata == nil {
					existing.Metadata = make(map[string]interface{})
				}
				for k, v := range mod.Metadata {
					existing.Metadata[k] = v
				}
				lic.Modules[name] = existing
			} else {
				lic.Modules[name] = mod
			}
		}
	}

	// Handle disabled modules.
	for _, name := range r.Form["disable_module"] {
		if mod, ok := lic.Modules[name]; ok {
			mod.Enabled = false
			lic.Modules[name] = mod
		}
	}

	// Re-sign.
	kp, err := h.store.GetKeyPair(rec.KeyPairID)
	if err != nil {
		http.Error(w, "Key pair not found", http.StatusInternalServerError)
		return
	}

	privBytes, _ := hex.DecodeString(kp.PrivateKeyHex)
	privKey := ed25519.PrivateKey(privBytes)
	pubBytes, _ := hex.DecodeString(kp.PublicKeyHex)
	signerHash := sha256.Sum256(pubBytes)
	signerFP := hex.EncodeToString(signerHash[:])

	fileContent, err := license.CreateSignedFile(lic, privKey, signerFP)
	if err != nil {
		http.Error(w, "Failed to re-sign license", http.StatusInternalServerError)
		return
	}

	modulesJSON, _ := json.Marshal(lic.Modules)
	limitsJSON, _ := json.Marshal(lic.GlobalLimits)

	if err := h.store.UpdateLicenseFileData(id, string(fileContent), string(modulesJSON), string(limitsJSON), lic.ExpiresAt, lic.Hardware.MatchThreshold); err != nil {
		http.Error(w, "Failed to update", http.StatusInternalServerError)
		return
	}

	h.store.LogAction(user.ID, user.Username, "license.update", "license", id, "", ClientIP(r))
	http.Redirect(w, r, fmt.Sprintf("/licenses/%d?flash=License+updated", id), http.StatusSeeOther)
}

// Download serves the license file.
func (h *Licenses) Download(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	rec, err := h.store.GetLicenseRecord(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.license", rec.LicenseID))
	w.Write([]byte(rec.LicenseFileData))
}

// Delete removes a license.
func (h *Licenses) Delete(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	if err := h.store.DeleteLicenseRecord(id); err != nil {
		http.Error(w, "Failed to delete", http.StatusInternalServerError)
		return
	}

	h.store.LogAction(user.ID, user.Username, "license.delete", "license", id, "", ClientIP(r))
	http.Redirect(w, r, "/licenses?flash=License+deleted", http.StatusSeeOther)
}

// UploadForm renders the license upload/analysis page.
func (h *Licenses) UploadForm(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	data := LicenseUploadData{
		PageData: PageData{
			Title: "Upload & Analyze License", Active: "licenses", User: user, CSRFToken: GetCSRFToken(r),
		},
	}
	h.templates.RenderPage(w, "license_upload", "base", data)
}

// Upload handles license file upload and analysis.
func (h *Licenses) Upload(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)

	file, _, err := r.FormFile("license_file")
	if err != nil {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}

	sl, err := license.ParseFile(fileData)
	if err != nil {
		data := LicenseUploadData{
			PageData: PageData{
				Title: "Upload & Analyze License", Active: "licenses", User: user,
				CSRFToken: GetCSRFToken(r), Error: "Failed to parse license: " + err.Error(),
			},
		}
		h.templates.RenderPage(w, "license_upload", "base", data)
		return
	}

	// Try to verify against all stored keys.
	verified := false
	verifyErr := "No matching key found"
	keys, _ := h.store.ListKeyPairs()
	for _, kp := range keys {
		pubBytes, _ := hex.DecodeString(kp.PublicKeyHex)
		if sl.Verify(ed25519.PublicKey(pubBytes)) == nil {
			verified = true
			verifyErr = ""
			break
		}
	}

	// Match against all hardware configs.
	allHW, _ := h.store.ListHardwareConfigs()
	var matches []HardwareMatch
	for _, hw := range allHW {
		hwInfo := &fingerprint.HardwareInfo{
			MachineID:   hw.MachineID,
			CPU:         hw.CPU,
			Motherboard: hw.Motherboard,
			DiskSerial:  hw.DiskSerial,
			NICMac:      hw.NICMac,
		}
		actual := fingerprint.ComputeFingerprints(hwInfo, sl.License.Hardware.Salt)
		matched, total, pass := fingerprint.MatchThreshold(sl.License.Hardware.Fingerprints, actual, sl.License.Hardware.MatchThreshold)
		matches = append(matches, HardwareMatch{
			HardwareConfig: hw,
			Matched:        matched,
			Total:          total,
			Pass:           pass,
		})
	}

	data := LicenseUploadData{
		PageData: PageData{
			Title: "License Analysis", Active: "licenses", User: user, CSRFToken: GetCSRFToken(r),
		},
		Decoded:   sl.License,
		SignerFP:  sl.SignerFP,
		Verified:  verified,
		VerifyErr: verifyErr,
		Matches:   matches,
		FileData:  string(fileData),
	}
	h.templates.RenderPage(w, "license_upload", "base", data)
}

// HardwareForProject returns hardware configs for a project (HTMX endpoint).
func (h *Licenses) HardwareForProject(w http.ResponseWriter, r *http.Request) {
	projectID, _ := strconv.Atoi(r.URL.Query().Get("project_id"))
	configs, _ := h.store.ListHardwareForProject(projectID)

	w.Header().Set("Content-Type", "text/html")
	for _, hw := range configs {
		fmt.Fprintf(w, `<option value="%d">%s</option>`, hw.ID, hw.Label)
	}
}

// parseModulesFromForm parses modules from repeated form fields.
// Expects module_name[], module_key[], module_value[] fields.
func (h *Licenses) parseModulesFromForm(r *http.Request) map[string]license.Module {
	r.ParseForm()
	names := r.Form["module_name"]
	mkeys := r.Form["module_key"]
	mvals := r.Form["module_value"]

	modules := make(map[string]license.Module)

	for i, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		mod, exists := modules[name]
		if !exists {
			mod = license.Module{
				Enabled:  true,
				Features: []string{},
				Metadata: make(map[string]interface{}),
			}
		}

		if i < len(mkeys) && i < len(mvals) {
			key := strings.TrimSpace(mkeys[i])
			val := strings.TrimSpace(mvals[i])
			if key != "" && val != "" {
				// Try numeric parsing.
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					mod.Metadata[key] = n
				} else if f, err := strconv.ParseFloat(val, 64); err == nil {
					mod.Metadata[key] = f
				} else {
					mod.Metadata[key] = val
				}
			}
		}

		modules[name] = mod
	}

	return modules
}
