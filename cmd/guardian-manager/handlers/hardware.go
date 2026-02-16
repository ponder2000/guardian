package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/ponder2000/guardian/internal/store"
)

// HardwareListData is the template data for hardware list.
type HardwareListData struct {
	PageData
	Configs []store.HardwareConfig
}

// HardwareFormData is the template data for hardware form.
type HardwareFormData struct {
	PageData
	ProjectID   int
	Projects    []store.Project
	EditConfig  *store.HardwareConfig
	IsEdit      bool
}

// Hardware handles hardware config CRUD.
type Hardware struct {
	store     *store.Store
	templates TemplateRenderer
	logger    *log.Logger
}

// NewHardware creates a new Hardware handler.
func NewHardware(s *store.Store, t TemplateRenderer, l *log.Logger) *Hardware {
	return &Hardware{store: s, templates: t, logger: l}
}

// List renders all hardware configs.
func (h *Hardware) List(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	configs, err := h.store.ListHardwareConfigs()
	if err != nil {
		h.logger.Printf("list hardware: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := HardwareListData{
		PageData: PageData{
			Title: "Hardware", Active: "hardware", User: user,
			CSRFToken: GetCSRFToken(r), Flash: r.URL.Query().Get("flash"),
		},
		Configs: configs,
	}
	h.templates.RenderPage(w, "hardware_list", "base", data)
}

// NewForm renders the create hardware form.
func (h *Hardware) NewForm(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	projectID, _ := strconv.Atoi(r.PathValue("pid"))
	projects, _ := h.store.ListProjects()

	data := HardwareFormData{
		PageData: PageData{
			Title: "New Hardware Config", Active: "hardware", User: user, CSRFToken: GetCSRFToken(r),
		},
		ProjectID: projectID,
		Projects:  projects,
	}
	h.templates.RenderPage(w, "hardware_form", "base", data)
}

// Create handles hardware config creation.
func (h *Hardware) Create(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	projectID, _ := strconv.Atoi(r.FormValue("project_id"))
	if projectID == 0 {
		projectID, _ = strconv.Atoi(r.PathValue("pid"))
	}
	label := r.FormValue("label")
	machineID := r.FormValue("machine_id")
	cpu := r.FormValue("cpu")
	motherboard := r.FormValue("motherboard")
	diskSerial := r.FormValue("disk_serial")
	nicMac := r.FormValue("nic_mac")
	notes := r.FormValue("notes")

	if label == "" || projectID == 0 {
		projects, _ := h.store.ListProjects()
		data := HardwareFormData{
			PageData: PageData{
				Title: "New Hardware Config", Active: "hardware", User: user,
				CSRFToken: GetCSRFToken(r), Error: "Project and label are required",
			},
			ProjectID: projectID,
			Projects:  projects,
		}
		w.WriteHeader(http.StatusBadRequest)
		h.templates.RenderPage(w, "hardware_form", "base", data)
		return
	}

	hw, err := h.store.CreateHardwareConfig(projectID, label, machineID, cpu, motherboard, diskSerial, nicMac, notes)
	if err != nil {
		projects, _ := h.store.ListProjects()
		data := HardwareFormData{
			PageData: PageData{
				Title: "New Hardware Config", Active: "hardware", User: user,
				CSRFToken: GetCSRFToken(r), Error: fmt.Sprintf("Failed: %v", err),
			},
			ProjectID: projectID,
			Projects:  projects,
		}
		w.WriteHeader(http.StatusBadRequest)
		h.templates.RenderPage(w, "hardware_form", "base", data)
		return
	}

	h.store.LogAction(user.ID, user.Username, "hardware.create", "hardware", hw.ID,
		fmt.Sprintf(`{"label":%q,"project_id":%d}`, label, projectID), ClientIP(r))

	http.Redirect(w, r, fmt.Sprintf("/projects/%d?flash=Hardware+config+created", projectID), http.StatusSeeOther)
}

// EditForm renders the edit hardware form.
func (h *Hardware) EditForm(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	hw, err := h.store.GetHardwareConfig(id)
	if err != nil {
		http.Error(w, "Hardware config not found", http.StatusNotFound)
		return
	}

	projects, _ := h.store.ListProjects()
	data := HardwareFormData{
		PageData: PageData{
			Title: "Edit Hardware Config", Active: "hardware", User: user, CSRFToken: GetCSRFToken(r),
		},
		ProjectID:  hw.ProjectID,
		Projects:   projects,
		EditConfig: hw,
		IsEdit:     true,
	}
	h.templates.RenderPage(w, "hardware_form", "base", data)
}

// Update handles hardware config updates.
func (h *Hardware) Update(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	hw, err := h.store.GetHardwareConfig(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	label := r.FormValue("label")
	machineID := r.FormValue("machine_id")
	cpu := r.FormValue("cpu")
	motherboard := r.FormValue("motherboard")
	diskSerial := r.FormValue("disk_serial")
	nicMac := r.FormValue("nic_mac")
	notes := r.FormValue("notes")

	if err := h.store.UpdateHardwareConfig(id, label, machineID, cpu, motherboard, diskSerial, nicMac, notes); err != nil {
		h.logger.Printf("update hardware %d: %v", id, err)
		http.Error(w, "Failed to update", http.StatusInternalServerError)
		return
	}

	h.store.LogAction(user.ID, user.Username, "hardware.update", "hardware", id,
		fmt.Sprintf(`{"label":%q}`, label), ClientIP(r))

	http.Redirect(w, r, fmt.Sprintf("/projects/%d?flash=Hardware+config+updated", hw.ProjectID), http.StatusSeeOther)
}

// Delete handles hardware config deletion.
func (h *Hardware) Delete(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)
	id, _ := strconv.Atoi(r.PathValue("id"))

	hw, err := h.store.GetHardwareConfig(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if err := h.store.DeleteHardwareConfig(id); err != nil {
		http.Error(w, "Failed to delete", http.StatusInternalServerError)
		return
	}

	h.store.LogAction(user.ID, user.Username, "hardware.delete", "hardware", id, "", ClientIP(r))
	http.Redirect(w, r, fmt.Sprintf("/projects/%d?flash=Hardware+config+deleted", hw.ProjectID), http.StatusSeeOther)
}

// UploadJSON handles hardware-info.json upload, returns form data as JSON.
func (h *Hardware) UploadJSON(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("hardware_json")
	if err != nil {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}

	// Parse both nested and flat formats (same as license-gen).
	var hwJSON struct {
		Components *struct {
			MachineID   string `json:"machine_id"`
			CPU         string `json:"cpu"`
			Motherboard string `json:"motherboard"`
			Disk        string `json:"disk"`
			NIC         string `json:"nic"`
		} `json:"components"`
		MachineID   string `json:"machine_id"`
		CPU         string `json:"cpu"`
		Motherboard string `json:"motherboard"`
		Disk        string `json:"disk"`
		NIC         string `json:"nic"`
	}

	if err := json.Unmarshal(data, &hwJSON); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	result := map[string]string{}
	if hwJSON.Components != nil {
		result["machine_id"] = hwJSON.Components.MachineID
		result["cpu"] = hwJSON.Components.CPU
		result["motherboard"] = hwJSON.Components.Motherboard
		result["disk_serial"] = hwJSON.Components.Disk
		result["nic_mac"] = hwJSON.Components.NIC
	} else {
		result["machine_id"] = hwJSON.MachineID
		result["cpu"] = hwJSON.CPU
		result["motherboard"] = hwJSON.Motherboard
		result["disk_serial"] = hwJSON.Disk
		result["nic_mac"] = hwJSON.NIC
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
