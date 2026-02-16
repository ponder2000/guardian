package store

import (
	"encoding/json"
	"fmt"
	"time"
)

// ExportData holds all data for a full database export.
type ExportData struct {
	ExportedAt time.Time              `json:"exported_at"`
	Version    int                    `json:"version"`
	Projects   []ProjectExport        `json:"projects"`
	Hardware   []HardwareExport       `json:"hardware_configs"`
	KeyPairs   []KeyPairExport        `json:"key_pairs"`
	Licenses   []LicenseExport        `json:"licenses"`
	Users      []UserExport           `json:"users"`
	Access     []AccessExport         `json:"access"`
}

// ProjectExport is the export format for a project.
type ProjectExport struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Contact     string `json:"contact"`
	Notes       string `json:"notes"`
	IsActive    bool   `json:"is_active"`
}

// HardwareExport is the export format for a hardware config.
type HardwareExport struct {
	ProjectName string `json:"project_name"`
	Label       string `json:"label"`
	MachineID   string `json:"machine_id"`
	CPU         string `json:"cpu"`
	Motherboard string `json:"motherboard"`
	DiskSerial  string `json:"disk_serial"`
	NICMac      string `json:"nic_mac"`
	Notes       string `json:"notes"`
}

// KeyPairExport is the export format for a key pair.
type KeyPairExport struct {
	Name          string `json:"name"`
	PublicKeyHex  string `json:"public_key_hex"`
	PrivateKeyHex string `json:"private_key_hex"`
	Fingerprint   string `json:"fingerprint"`
	IsDefault     bool   `json:"is_default"`
}

// LicenseExport is the export format for a license record.
type LicenseExport struct {
	LicenseID        string `json:"license_id"`
	ProjectName      string `json:"project_name"`
	HardwareLabel    string `json:"hardware_label"`
	KeyName          string `json:"key_name"`
	IssuedTo         string `json:"issued_to"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
	MatchThreshold   int    `json:"match_threshold"`
	ModulesJSON      string `json:"modules_json"`
	GlobalLimitsJSON string `json:"global_limits_json"`
	LicenseFileData  string `json:"license_file_data"`
	Salt             string `json:"salt"`
	Version          int    `json:"version"`
	Notes            string `json:"notes"`
}

// UserExport is the export format for a user.
type UserExport struct {
	Username     string `json:"username"`
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	Role         string `json:"role"`
	IsActive     bool   `json:"is_active"`
}

// AccessExport is the export format for user-project access.
type AccessExport struct {
	Username    string `json:"username"`
	ProjectName string `json:"project_name"`
}

// Export returns all database data in a portable format.
func (s *Store) Export() (*ExportData, error) {
	data := &ExportData{
		ExportedAt: time.Now().UTC(),
		Version:    1,
	}

	// Projects.
	projects, err := s.ListProjects()
	if err != nil {
		return nil, fmt.Errorf("export projects: %w", err)
	}
	for _, p := range projects {
		data.Projects = append(data.Projects, ProjectExport{
			Name: p.Name, Description: p.Description, Contact: p.Contact,
			Notes: p.Notes, IsActive: p.IsActive,
		})
	}

	// Hardware configs.
	hardware, err := s.ListHardwareConfigs()
	if err != nil {
		return nil, fmt.Errorf("export hardware: %w", err)
	}
	for _, h := range hardware {
		data.Hardware = append(data.Hardware, HardwareExport{
			ProjectName: h.ProjectName, Label: h.Label, MachineID: h.MachineID,
			CPU: h.CPU, Motherboard: h.Motherboard, DiskSerial: h.DiskSerial,
			NICMac: h.NICMac, Notes: h.Notes,
		})
	}

	// Key pairs.
	keys, err := s.ListKeyPairs()
	if err != nil {
		return nil, fmt.Errorf("export keys: %w", err)
	}
	for _, k := range keys {
		data.KeyPairs = append(data.KeyPairs, KeyPairExport{
			Name: k.Name, PublicKeyHex: k.PublicKeyHex, PrivateKeyHex: k.PrivateKeyHex,
			Fingerprint: k.Fingerprint, IsDefault: k.IsDefault,
		})
	}

	// Licenses.
	licenses, err := s.ListLicenseRecords()
	if err != nil {
		return nil, fmt.Errorf("export licenses: %w", err)
	}
	for _, l := range licenses {
		data.Licenses = append(data.Licenses, LicenseExport{
			LicenseID: l.LicenseID, ProjectName: l.ProjectName,
			HardwareLabel: l.HardwareLabel, KeyName: l.KeyName,
			IssuedTo: l.IssuedTo,
			IssuedAt: l.IssuedAt.Format("2006-01-02 15:04:05"),
			ExpiresAt: l.ExpiresAt.Format("2006-01-02 15:04:05"),
			MatchThreshold: l.MatchThreshold, ModulesJSON: l.ModulesJSON,
			GlobalLimitsJSON: l.GlobalLimitsJSON, LicenseFileData: l.LicenseFileData,
			Salt: l.Salt, Version: l.Version, Notes: l.Notes,
		})
	}

	// Users.
	users, err := s.ListUsers()
	if err != nil {
		return nil, fmt.Errorf("export users: %w", err)
	}
	for _, u := range users {
		data.Users = append(data.Users, UserExport{
			Username: u.Username, Email: u.Email, PasswordHash: u.PasswordHash,
			Role: u.Role, IsActive: u.IsActive,
		})
	}

	// Access.
	access, err := s.ListAllAccess()
	if err != nil {
		return nil, fmt.Errorf("export access: %w", err)
	}
	for _, a := range access {
		data.Access = append(data.Access, AccessExport{
			Username: a.Username, ProjectName: a.ProjectName,
		})
	}

	return data, nil
}

// Import loads exported data into the database. Existing data is NOT cleared.
// Records with conflicting unique keys are skipped.
func (s *Store) Import(jsonData []byte) (ImportResult, error) {
	var data ExportData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return ImportResult{}, fmt.Errorf("parse export data: %w", err)
	}

	var result ImportResult

	// Import projects.
	projectMap := make(map[string]int) // name -> id
	for _, p := range data.Projects {
		proj, err := s.CreateProject(p.Name, p.Description, p.Contact, p.Notes)
		if err != nil {
			result.Skipped++
			// Try to look up existing.
			existing, _ := s.getProjectByName(p.Name)
			if existing != nil {
				projectMap[p.Name] = existing.ID
			}
			continue
		}
		projectMap[p.Name] = proj.ID
		result.Projects++
	}

	// Import key pairs.
	keyMap := make(map[string]int) // name -> id
	for _, k := range data.KeyPairs {
		kp, err := s.CreateKeyPair(k.Name, k.PublicKeyHex, k.PrivateKeyHex, k.Fingerprint)
		if err != nil {
			result.Skipped++
			existing, _ := s.getKeyPairByName(k.Name)
			if existing != nil {
				keyMap[k.Name] = existing.ID
			}
			continue
		}
		if k.IsDefault {
			s.SetDefaultKeyPair(kp.ID)
		}
		keyMap[k.Name] = kp.ID
		result.Keys++
	}

	// Import hardware configs.
	hwMap := make(map[string]int) // "projectName:label" -> id
	for _, h := range data.Hardware {
		pid, ok := projectMap[h.ProjectName]
		if !ok {
			result.Skipped++
			continue
		}
		hw, err := s.CreateHardwareConfig(pid, h.Label, h.MachineID, h.CPU, h.Motherboard, h.DiskSerial, h.NICMac, h.Notes)
		if err != nil {
			result.Skipped++
			continue
		}
		hwMap[h.ProjectName+":"+h.Label] = hw.ID
		result.Hardware++
	}

	// Import licenses.
	for _, l := range data.Licenses {
		pid, ok := projectMap[l.ProjectName]
		if !ok {
			result.Skipped++
			continue
		}
		hwID, ok := hwMap[l.ProjectName+":"+l.HardwareLabel]
		if !ok {
			result.Skipped++
			continue
		}
		kpID, ok := keyMap[l.KeyName]
		if !ok {
			result.Skipped++
			continue
		}
		issuedAt, _ := time.Parse("2006-01-02 15:04:05", l.IssuedAt)
		expiresAt, _ := time.Parse("2006-01-02 15:04:05", l.ExpiresAt)
		rec := &LicenseRecord{
			LicenseID: l.LicenseID, ProjectID: pid, HardwareConfigID: hwID,
			KeyPairID: kpID, IssuedTo: l.IssuedTo, IssuedAt: issuedAt,
			ExpiresAt: expiresAt, MatchThreshold: l.MatchThreshold,
			ModulesJSON: l.ModulesJSON, GlobalLimitsJSON: l.GlobalLimitsJSON,
			LicenseFileData: l.LicenseFileData, Salt: l.Salt,
			Version: l.Version, Notes: l.Notes,
		}
		if _, err := s.CreateLicenseRecord(rec); err != nil {
			result.Skipped++
			continue
		}
		result.Licenses++
	}

	// Import users (skip if username already exists).
	userMap := make(map[string]int)
	for _, u := range data.Users {
		user, err := s.createUserWithHash(u.Username, u.Email, u.PasswordHash, u.Role, u.IsActive)
		if err != nil {
			result.Skipped++
			existing, _ := s.GetUserByUsername(u.Username)
			if existing != nil {
				userMap[u.Username] = existing.ID
			}
			continue
		}
		userMap[u.Username] = user.ID
		result.Users++
	}

	// Import access.
	for _, a := range data.Access {
		uid, ok := userMap[a.Username]
		if !ok {
			existing, _ := s.GetUserByUsername(a.Username)
			if existing != nil {
				uid = existing.ID
			} else {
				result.Skipped++
				continue
			}
		}
		pid, ok := projectMap[a.ProjectName]
		if !ok {
			result.Skipped++
			continue
		}
		s.GrantAccess(uid, pid)
		result.Access++
	}

	return result, nil
}

// ImportResult tracks what was imported.
type ImportResult struct {
	Projects int `json:"projects"`
	Hardware int `json:"hardware"`
	Keys     int `json:"keys"`
	Licenses int `json:"licenses"`
	Users    int `json:"users"`
	Access   int `json:"access"`
	Skipped  int `json:"skipped"`
}

// getProjectByName looks up a project by name.
func (s *Store) getProjectByName(name string) (*Project, error) {
	var id int
	err := s.DB.QueryRow(`SELECT id FROM projects WHERE name = ?`, name).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetProject(id)
}

// getKeyPairByName looks up a key pair by name.
func (s *Store) getKeyPairByName(name string) (*KeyPair, error) {
	var id int
	err := s.DB.QueryRow(`SELECT id FROM key_pairs WHERE name = ?`, name).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetKeyPair(id)
}

// createUserWithHash creates a user with a pre-computed password hash.
func (s *Store) createUserWithHash(username, email, passwordHash, role string, isActive bool) (*User, error) {
	active := 0
	if isActive {
		active = 1
	}
	res, err := s.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role, is_active) VALUES (?, ?, ?, ?, ?)`,
		username, email, passwordHash, role, active,
	)
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}
	id, _ := res.LastInsertId()
	return s.GetUser(int(id))
}
