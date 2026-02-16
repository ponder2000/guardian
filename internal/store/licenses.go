package store

import (
	"database/sql"
	"fmt"
	"time"
)

// LicenseRecord represents a license stored in the database.
type LicenseRecord struct {
	ID               int
	LicenseID        string
	ProjectID        int
	HardwareConfigID int
	KeyPairID        int
	IssuedTo         string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	MatchThreshold   int
	ModulesJSON      string
	GlobalLimitsJSON string
	LicenseFileData  string
	Salt             string
	Version          int
	Notes            string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	// Joined fields.
	ProjectName string
	HardwareLabel string
	KeyName       string
}

// CreateLicenseRecord stores a new license record.
func (s *Store) CreateLicenseRecord(rec *LicenseRecord) (*LicenseRecord, error) {
	res, err := s.DB.Exec(
		`INSERT INTO licenses (license_id, project_id, hardware_config_id, key_pair_id, issued_to, issued_at, expires_at,
		 match_threshold, modules_json, global_limits_json, license_file_data, salt, version, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.LicenseID, rec.ProjectID, rec.HardwareConfigID, rec.KeyPairID, rec.IssuedTo,
		rec.IssuedAt.Format("2006-01-02 15:04:05"), rec.ExpiresAt.Format("2006-01-02 15:04:05"),
		rec.MatchThreshold, rec.ModulesJSON, rec.GlobalLimitsJSON, rec.LicenseFileData,
		rec.Salt, rec.Version, rec.Notes,
	)
	if err != nil {
		return nil, fmt.Errorf("insert license: %w", err)
	}
	id, _ := res.LastInsertId()
	return s.GetLicenseRecord(int(id))
}

// GetLicenseRecord returns a license record by ID.
func (s *Store) GetLicenseRecord(id int) (*LicenseRecord, error) {
	r := &LicenseRecord{}
	var issuedAt, expiresAt, createdAt, updatedAt string
	err := s.DB.QueryRow(
		`SELECT l.id, l.license_id, l.project_id, l.hardware_config_id, l.key_pair_id,
		 l.issued_to, l.issued_at, l.expires_at, l.match_threshold, l.modules_json,
		 l.global_limits_json, l.license_file_data, l.salt, l.version, l.notes,
		 l.created_at, l.updated_at, p.name, h.label, k.name
		 FROM licenses l
		 JOIN projects p ON p.id = l.project_id
		 JOIN hardware_configs h ON h.id = l.hardware_config_id
		 JOIN key_pairs k ON k.id = l.key_pair_id
		 WHERE l.id = ?`, id,
	).Scan(&r.ID, &r.LicenseID, &r.ProjectID, &r.HardwareConfigID, &r.KeyPairID,
		&r.IssuedTo, &issuedAt, &expiresAt, &r.MatchThreshold, &r.ModulesJSON,
		&r.GlobalLimitsJSON, &r.LicenseFileData, &r.Salt, &r.Version, &r.Notes,
		&createdAt, &updatedAt, &r.ProjectName, &r.HardwareLabel, &r.KeyName)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("license not found")
	}
	if err != nil {
		return nil, err
	}
	r.IssuedAt, _ = time.Parse("2006-01-02 15:04:05", issuedAt)
	r.ExpiresAt, _ = time.Parse("2006-01-02 15:04:05", expiresAt)
	r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	r.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
	return r, nil
}

// GetLicenseRecordByLicenseID returns a license record by its license_id field.
func (s *Store) GetLicenseRecordByLicenseID(licenseID string) (*LicenseRecord, error) {
	var id int
	err := s.DB.QueryRow(`SELECT id FROM licenses WHERE license_id = ?`, licenseID).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("license not found")
	}
	if err != nil {
		return nil, err
	}
	return s.GetLicenseRecord(id)
}

// ListLicenseRecords returns all license records.
func (s *Store) ListLicenseRecords() ([]LicenseRecord, error) {
	rows, err := s.DB.Query(
		`SELECT l.id, l.license_id, l.project_id, l.hardware_config_id, l.key_pair_id,
		 l.issued_to, l.issued_at, l.expires_at, l.match_threshold, l.modules_json,
		 l.global_limits_json, l.license_file_data, l.salt, l.version, l.notes,
		 l.created_at, l.updated_at, p.name, h.label, k.name
		 FROM licenses l
		 JOIN projects p ON p.id = l.project_id
		 JOIN hardware_configs h ON h.id = l.hardware_config_id
		 JOIN key_pairs k ON k.id = l.key_pair_id
		 ORDER BY l.id DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanLicenseRecords(rows)
}

// ListLicensesForProject returns licenses for a specific project.
func (s *Store) ListLicensesForProject(projectID int) ([]LicenseRecord, error) {
	rows, err := s.DB.Query(
		`SELECT l.id, l.license_id, l.project_id, l.hardware_config_id, l.key_pair_id,
		 l.issued_to, l.issued_at, l.expires_at, l.match_threshold, l.modules_json,
		 l.global_limits_json, l.license_file_data, l.salt, l.version, l.notes,
		 l.created_at, l.updated_at, p.name, h.label, k.name
		 FROM licenses l
		 JOIN projects p ON p.id = l.project_id
		 JOIN hardware_configs h ON h.id = l.hardware_config_id
		 JOIN key_pairs k ON k.id = l.key_pair_id
		 WHERE l.project_id = ?
		 ORDER BY l.id DESC`, projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanLicenseRecords(rows)
}

func scanLicenseRecords(rows *sql.Rows) ([]LicenseRecord, error) {
	var records []LicenseRecord
	for rows.Next() {
		var r LicenseRecord
		var issuedAt, expiresAt, createdAt, updatedAt string
		if err := rows.Scan(&r.ID, &r.LicenseID, &r.ProjectID, &r.HardwareConfigID, &r.KeyPairID,
			&r.IssuedTo, &issuedAt, &expiresAt, &r.MatchThreshold, &r.ModulesJSON,
			&r.GlobalLimitsJSON, &r.LicenseFileData, &r.Salt, &r.Version, &r.Notes,
			&createdAt, &updatedAt, &r.ProjectName, &r.HardwareLabel, &r.KeyName); err != nil {
			return nil, err
		}
		r.IssuedAt, _ = time.Parse("2006-01-02 15:04:05", issuedAt)
		r.ExpiresAt, _ = time.Parse("2006-01-02 15:04:05", expiresAt)
		r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		r.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
		records = append(records, r)
	}
	return records, rows.Err()
}

// UpdateLicenseFileData updates the license file content after modification.
func (s *Store) UpdateLicenseFileData(id int, fileData, modulesJSON, globalLimitsJSON string, expiresAt time.Time, matchThreshold int) error {
	_, err := s.DB.Exec(
		`UPDATE licenses SET license_file_data=?, modules_json=?, global_limits_json=?,
		 expires_at=?, match_threshold=?, updated_at=datetime('now') WHERE id=?`,
		fileData, modulesJSON, globalLimitsJSON, expiresAt.Format("2006-01-02 15:04:05"), matchThreshold, id,
	)
	return err
}

// DeleteLicenseRecord removes a license record.
func (s *Store) DeleteLicenseRecord(id int) error {
	_, err := s.DB.Exec(`DELETE FROM licenses WHERE id = ?`, id)
	return err
}
