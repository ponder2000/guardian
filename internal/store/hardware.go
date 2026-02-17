package store

import (
	"database/sql"
	"fmt"
	"time"
)

// HardwareConfig represents a hardware configuration linked to a project.
type HardwareConfig struct {
	ID          int
	ProjectID   int
	Label       string
	MachineID   string
	CPU         string
	Motherboard string
	DiskSerial  string
	NICMac      string
	Notes       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	// Joined fields (optional).
	ProjectName string
}

// CreateHardwareConfig creates a new hardware config.
func (s *Store) CreateHardwareConfig(projectID int, label, machineID, cpu, motherboard, diskSerial, nicMac, notes string) (*HardwareConfig, error) {
	res, err := s.DB.Exec(
		`INSERT INTO hardware_configs (project_id, label, machine_id, cpu, motherboard, disk_serial, nic_mac, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		projectID, label, machineID, cpu, motherboard, diskSerial, nicMac, notes,
	)
	if err != nil {
		return nil, fmt.Errorf("insert hardware config: %w", err)
	}
	id, _ := res.LastInsertId()
	return s.GetHardwareConfig(int(id))
}

// GetHardwareConfig returns a hardware config by ID.
func (s *Store) GetHardwareConfig(id int) (*HardwareConfig, error) {
	hw := &HardwareConfig{}
	var createdAt, updatedAt string
	err := s.DB.QueryRow(
		`SELECT h.id, h.project_id, h.label, h.machine_id, h.cpu, h.motherboard, h.disk_serial, h.nic_mac, h.notes, h.created_at, h.updated_at, p.name
		 FROM hardware_configs h JOIN projects p ON p.id = h.project_id WHERE h.id = ?`, id,
	).Scan(&hw.ID, &hw.ProjectID, &hw.Label, &hw.MachineID, &hw.CPU, &hw.Motherboard, &hw.DiskSerial, &hw.NICMac, &hw.Notes, &createdAt, &updatedAt, &hw.ProjectName)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("hardware config not found")
	}
	if err != nil {
		return nil, err
	}
	hw.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	hw.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
	return hw, nil
}

// ListHardwareConfigs returns all hardware configs with project names.
func (s *Store) ListHardwareConfigs() ([]HardwareConfig, error) {
	rows, err := s.DB.Query(
		`SELECT h.id, h.project_id, h.label, h.machine_id, h.cpu, h.motherboard, h.disk_serial, h.nic_mac, h.notes, h.created_at, h.updated_at, p.name
		 FROM hardware_configs h JOIN projects p ON p.id = h.project_id ORDER BY p.name, h.label`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHardwareConfigs(rows)
}

// ListHardwareForProject returns hardware configs for a specific project.
func (s *Store) ListHardwareForProject(projectID int) ([]HardwareConfig, error) {
	rows, err := s.DB.Query(
		`SELECT h.id, h.project_id, h.label, h.machine_id, h.cpu, h.motherboard, h.disk_serial, h.nic_mac, h.notes, h.created_at, h.updated_at, p.name
		 FROM hardware_configs h JOIN projects p ON p.id = h.project_id WHERE h.project_id = ? ORDER BY h.label`, projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHardwareConfigs(rows)
}

func scanHardwareConfigs(rows *sql.Rows) ([]HardwareConfig, error) {
	var configs []HardwareConfig
	for rows.Next() {
		var hw HardwareConfig
		var createdAt, updatedAt string
		if err := rows.Scan(&hw.ID, &hw.ProjectID, &hw.Label, &hw.MachineID, &hw.CPU, &hw.Motherboard, &hw.DiskSerial, &hw.NICMac, &hw.Notes, &createdAt, &updatedAt, &hw.ProjectName); err != nil {
			return nil, err
		}
		hw.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		hw.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
		configs = append(configs, hw)
	}
	return configs, rows.Err()
}

// UpdateHardwareConfig updates a hardware config.
func (s *Store) UpdateHardwareConfig(id int, label, machineID, cpu, motherboard, diskSerial, nicMac, notes string) error {
	_, err := s.DB.Exec(
		`UPDATE hardware_configs SET label=?, machine_id=?, cpu=?, motherboard=?, disk_serial=?, nic_mac=?, notes=?, updated_at=datetime('now') WHERE id=?`,
		label, machineID, cpu, motherboard, diskSerial, nicMac, notes, id,
	)
	return err
}

// DeleteHardwareConfig removes a hardware config.
func (s *Store) DeleteHardwareConfig(id int) error {
	_, err := s.DB.Exec(`DELETE FROM hardware_configs WHERE id = ?`, id)
	return err
}
