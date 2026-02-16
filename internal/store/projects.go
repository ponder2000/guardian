package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Project represents a customer/deployment project.
type Project struct {
	ID          int
	Name        string
	Description string
	Contact     string
	Notes       string
	IsActive    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CreateProject creates a new project.
func (s *Store) CreateProject(name, description, contact, notes string) (*Project, error) {
	res, err := s.DB.Exec(
		`INSERT INTO projects (name, description, contact, notes) VALUES (?, ?, ?, ?)`,
		name, description, contact, notes,
	)
	if err != nil {
		return nil, fmt.Errorf("insert project: %w", err)
	}
	id, _ := res.LastInsertId()
	return s.GetProject(int(id))
}

// GetProject returns a project by ID.
func (s *Store) GetProject(id int) (*Project, error) {
	p := &Project{}
	var isActive int
	var createdAt, updatedAt string
	err := s.DB.QueryRow(
		`SELECT id, name, description, contact, notes, is_active, created_at, updated_at FROM projects WHERE id = ?`, id,
	).Scan(&p.ID, &p.Name, &p.Description, &p.Contact, &p.Notes, &isActive, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("project not found")
	}
	if err != nil {
		return nil, err
	}
	p.IsActive = isActive == 1
	p.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	p.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
	return p, nil
}

// ListProjects returns all projects.
func (s *Store) ListProjects() ([]Project, error) {
	rows, err := s.DB.Query(
		`SELECT id, name, description, contact, notes, is_active, created_at, updated_at FROM projects ORDER BY name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProjects(rows)
}

// ListProjectsForUser returns projects accessible to a viewer user.
// Admins see all projects (call ListProjects instead).
func (s *Store) ListProjectsForUser(userID int) ([]Project, error) {
	rows, err := s.DB.Query(
		`SELECT p.id, p.name, p.description, p.contact, p.notes, p.is_active, p.created_at, p.updated_at
		 FROM projects p
		 JOIN user_project_access upa ON upa.project_id = p.id
		 WHERE upa.user_id = ?
		 ORDER BY p.name`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProjects(rows)
}

func scanProjects(rows *sql.Rows) ([]Project, error) {
	var projects []Project
	for rows.Next() {
		var p Project
		var isActive int
		var createdAt, updatedAt string
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Contact, &p.Notes, &isActive, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		p.IsActive = isActive == 1
		p.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		p.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
		projects = append(projects, p)
	}
	return projects, rows.Err()
}

// UpdateProject updates project fields.
func (s *Store) UpdateProject(id int, name, description, contact, notes string, isActive bool) error {
	active := 0
	if isActive {
		active = 1
	}
	_, err := s.DB.Exec(
		`UPDATE projects SET name=?, description=?, contact=?, notes=?, is_active=?, updated_at=datetime('now') WHERE id=?`,
		name, description, contact, notes, active, id,
	)
	return err
}

// DeleteProject removes a project and cascades to hardware and licenses.
func (s *Store) DeleteProject(id int) error {
	_, err := s.DB.Exec(`DELETE FROM projects WHERE id = ?`, id)
	return err
}
