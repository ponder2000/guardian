package store

import (
	"time"
)

// UserProjectAccess represents a user-project access grant.
type UserProjectAccess struct {
	ID          int
	UserID      int
	ProjectID   int
	GrantedAt   time.Time
	Username    string // joined
	ProjectName string // joined
}

// GrantAccess grants a user access to a project.
func (s *Store) GrantAccess(userID, projectID int) error {
	_, err := s.DB.Exec(
		`INSERT OR IGNORE INTO user_project_access (user_id, project_id) VALUES (?, ?)`,
		userID, projectID,
	)
	return err
}

// RevokeAccess revokes a user's access to a project.
func (s *Store) RevokeAccess(userID, projectID int) error {
	_, err := s.DB.Exec(
		`DELETE FROM user_project_access WHERE user_id = ? AND project_id = ?`,
		userID, projectID,
	)
	return err
}

// ListAllAccess returns all user-project access grants.
func (s *Store) ListAllAccess() ([]UserProjectAccess, error) {
	rows, err := s.DB.Query(
		`SELECT upa.id, upa.user_id, upa.project_id, upa.granted_at, u.username, p.name
		 FROM user_project_access upa
		 JOIN users u ON u.id = upa.user_id
		 JOIN projects p ON p.id = upa.project_id
		 ORDER BY u.username, p.name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var access []UserProjectAccess
	for rows.Next() {
		var a UserProjectAccess
		var grantedAt string
		if err := rows.Scan(&a.ID, &a.UserID, &a.ProjectID, &grantedAt, &a.Username, &a.ProjectName); err != nil {
			return nil, err
		}
		a.GrantedAt, _ = time.Parse("2006-01-02 15:04:05", grantedAt)
		access = append(access, a)
	}
	return access, rows.Err()
}

// HasAccess checks if a user has access to a project.
func (s *Store) HasAccess(userID, projectID int) bool {
	var count int
	s.DB.QueryRow(
		`SELECT COUNT(*) FROM user_project_access WHERE user_id = ? AND project_id = ?`,
		userID, projectID,
	).Scan(&count)
	return count > 0
}
