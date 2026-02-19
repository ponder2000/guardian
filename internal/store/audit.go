package store

import (
	"time"
)

// AuditLog represents an audit log entry.
type AuditLog struct {
	ID         int
	UserID     *int
	Username   string
	Action     string
	EntityType string
	EntityID   *int
	Details    string
	IPAddress  string
	CreatedAt  time.Time
}

// AuditFilter specifies query filters for audit logs.
type AuditFilter struct {
	Username   string
	Action     string
	EntityType string
	Limit      int
	Offset     int
}

// LogAction records an audit log entry.
// A userID of 0 is stored as NULL (e.g. for failed login attempts by unknown users).
func (s *Store) LogAction(userID int, username, action, entityType string, entityID int, details, ip string) error {
	var uid interface{}
	if userID != 0 {
		uid = userID
	}
	_, err := s.DB.Exec(
		`INSERT INTO audit_logs (user_id, username, action, entity_type, entity_id, details, ip_address)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		uid, username, action, entityType, entityID, details, ip,
	)
	return err
}

// ListAuditLogs returns audit logs with optional filtering and pagination.
func (s *Store) ListAuditLogs(filter AuditFilter) ([]AuditLog, int, error) {
	where := "1=1"
	args := []interface{}{}

	if filter.Username != "" {
		where += " AND username LIKE ?"
		args = append(args, "%"+filter.Username+"%")
	}
	if filter.Action != "" {
		where += " AND action LIKE ?"
		args = append(args, "%"+filter.Action+"%")
	}
	if filter.EntityType != "" {
		where += " AND entity_type = ?"
		args = append(args, filter.EntityType)
	}

	// Count total.
	var total int
	err := s.DB.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE "+where, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}

	query := "SELECT id, user_id, username, action, entity_type, entity_id, details, ip_address, created_at FROM audit_logs WHERE " + where + " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, filter.Offset)

	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		var userID, entityID *int
		var createdAt string
		if err := rows.Scan(&l.ID, &userID, &l.Username, &l.Action, &l.EntityType, &entityID, &l.Details, &l.IPAddress, &createdAt); err != nil {
			return nil, 0, err
		}
		l.UserID = userID
		l.EntityID = entityID
		l.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		logs = append(logs, l)
	}
	return logs, total, rows.Err()
}
