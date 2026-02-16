package store

import (
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrate(t *testing.T) {
	s := testStore(t)
	// Running migrate twice should be idempotent.
	if err := s.Migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestUserCRUD(t *testing.T) {
	s := testStore(t)

	// Create user.
	u, err := s.CreateUser("admin", "admin@test.com", "secret123", "admin")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if u.Username != "admin" || u.Role != "admin" || !u.IsActive {
		t.Fatalf("unexpected user: %+v", u)
	}

	// Verify password.
	if !VerifyPassword(u, "secret123") {
		t.Fatal("password should match")
	}
	if VerifyPassword(u, "wrong") {
		t.Fatal("wrong password should not match")
	}

	// Get by username.
	u2, err := s.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get by username: %v", err)
	}
	if u2.ID != u.ID {
		t.Fatalf("user IDs don't match: %d vs %d", u2.ID, u.ID)
	}

	// List users.
	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}

	// Update user.
	err = s.UpdateUser(u.ID, "admin2", "admin2@test.com", "viewer", true)
	if err != nil {
		t.Fatalf("update user: %v", err)
	}
	u3, _ := s.GetUser(u.ID)
	if u3.Username != "admin2" || u3.Role != "viewer" {
		t.Fatalf("update didn't apply: %+v", u3)
	}

	// Update password.
	err = s.UpdateUserPassword(u.ID, "newpass")
	if err != nil {
		t.Fatalf("update password: %v", err)
	}
	u4, _ := s.GetUser(u.ID)
	if !VerifyPassword(u4, "newpass") {
		t.Fatal("new password should match")
	}

	// Delete user.
	err = s.DeleteUser(u.ID)
	if err != nil {
		t.Fatalf("delete user: %v", err)
	}
	_, err = s.GetUser(u.ID)
	if err == nil {
		t.Fatal("expected error getting deleted user")
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := testStore(t)

	u, _ := s.CreateUser("sess_user", "sess@test.com", "pass", "admin")

	// Create session.
	sess, err := s.CreateSession(u.ID, "127.0.0.1", "TestAgent", 24*time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if sess.ID == "" || sess.UserID != u.ID {
		t.Fatalf("bad session: %+v", sess)
	}

	// Get session.
	gotSess, gotUser, err := s.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if gotSess.UserID != u.ID || gotUser.Username != "sess_user" {
		t.Fatalf("wrong session data: sess=%+v user=%+v", gotSess, gotUser)
	}

	// Nonexistent session.
	_, _, err = s.GetSession("bogus")
	if err == nil {
		t.Fatal("expected error for bogus session")
	}

	// Delete session.
	err = s.DeleteSession(sess.ID)
	if err != nil {
		t.Fatalf("delete session: %v", err)
	}
	_, _, err = s.GetSession(sess.ID)
	if err == nil {
		t.Fatal("expected error for deleted session")
	}
}

func TestExpiredSession(t *testing.T) {
	s := testStore(t)

	u, _ := s.CreateUser("exp_user", "exp@test.com", "pass", "admin")

	// Create already-expired session.
	sess, err := s.CreateSession(u.ID, "127.0.0.1", "TestAgent", -1*time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, _, err = s.GetSession(sess.ID)
	if err == nil {
		t.Fatal("expected error for expired session")
	}

	// Clean expired.
	cleaned, err := s.CleanExpiredSessions()
	if err != nil {
		t.Fatalf("clean: %v", err)
	}
	// The session was already deleted by GetSession, so cleaned may be 0.
	_ = cleaned
}

func TestDuplicateUser(t *testing.T) {
	s := testStore(t)

	_, err := s.CreateUser("dup", "dup@test.com", "pass", "admin")
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.CreateUser("dup", "dup2@test.com", "pass", "admin")
	if err == nil {
		t.Fatal("expected error for duplicate username")
	}
}

func TestAuditLog(t *testing.T) {
	s := testStore(t)

	u, _ := s.CreateUser("auditor", "audit@test.com", "pass", "admin")

	err := s.LogAction(u.ID, "auditor", "user.create", "user", 1, `{"username":"newguy"}`, "127.0.0.1")
	if err != nil {
		t.Fatalf("log action: %v", err)
	}

	err = s.LogAction(u.ID, "auditor", "project.create", "project", 1, `{}`, "127.0.0.1")
	if err != nil {
		t.Fatalf("log action: %v", err)
	}

	logs, total, err := s.ListAuditLogs(AuditFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if total != 2 || len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d (total=%d)", len(logs), total)
	}

	// Filter by action.
	logs, total, err = s.ListAuditLogs(AuditFilter{Action: "user", Limit: 50})
	if err != nil {
		t.Fatalf("filtered list: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected 1 filtered log, got %d", total)
	}
}

func TestUserCount(t *testing.T) {
	s := testStore(t)

	count, _ := s.UserCount()
	if count != 0 {
		t.Fatalf("expected 0, got %d", count)
	}

	s.CreateUser("a", "a@test.com", "p", "admin")
	s.CreateUser("b", "b@test.com", "p", "viewer")

	count, _ = s.UserCount()
	if count != 2 {
		t.Fatalf("expected 2, got %d", count)
	}
}

func TestDisabledUserSession(t *testing.T) {
	s := testStore(t)

	u, _ := s.CreateUser("disabled_user", "dis@test.com", "pass", "admin")
	sess, _ := s.CreateSession(u.ID, "127.0.0.1", "TestAgent", 24*time.Hour)

	// Disable the user.
	s.UpdateUser(u.ID, u.Username, u.Email, u.Role, false)

	// Session should fail because user is disabled.
	_, _, err := s.GetSession(sess.ID)
	if err == nil {
		t.Fatal("expected error for disabled user session")
	}
}
