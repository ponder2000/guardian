package store

import (
	"fmt"
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

func TestKeyPairCRUD(t *testing.T) {
	s := testStore(t)

	// Create key pair.
	kp, err := s.CreateKeyPair("test-key", "aabbccdd", "11223344aabbccdd", "fp123")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if kp.Name != "test-key" || !kp.IsDefault {
		t.Fatalf("unexpected key: %+v", kp)
	}

	// First key should be default.
	def, err := s.GetDefaultKeyPair()
	if err != nil {
		t.Fatalf("get default: %v", err)
	}
	if def.ID != kp.ID {
		t.Fatal("first key should be default")
	}

	// Create second key.
	kp2, err := s.CreateKeyPair("test-key-2", "eeff0011", "55667788eeff0011", "fp456")
	if err != nil {
		t.Fatalf("create key 2: %v", err)
	}
	if kp2.IsDefault {
		t.Fatal("second key should not be default")
	}

	// List keys.
	keys, err := s.ListKeyPairs()
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	// Set default.
	if err := s.SetDefaultKeyPair(kp2.ID); err != nil {
		t.Fatalf("set default: %v", err)
	}
	def2, _ := s.GetDefaultKeyPair()
	if def2.ID != kp2.ID {
		t.Fatal("kp2 should now be default")
	}

	// Delete key.
	if err := s.DeleteKeyPair(kp.ID); err != nil {
		t.Fatalf("delete key: %v", err)
	}
	keys2, _ := s.ListKeyPairs()
	if len(keys2) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys2))
	}
}

func TestDuplicateKeyName(t *testing.T) {
	s := testStore(t)
	s.CreateKeyPair("dup-key", "aa", "bb", "fp")
	_, err := s.CreateKeyPair("dup-key", "cc", "dd", "fp2")
	if err == nil {
		t.Fatal("expected error for duplicate key name")
	}
}

func TestProjectCRUD(t *testing.T) {
	s := testStore(t)

	p, err := s.CreateProject("ACME Corp", "A test project", "john@acme.com", "notes")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	if p.Name != "ACME Corp" || !p.IsActive {
		t.Fatalf("unexpected project: %+v", p)
	}

	projects, _ := s.ListProjects()
	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}

	s.UpdateProject(p.ID, "ACME Updated", "desc", "contact", "notes", true)
	p2, _ := s.GetProject(p.ID)
	if p2.Name != "ACME Updated" {
		t.Fatalf("update didn't apply: %s", p2.Name)
	}

	s.DeleteProject(p.ID)
	_, err = s.GetProject(p.ID)
	if err == nil {
		t.Fatal("expected error for deleted project")
	}
}

func TestHardwareConfigCRUD(t *testing.T) {
	s := testStore(t)

	p, _ := s.CreateProject("HW Test", "", "", "")
	hw, err := s.CreateHardwareConfig(p.ID, "Server #1", "machine123", "Intel x8", "Board1", "disk-abc", "aa:bb:cc:dd:ee:ff", "test hw")
	if err != nil {
		t.Fatalf("create hw: %v", err)
	}
	if hw.Label != "Server #1" || hw.ProjectName != "HW Test" {
		t.Fatalf("unexpected hw: %+v", hw)
	}

	configs, _ := s.ListHardwareForProject(p.ID)
	if len(configs) != 1 {
		t.Fatalf("expected 1, got %d", len(configs))
	}

	s.UpdateHardwareConfig(hw.ID, "Server #1 Updated", "m2", "cpu2", "mb2", "d2", "n2", "n")
	hw2, _ := s.GetHardwareConfig(hw.ID)
	if hw2.Label != "Server #1 Updated" {
		t.Fatal("update didn't apply")
	}

	allHw, _ := s.ListHardwareConfigs()
	if len(allHw) != 1 {
		t.Fatalf("expected 1 in all, got %d", len(allHw))
	}

	s.DeleteHardwareConfig(hw.ID)
	_, err = s.GetHardwareConfig(hw.ID)
	if err == nil {
		t.Fatal("expected error for deleted hw")
	}
}

func TestAccessControl(t *testing.T) {
	s := testStore(t)

	u, _ := s.CreateUser("viewer1", "v@test.com", "pass", "viewer")
	p, _ := s.CreateProject("AccessProj", "", "", "")

	// No access initially.
	if s.HasAccess(u.ID, p.ID) {
		t.Fatal("should not have access")
	}

	viewerProjects, _ := s.ListProjectsForUser(u.ID)
	if len(viewerProjects) != 0 {
		t.Fatalf("expected 0 projects for viewer, got %d", len(viewerProjects))
	}

	// Grant.
	s.GrantAccess(u.ID, p.ID)
	if !s.HasAccess(u.ID, p.ID) {
		t.Fatal("should have access after grant")
	}

	viewerProjects, _ = s.ListProjectsForUser(u.ID)
	if len(viewerProjects) != 1 {
		t.Fatalf("expected 1 project for viewer, got %d", len(viewerProjects))
	}

	access, _ := s.ListAllAccess()
	if len(access) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(access))
	}

	// Revoke.
	s.RevokeAccess(u.ID, p.ID)
	if s.HasAccess(u.ID, p.ID) {
		t.Fatal("should not have access after revoke")
	}

	// Double grant is idempotent.
	s.GrantAccess(u.ID, p.ID)
	s.GrantAccess(u.ID, p.ID)
	access2, _ := s.ListAllAccess()
	if len(access2) != 1 {
		t.Fatalf("expected 1 after double grant, got %d", len(access2))
	}
}

func TestHardwareCascadeOnProjectDelete(t *testing.T) {
	s := testStore(t)

	p, _ := s.CreateProject("Cascade", "", "", "")
	s.CreateHardwareConfig(p.ID, "HW1", "", "", "", "", "", "")
	s.CreateHardwareConfig(p.ID, "HW2", "", "", "", "", "", "")

	configs, _ := s.ListHardwareForProject(p.ID)
	if len(configs) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(configs))
	}

	s.DeleteProject(p.ID)

	configs2, _ := s.ListHardwareForProject(p.ID)
	if len(configs2) != 0 {
		t.Fatalf("expected 0 after cascade, got %d", len(configs2))
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

func TestLicenseCRUD(t *testing.T) {
	s := testStore(t)

	// Set up required foreign key records.
	p, _ := s.CreateProject("License Proj", "", "", "")
	hw, _ := s.CreateHardwareConfig(p.ID, "Server1", "machine1", "cpu1", "mb1", "disk1", "aa:bb:cc", "")
	kp, _ := s.CreateKeyPair("lic-key", "aabb", "ccdd", "fp1")

	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(365 * 24 * time.Hour)

	rec := &LicenseRecord{
		LicenseID:        "LIC-TEST001",
		ProjectID:        p.ID,
		HardwareConfigID: hw.ID,
		KeyPairID:        kp.ID,
		IssuedTo:         "Test Customer",
		IssuedAt:         now,
		ExpiresAt:        expires,
		MatchThreshold:   3,
		ModulesJSON:      `{"analytics":{"enabled":true}}`,
		GlobalLimitsJSON: `{}`,
		LicenseFileData:  "GUARDIAN-LICENSE-V1\nPAYLOAD: test\nSIGNATURE: test\nSIGNER: test",
		Salt:             "abc123",
		Version:          1,
		Notes:            "test license",
	}

	// Create.
	created, err := s.CreateLicenseRecord(rec)
	if err != nil {
		t.Fatalf("create license: %v", err)
	}
	if created.LicenseID != "LIC-TEST001" || created.IssuedTo != "Test Customer" {
		t.Fatalf("unexpected license: %+v", created)
	}
	if created.ProjectName != "License Proj" || created.HardwareLabel != "Server1" || created.KeyName != "lic-key" {
		t.Fatalf("joined fields wrong: project=%q hw=%q key=%q", created.ProjectName, created.HardwareLabel, created.KeyName)
	}

	// Get by ID.
	got, err := s.GetLicenseRecord(created.ID)
	if err != nil {
		t.Fatalf("get license: %v", err)
	}
	if got.LicenseID != "LIC-TEST001" || got.MatchThreshold != 3 {
		t.Fatalf("get returned wrong data: %+v", got)
	}

	// Get by license ID.
	got2, err := s.GetLicenseRecordByLicenseID("LIC-TEST001")
	if err != nil {
		t.Fatalf("get by license_id: %v", err)
	}
	if got2.ID != created.ID {
		t.Fatal("get by license_id returned different record")
	}

	// List all.
	all, err := s.ListLicenseRecords()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 license, got %d", len(all))
	}

	// List for project.
	projLics, err := s.ListLicensesForProject(p.ID)
	if err != nil {
		t.Fatalf("list for project: %v", err)
	}
	if len(projLics) != 1 {
		t.Fatalf("expected 1 project license, got %d", len(projLics))
	}

	// Update license file data.
	newExpires := expires.Add(30 * 24 * time.Hour)
	err = s.UpdateLicenseFileData(created.ID, "new-file-data", `{"mod1":{}}`, `{"limit":1}`, newExpires, 4)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	updated, _ := s.GetLicenseRecord(created.ID)
	if updated.LicenseFileData != "new-file-data" || updated.MatchThreshold != 4 {
		t.Fatalf("update didn't apply: data=%q threshold=%d", updated.LicenseFileData, updated.MatchThreshold)
	}
	if updated.ModulesJSON != `{"mod1":{}}` {
		t.Fatalf("modules not updated: %s", updated.ModulesJSON)
	}

	// Delete.
	if err := s.DeleteLicenseRecord(created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err = s.GetLicenseRecord(created.ID)
	if err == nil {
		t.Fatal("expected error for deleted license")
	}
}

func TestLicenseNotFound(t *testing.T) {
	s := testStore(t)

	_, err := s.GetLicenseRecord(999)
	if err == nil {
		t.Fatal("expected error for nonexistent license")
	}

	_, err = s.GetLicenseRecordByLicenseID("NOPE")
	if err == nil {
		t.Fatal("expected error for nonexistent license_id")
	}
}

func TestMultipleLicensesForProject(t *testing.T) {
	s := testStore(t)

	p, _ := s.CreateProject("Multi Lic", "", "", "")
	hw1, _ := s.CreateHardwareConfig(p.ID, "HW-A", "", "", "", "", "", "")
	hw2, _ := s.CreateHardwareConfig(p.ID, "HW-B", "", "", "", "", "", "")
	kp, _ := s.CreateKeyPair("multi-key", "aa", "bb", "fp")

	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(365 * 24 * time.Hour)

	for i, hw := range []int{hw1.ID, hw2.ID} {
		rec := &LicenseRecord{
			LicenseID:        fmt.Sprintf("LIC-MULTI%d", i),
			ProjectID:        p.ID,
			HardwareConfigID: hw,
			KeyPairID:        kp.ID,
			IssuedTo:         "Customer",
			IssuedAt:         now,
			ExpiresAt:        expires,
			MatchThreshold:   3,
			ModulesJSON:      "{}",
			GlobalLimitsJSON: "{}",
			LicenseFileData:  "test",
			Salt:             "salt",
			Version:          1,
		}
		if _, err := s.CreateLicenseRecord(rec); err != nil {
			t.Fatalf("create license %d: %v", i, err)
		}
	}

	lics, _ := s.ListLicensesForProject(p.ID)
	if len(lics) != 2 {
		t.Fatalf("expected 2, got %d", len(lics))
	}

	// Other project should have 0.
	p2, _ := s.CreateProject("Empty Proj", "", "", "")
	lics2, _ := s.ListLicensesForProject(p2.ID)
	if len(lics2) != 0 {
		t.Fatalf("expected 0, got %d", len(lics2))
	}
}
