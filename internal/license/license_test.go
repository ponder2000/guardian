package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ponder2000/guardian/internal/fingerprint"
)

func makeTestLicense() *License {
	return &License{
		LicenseID: "LIC-TEST-001",
		Version:   1,
		IssuedTo:  "Test Corp",
		IssuedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Hardware: HardwareSpec{
			Salt:           "test-salt",
			MatchThreshold: 3,
			Fingerprints: map[fingerprint.Component]string{
				fingerprint.CompMachineID:   "fp_machine",
				fingerprint.CompCPU:         "fp_cpu",
				fingerprint.CompMotherboard: "fp_mobo",
				fingerprint.CompDisk:        "fp_disk",
				fingerprint.CompNIC:         "fp_nic",
			},
		},
		Modules: map[string]Module{
			"rdpms-core": {
				Enabled:  true,
				Features: []string{"realtime-alerts", "data-export"},
				Limits:   map[string]interface{}{"max_users": float64(50)},
			},
			"analytics": {
				Enabled:  false,
				Features: []string{},
				Limits:   map[string]interface{}{},
			},
		},
		GlobalLimits: map[string]interface{}{
			"max_total_users": float64(200),
		},
	}
}

func makeSignedLicense(t *testing.T) (*SignedLicense, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	lic := makeTestLicense()
	fileData, err := CreateSignedFile(lic, priv, "test-signer-fp")
	if err != nil {
		t.Fatalf("CreateSignedFile: %v", err)
	}

	sl, err := ParseFile(fileData)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	return sl, pub, priv
}

func TestCreateAndParseLicenseFile(t *testing.T) {
	sl, _, _ := makeSignedLicense(t)

	if sl.License.LicenseID != "LIC-TEST-001" {
		t.Errorf("LicenseID = %q, want %q", sl.License.LicenseID, "LIC-TEST-001")
	}
	if sl.License.IssuedTo != "Test Corp" {
		t.Errorf("IssuedTo = %q, want %q", sl.License.IssuedTo, "Test Corp")
	}
	if sl.SignerFP != "test-signer-fp" {
		t.Errorf("SignerFP = %q, want %q", sl.SignerFP, "test-signer-fp")
	}
}

func TestVerifyValidSignature(t *testing.T) {
	sl, pub, _ := makeSignedLicense(t)

	if err := sl.Verify(pub); err != nil {
		t.Errorf("Verify() error: %v", err)
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	sl, _, _ := makeSignedLicense(t)

	// Use a different key to verify
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := sl.Verify(otherPub); err == nil {
		t.Error("Verify() expected error for wrong public key")
	}
}

func TestVerifyTamperedPayload(t *testing.T) {
	sl, pub, _ := makeSignedLicense(t)

	// Tamper with the payload
	lic := makeTestLicense()
	lic.LicenseID = "LIC-TAMPERED"
	tamperedJSON, _ := json.Marshal(lic)
	sl.PayloadB64 = base64.StdEncoding.EncodeToString(tamperedJSON)

	if err := sl.Verify(pub); err == nil {
		t.Error("Verify() expected error for tampered payload")
	}
}

func TestCheckExpiryValid(t *testing.T) {
	lic := makeTestLicense()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if err := CheckExpiryAt(lic, now); err != nil {
		t.Errorf("CheckExpiryAt() error: %v", err)
	}
}

func TestCheckExpiryExpired(t *testing.T) {
	lic := makeTestLicense()
	now := time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := CheckExpiryAt(lic, now); err == nil {
		t.Error("CheckExpiryAt() expected error for expired license")
	}
}

func TestCheckExpiryExactBoundary(t *testing.T) {
	lic := makeTestLicense()
	// Exactly at expiry time - should be valid (not after)
	now := lic.ExpiresAt
	if err := CheckExpiryAt(lic, now); err != nil {
		t.Errorf("CheckExpiryAt() should pass at exact boundary: %v", err)
	}

	// One second after
	now = lic.ExpiresAt.Add(time.Second)
	if err := CheckExpiryAt(lic, now); err == nil {
		t.Error("CheckExpiryAt() should fail one second after expiry")
	}
}

func TestGetModuleEnabled(t *testing.T) {
	sl, _, _ := makeSignedLicense(t)

	mod, err := sl.GetModule("rdpms-core")
	if err != nil {
		t.Fatalf("GetModule() error: %v", err)
	}
	if !mod.Enabled {
		t.Error("module should be enabled")
	}
	if len(mod.Features) != 2 {
		t.Errorf("features count = %d, want 2", len(mod.Features))
	}
}

func TestGetModuleDisabled(t *testing.T) {
	sl, _, _ := makeSignedLicense(t)

	_, err := sl.GetModule("analytics")
	if err == nil {
		t.Error("GetModule() expected error for disabled module")
	}
}

func TestGetModuleNotFound(t *testing.T) {
	sl, _, _ := makeSignedLicense(t)

	_, err := sl.GetModule("nonexistent")
	if err == nil {
		t.Error("GetModule() expected error for nonexistent module")
	}
}

func TestDaysUntilExpiry(t *testing.T) {
	sl, _, _ := makeSignedLicense(t)
	days := sl.DaysUntilExpiry()
	// License expires 2027-01-01, current time varies, just check it's positive
	if days < 0 {
		t.Errorf("DaysUntilExpiry() = %d, want >= 0", days)
	}
}

func TestParseFileInvalidHeader(t *testing.T) {
	data := []byte("INVALID-HEADER\nPAYLOAD: abc\nSIGNATURE: def\nSIGNER: ghi\n")
	_, err := ParseFile(data)
	if err == nil {
		t.Error("ParseFile() expected error for invalid header")
	}
}

func TestParseFileTooShort(t *testing.T) {
	data := []byte("GUARDIAN-LICENSE-V1\n")
	_, err := ParseFile(data)
	if err == nil {
		t.Error("ParseFile() expected error for short file")
	}
}

func TestParseFileMissingPayload(t *testing.T) {
	data := []byte(fmt.Sprintf("%s\n%s %s\n%s %s\n",
		FileHeader,
		FieldSignature, base64.StdEncoding.EncodeToString([]byte("sig")),
		FieldSigner, "fp",
	))
	_, err := ParseFile(data)
	if err == nil {
		t.Error("ParseFile() expected error for missing payload")
	}
}

func TestParseFileMissingSignature(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(`{"license_id":"test"}`))
	data := []byte(fmt.Sprintf("%s\n%s %s\n%s %s\n",
		FileHeader,
		FieldPayload, payload,
		FieldSigner, "fp",
	))
	_, err := ParseFile(data)
	if err == nil {
		t.Error("ParseFile() expected error for missing signature")
	}
}

func TestRoundTripLicenseModules(t *testing.T) {
	sl, _, _ := makeSignedLicense(t)

	// Verify all modules are present
	if len(sl.License.Modules) != 2 {
		t.Errorf("module count = %d, want 2", len(sl.License.Modules))
	}

	rdpms := sl.License.Modules["rdpms-core"]
	if !rdpms.Enabled {
		t.Error("rdpms-core should be enabled")
	}
	if maxUsers, ok := rdpms.Limits["max_users"].(float64); !ok || maxUsers != 50 {
		t.Errorf("rdpms-core max_users = %v, want 50", rdpms.Limits["max_users"])
	}
}

func TestRoundTripGlobalLimits(t *testing.T) {
	sl, _, _ := makeSignedLicense(t)

	if maxUsers, ok := sl.License.GlobalLimits["max_total_users"].(float64); !ok || maxUsers != 200 {
		t.Errorf("max_total_users = %v, want 200", sl.License.GlobalLimits["max_total_users"])
	}
}
