package license

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ponder2000/guardian/internal/crypto"
	"github.com/ponder2000/guardian/internal/fingerprint"

	"crypto/ed25519"
)

const (
	FileHeader  = "GUARDIAN-LICENSE-V1"
	FieldPayload   = "PAYLOAD:"
	FieldSignature = "SIGNATURE:"
	FieldSigner    = "SIGNER:"
)

// License represents the decoded license payload.
type License struct {
	LicenseID string    `json:"license_id"`
	Version   int       `json:"version"`
	IssuedTo  string    `json:"issued_to"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`

	Hardware     HardwareSpec          `json:"hardware"`
	Modules      map[string]Module     `json:"modules"`
	GlobalLimits map[string]interface{} `json:"global_limits"`
}

// HardwareSpec defines the hardware fingerprint requirements.
type HardwareSpec struct {
	Salt           string                              `json:"salt"`
	Fingerprints   map[fingerprint.Component]string     `json:"fingerprints"`
	MatchThreshold int                                  `json:"match_threshold"`
}

// Module defines a licensed module's configuration.
type Module struct {
	Enabled  bool                   `json:"enabled"`
	Features []string               `json:"features"`
	Limits   map[string]interface{} `json:"limits"`
}

// SignedLicense represents a complete signed license file.
type SignedLicense struct {
	PayloadB64 string // base64-encoded JSON payload
	Signature  []byte // Ed25519 signature of the raw payload bytes
	SignerFP   string // fingerprint of the signing public key
	License    *License
}

// ParseFile parses a .license file content into a SignedLicense.
func ParseFile(data []byte) (*SignedLicense, error) {
	content := string(data)
	lines := strings.Split(strings.TrimSpace(content), "\n")

	if len(lines) < 4 {
		return nil, fmt.Errorf("license file too short")
	}

	if strings.TrimSpace(lines[0]) != FileHeader {
		return nil, fmt.Errorf("invalid license header: expected %q", FileHeader)
	}

	sl := &SignedLicense{}

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, FieldPayload):
			sl.PayloadB64 = strings.TrimSpace(strings.TrimPrefix(line, FieldPayload))
		case strings.HasPrefix(line, FieldSignature):
			sigHex := strings.TrimSpace(strings.TrimPrefix(line, FieldSignature))
			sig, err := base64.StdEncoding.DecodeString(sigHex)
			if err != nil {
				return nil, fmt.Errorf("decode signature: %w", err)
			}
			sl.Signature = sig
		case strings.HasPrefix(line, FieldSigner):
			sl.SignerFP = strings.TrimSpace(strings.TrimPrefix(line, FieldSigner))
		}
	}

	if sl.PayloadB64 == "" {
		return nil, fmt.Errorf("missing PAYLOAD field")
	}
	if sl.Signature == nil {
		return nil, fmt.Errorf("missing SIGNATURE field")
	}

	// Decode the payload
	payloadBytes, err := base64.StdEncoding.DecodeString(sl.PayloadB64)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var lic License
	if err := json.Unmarshal(payloadBytes, &lic); err != nil {
		return nil, fmt.Errorf("parse license JSON: %w", err)
	}
	sl.License = &lic

	return sl, nil
}

// Verify checks the Ed25519 signature of the license payload.
func (sl *SignedLicense) Verify(masterPub ed25519.PublicKey) error {
	payloadBytes, err := base64.StdEncoding.DecodeString(sl.PayloadB64)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	if !crypto.Verify(masterPub, payloadBytes, sl.Signature) {
		return fmt.Errorf("invalid license signature")
	}
	return nil
}

// CheckExpiry returns an error if the license has expired.
func (sl *SignedLicense) CheckExpiry() error {
	return CheckExpiryAt(sl.License, time.Now())
}

// CheckExpiryAt returns an error if the license has expired relative to the given time.
func CheckExpiryAt(lic *License, now time.Time) error {
	if now.After(lic.ExpiresAt) {
		return fmt.Errorf("license expired at %s", lic.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

// CheckHardware validates the hardware fingerprints against the license.
func (sl *SignedLicense) CheckHardware(hwInfo *fingerprint.HardwareInfo) (matched int, total int, err error) {
	actual := fingerprint.ComputeFingerprints(hwInfo, sl.License.Hardware.Salt)
	matched, total, pass := fingerprint.MatchThreshold(
		sl.License.Hardware.Fingerprints,
		actual,
		sl.License.Hardware.MatchThreshold,
	)
	if !pass {
		return matched, total, fmt.Errorf("hardware mismatch: %d/%d (threshold: %d)",
			matched, total, sl.License.Hardware.MatchThreshold)
	}
	return matched, total, nil
}

// GetModule returns a module's config, or error if not found or disabled.
func (sl *SignedLicense) GetModule(name string) (*Module, error) {
	mod, ok := sl.License.Modules[name]
	if !ok {
		return nil, fmt.Errorf("module %q not found in license", name)
	}
	if !mod.Enabled {
		return nil, fmt.Errorf("module %q is disabled", name)
	}
	return &mod, nil
}

// CreateSignedFile generates a .license file content from a license and signing key.
func CreateSignedFile(lic *License, masterPriv ed25519.PrivateKey, signerFingerprint string) ([]byte, error) {
	payloadBytes, err := json.Marshal(lic)
	if err != nil {
		return nil, fmt.Errorf("marshal license: %w", err)
	}

	payloadB64 := base64.StdEncoding.EncodeToString(payloadBytes)
	signature := ed25519.Sign(masterPriv, payloadBytes)
	sigB64 := base64.StdEncoding.EncodeToString(signature)

	content := fmt.Sprintf("%s\n%s %s\n%s %s\n%s %s\n",
		FileHeader,
		FieldPayload, payloadB64,
		FieldSignature, sigB64,
		FieldSigner, signerFingerprint,
	)

	return []byte(content), nil
}

// DaysUntilExpiry returns the number of days until the license expires.
func (sl *SignedLicense) DaysUntilExpiry() int {
	d := time.Until(sl.License.ExpiresAt)
	if d < 0 {
		return 0
	}
	return int(d.Hours() / 24)
}
