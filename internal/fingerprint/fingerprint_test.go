package fingerprint

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/ponder2000/guardian/internal/crypto"
)

// ---------- helpers ----------

func mockHardwareInfo() *HardwareInfo {
	return &HardwareInfo{
		MachineID:   "abc123",
		CPU:         "Intel Xeon E5-2680 v4 x28",
		Motherboard: "SER-1234-MB",
		DiskSerial:  "WD-WMAZ1234",
		NICMac:      "aa:bb:cc:dd:ee:ff",
	}
}

func mockProviders(info *HardwareInfo) map[Component]Provider {
	return map[Component]Provider{
		CompMachineID:   func() (string, error) { return info.MachineID, nil },
		CompCPU:         func() (string, error) { return info.CPU, nil },
		CompMotherboard: func() (string, error) { return info.Motherboard, nil },
		CompDisk:        func() (string, error) { return info.DiskSerial, nil },
		CompNIC:         func() (string, error) { return info.NICMac, nil },
	}
}

// ---------- ComputeFingerprints ----------

func TestComputeFingerprints(t *testing.T) {
	info := mockHardwareInfo()
	salt := "test-salt"

	fp1 := ComputeFingerprints(info, salt)
	fp2 := ComputeFingerprints(info, salt)

	// Must produce a fingerprint for every component.
	for _, c := range AllComponents {
		v1, ok1 := fp1[c]
		v2, ok2 := fp2[c]
		if !ok1 || !ok2 {
			t.Fatalf("missing fingerprint for component %s", c)
		}
		if v1 != v2 {
			t.Errorf("fingerprints not deterministic for %s: %s != %s", c, v1, v2)
		}
		if v1 == "" {
			t.Errorf("fingerprint for %s is empty", c)
		}
	}

	// Verify the actual HMAC value for machine_id as a spot check.
	expectedMAC := crypto.HMACSHA256([]byte(info.MachineID), []byte(salt))
	expectedHex := hex.EncodeToString(expectedMAC)
	if fp1[CompMachineID] != expectedHex {
		t.Errorf("machine_id fingerprint mismatch: got %s, want %s", fp1[CompMachineID], expectedHex)
	}
}

func TestComputeFingerprintsDifferentSalt(t *testing.T) {
	info := mockHardwareInfo()

	fp1 := ComputeFingerprints(info, "salt-one")
	fp2 := ComputeFingerprints(info, "salt-two")

	for _, c := range AllComponents {
		if fp1[c] == fp2[c] {
			t.Errorf("fingerprint for %s should differ with different salts, both are %s", c, fp1[c])
		}
	}
}

// ---------- MatchThreshold ----------

func TestMatchThreshold_AllMatch(t *testing.T) {
	info := mockHardwareInfo()
	salt := "s"
	fp := ComputeFingerprints(info, salt)

	matched, total, pass := MatchThreshold(fp, fp, 3)
	if matched != 5 {
		t.Errorf("expected 5 matched, got %d", matched)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if !pass {
		t.Error("expected pass=true for 5/5 with threshold 3")
	}
}

func TestMatchThreshold_PartialMatch(t *testing.T) {
	info := mockHardwareInfo()
	salt := "s"
	expected := ComputeFingerprints(info, salt)

	// Create an actual set where 3 out of 5 match.
	actual := make(Fingerprints, len(AllComponents))
	for c, v := range expected {
		actual[c] = v
	}
	// Tamper with 2 components.
	actual[CompDisk] = "aaaa"
	actual[CompNIC] = "bbbb"

	matched, total, pass := MatchThreshold(expected, actual, 3)
	if matched != 3 {
		t.Errorf("expected 3 matched, got %d", matched)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if !pass {
		t.Error("expected pass=true for 3/5 with threshold 3")
	}
}

func TestMatchThreshold_BelowThreshold(t *testing.T) {
	info := mockHardwareInfo()
	salt := "s"
	expected := ComputeFingerprints(info, salt)

	actual := make(Fingerprints, len(AllComponents))
	for c, v := range expected {
		actual[c] = v
	}
	// Tamper with 3 components so only 2 match.
	actual[CompMotherboard] = "xxxx"
	actual[CompDisk] = "yyyy"
	actual[CompNIC] = "zzzz"

	matched, total, pass := MatchThreshold(expected, actual, 3)
	if matched != 2 {
		t.Errorf("expected 2 matched, got %d", matched)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if pass {
		t.Error("expected pass=false for 2/5 with threshold 3")
	}
}

func TestMatchThreshold_NoMatch(t *testing.T) {
	info := mockHardwareInfo()
	salt := "s"
	expected := ComputeFingerprints(info, salt)

	// Every value different.
	actual := make(Fingerprints, len(AllComponents))
	for _, c := range AllComponents {
		actual[c] = "no-match"
	}

	matched, total, pass := MatchThreshold(expected, actual, 3)
	if matched != 0 {
		t.Errorf("expected 0 matched, got %d", matched)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if pass {
		t.Error("expected pass=false for 0/5 with threshold 3")
	}
}

// ---------- CollectWithProviders ----------

func TestCollectWithProviders(t *testing.T) {
	want := mockHardwareInfo()
	providers := mockProviders(want)

	got, err := CollectWithProviders(providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.MachineID != want.MachineID {
		t.Errorf("MachineID: got %q, want %q", got.MachineID, want.MachineID)
	}
	if got.CPU != want.CPU {
		t.Errorf("CPU: got %q, want %q", got.CPU, want.CPU)
	}
	if got.Motherboard != want.Motherboard {
		t.Errorf("Motherboard: got %q, want %q", got.Motherboard, want.Motherboard)
	}
	if got.DiskSerial != want.DiskSerial {
		t.Errorf("DiskSerial: got %q, want %q", got.DiskSerial, want.DiskSerial)
	}
	if got.NICMac != want.NICMac {
		t.Errorf("NICMac: got %q, want %q", got.NICMac, want.NICMac)
	}
}

func TestCollectWithProviders_MissingProvider(t *testing.T) {
	// Omit the NIC provider; should return an error.
	providers := map[Component]Provider{
		CompMachineID:   func() (string, error) { return "id", nil },
		CompCPU:         func() (string, error) { return "cpu", nil },
		CompMotherboard: func() (string, error) { return "mb", nil },
		CompDisk:        func() (string, error) { return "disk", nil },
		// CompNIC intentionally missing
	}

	_, err := CollectWithProviders(providers)
	if err == nil {
		t.Fatal("expected error when provider is missing")
	}
	if !strings.Contains(err.Error(), string(CompNIC)) {
		t.Errorf("error should mention %s, got: %v", CompNIC, err)
	}
}

func TestCollectWithProviders_ProviderError(t *testing.T) {
	providers := map[Component]Provider{
		CompMachineID:   func() (string, error) { return "", fmt.Errorf("read fail") },
		CompCPU:         func() (string, error) { return "cpu", nil },
		CompMotherboard: func() (string, error) { return "mb", nil },
		CompDisk:        func() (string, error) { return "disk", nil },
		CompNIC:         func() (string, error) { return "nic", nil },
	}

	_, err := CollectWithProviders(providers)
	if err == nil {
		t.Fatal("expected error when provider returns error")
	}
	if !strings.Contains(err.Error(), "read fail") {
		t.Errorf("error should propagate provider message, got: %v", err)
	}
}

// ---------- ComputeComposite ----------

func TestComputeComposite(t *testing.T) {
	info := mockHardwareInfo()
	salt := "composite-salt"

	c1 := ComputeComposite(info, salt)
	c2 := ComputeComposite(info, salt)

	if c1 != c2 {
		t.Errorf("composite fingerprint not deterministic: %s != %s", c1, c2)
	}
	if c1 == "" {
		t.Error("composite fingerprint is empty")
	}

	// Manually build the expected value.
	var combined strings.Builder
	combined.WriteString(info.MachineID)
	combined.WriteString(info.CPU)
	combined.WriteString(info.Motherboard)
	combined.WriteString(info.DiskSerial)
	combined.WriteString(info.NICMac)

	expectedMAC := crypto.HMACSHA256([]byte(combined.String()), []byte(salt))
	expectedHex := hex.EncodeToString(expectedMAC)

	if c1 != expectedHex {
		t.Errorf("composite fingerprint mismatch: got %s, want %s", c1, expectedHex)
	}
}

func TestComputeComposite_DifferentSalt(t *testing.T) {
	info := mockHardwareInfo()

	c1 := ComputeComposite(info, "salt-a")
	c2 := ComputeComposite(info, "salt-b")

	if c1 == c2 {
		t.Errorf("composite fingerprint should differ with different salts, both are %s", c1)
	}
}

func TestComputeComposite_DifferentInfo(t *testing.T) {
	salt := "same-salt"

	info1 := mockHardwareInfo()
	info2 := mockHardwareInfo()
	info2.MachineID = "different-id"

	c1 := ComputeComposite(info1, salt)
	c2 := ComputeComposite(info2, salt)

	if c1 == c2 {
		t.Error("composite fingerprint should differ when hardware info differs")
	}
}
