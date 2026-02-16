package fingerprint

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ponder2000/guardian/internal/crypto"
)

// Component identifies a hardware component used in fingerprinting.
type Component string

const (
	CompMachineID   Component = "machine_id"
	CompCPU         Component = "cpu"
	CompMotherboard Component = "motherboard"
	CompDisk        Component = "disk"
	CompNIC         Component = "nic"
)

// AllComponents lists every component in a deterministic order.
var AllComponents = []Component{
	CompMachineID,
	CompCPU,
	CompMotherboard,
	CompDisk,
	CompNIC,
}

// HardwareInfo holds raw values collected from the running machine.
type HardwareInfo struct {
	MachineID   string
	CPU         string
	Motherboard string
	DiskSerial  string
	NICMac      string
}

// Fingerprints maps each component to its HMAC-SHA256 hex digest.
type Fingerprints map[Component]string

// Provider is a function that returns a single hardware value.
type Provider func() (string, error)

// ---------- individual collectors ----------

// MachineID reads /etc/machine-id and returns the trimmed contents.
func MachineID() (string, error) {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return "", fmt.Errorf("read machine-id: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// CPUInfo parses /proc/cpuinfo and returns a string like
// "Intel Xeon E5-2680 v4 x28" (model name x processor count).
func CPUInfo() (string, error) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", fmt.Errorf("read cpuinfo: %w", err)
	}

	var modelName string
	processorCount := 0

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "processor") {
			processorCount++
		}
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 && modelName == "" {
				modelName = strings.TrimSpace(parts[1])
			}
		}
	}

	if modelName == "" {
		modelName = "unknown"
	}
	if processorCount == 0 {
		processorCount = 1
	}

	return fmt.Sprintf("%s x%d", modelName, processorCount), nil
}

// dmiPlaceholders contains common BIOS placeholder values that should be
// treated as missing/unknown.
var dmiPlaceholders = []string{
	"default string",
	"to be filled by o.e.m.",
	"not specified",
	"not available",
	"none",
	"n/a",
	"unknown",
	"system serial number",
	"chassis serial number",
	"base board serial number",
}

// isDMIPlaceholder reports whether a DMI value is a known placeholder.
func isDMIPlaceholder(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	for _, p := range dmiPlaceholders {
		if lower == p {
			return true
		}
	}
	return false
}

// readDMIField tries to read a sysfs DMI field, returning "" if the file
// is missing, unreadable, empty, or contains a known placeholder value.
func readDMIField(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	val := strings.TrimSpace(string(data))
	if val == "" || isDMIPlaceholder(val) {
		return ""
	}
	return val
}

// MotherboardSerial reads the board identity from sysfs, trying several
// DMI fields in order of specificity. Falls back to "unknown" when none
// yield a usable value.
func MotherboardSerial() (string, error) {
	candidates := []string{
		"/sys/devices/virtual/dmi/id/board_serial",
		"/sys/devices/virtual/dmi/id/product_serial",
		"/sys/devices/virtual/dmi/id/board_name",
		"/sys/devices/virtual/dmi/id/product_name",
	}
	for _, path := range candidates {
		if val := readDMIField(path); val != "" {
			return val, nil
		}
	}
	return "unknown", nil
}

// DiskSerial tries to read the serial for common block devices including
// SCSI/SATA (sda), virtio (vda), NVMe (nvme0n1), and eMMC (mmcblk0).
// Falls back to "unknown" if none are found.
func DiskSerial() (string, error) {
	// Static candidates — covers the most common device names.
	candidates := []string{
		"/sys/block/sda/device/serial",
		"/sys/block/vda/device/serial",
		"/sys/block/nvme0n1/device/serial",
		"/sys/block/mmcblk0/device/serial",
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err == nil {
			serial := strings.TrimSpace(string(data))
			if serial != "" {
				return serial, nil
			}
		}
	}

	// Dynamic scan — look for any block device with a serial.
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return "unknown", nil
	}
	for _, entry := range entries {
		name := entry.Name()
		// Skip loopback and ram devices.
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			continue
		}
		path := filepath.Join("/sys/block", name, "device", "serial")
		data, err := os.ReadFile(path)
		if err == nil {
			serial := strings.TrimSpace(string(data))
			if serial != "" {
				return serial, nil
			}
		}
	}

	// Last resort: try the eMMC CID (unique per chip) for mmcblk devices.
	entries2, _ := os.ReadDir("/sys/block")
	for _, entry := range entries2 {
		name := entry.Name()
		if !strings.HasPrefix(name, "mmcblk") {
			continue
		}
		cidPath := filepath.Join("/sys/block", name, "device", "cid")
		data, err := os.ReadFile(cidPath)
		if err == nil {
			cid := strings.TrimSpace(string(data))
			if cid != "" {
				return cid, nil
			}
		}
	}

	return "unknown", nil
}

// NICMac returns the MAC address of the first non-loopback, non-docker
// network interface found under /sys/class/net/.
func NICMac() (string, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", fmt.Errorf("read net interfaces: %w", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") {
			continue
		}
		addrPath := filepath.Join("/sys/class/net", name, "address")
		data, err := os.ReadFile(addrPath)
		if err != nil {
			continue
		}
		mac := strings.TrimSpace(string(data))
		if mac != "" && mac != "00:00:00:00:00:00" {
			return mac, nil
		}
	}

	return "", fmt.Errorf("no suitable network interface found")
}

// ---------- collection ----------

// Collect gathers hardware info from the running system using the real
// filesystem-based providers.
func Collect() (*HardwareInfo, error) {
	providers := map[Component]Provider{
		CompMachineID:   MachineID,
		CompCPU:         CPUInfo,
		CompMotherboard: MotherboardSerial,
		CompDisk:        DiskSerial,
		CompNIC:         NICMac,
	}
	return CollectWithProviders(providers)
}

// CollectWithProviders gathers hardware info using the supplied provider
// functions, making it easy to inject fakes for testing.
func CollectWithProviders(providers map[Component]Provider) (*HardwareInfo, error) {
	info := &HardwareInfo{}

	get := func(c Component) (string, error) {
		p, ok := providers[c]
		if !ok {
			return "", fmt.Errorf("no provider for component %s", c)
		}
		return p()
	}

	var err error

	info.MachineID, err = get(CompMachineID)
	if err != nil {
		return nil, fmt.Errorf("collect %s: %w", CompMachineID, err)
	}

	info.CPU, err = get(CompCPU)
	if err != nil {
		return nil, fmt.Errorf("collect %s: %w", CompCPU, err)
	}

	info.Motherboard, err = get(CompMotherboard)
	if err != nil {
		return nil, fmt.Errorf("collect %s: %w", CompMotherboard, err)
	}

	info.DiskSerial, err = get(CompDisk)
	if err != nil {
		return nil, fmt.Errorf("collect %s: %w", CompDisk, err)
	}

	info.NICMac, err = get(CompNIC)
	if err != nil {
		return nil, fmt.Errorf("collect %s: %w", CompNIC, err)
	}

	return info, nil
}

// ---------- fingerprinting ----------

// componentValue returns the raw string for a given component from HardwareInfo.
func componentValue(info *HardwareInfo, c Component) string {
	switch c {
	case CompMachineID:
		return info.MachineID
	case CompCPU:
		return info.CPU
	case CompMotherboard:
		return info.Motherboard
	case CompDisk:
		return info.DiskSerial
	case CompNIC:
		return info.NICMac
	default:
		return ""
	}
}

// ComputeFingerprints computes an HMAC-SHA256 hex digest for every
// component in the HardwareInfo using the provided salt.
func ComputeFingerprints(info *HardwareInfo, salt string) Fingerprints {
	fp := make(Fingerprints, len(AllComponents))
	for _, c := range AllComponents {
		raw := componentValue(info, c)
		mac := crypto.HMACSHA256([]byte(raw), []byte(salt))
		fp[c] = hex.EncodeToString(mac)
	}
	return fp
}

// ComputeComposite returns a single HMAC-SHA256 hex digest computed over
// the concatenation of all raw component values (in deterministic order).
func ComputeComposite(info *HardwareInfo, salt string) string {
	var combined strings.Builder
	for _, c := range AllComponents {
		combined.WriteString(componentValue(info, c))
	}
	mac := crypto.HMACSHA256([]byte(combined.String()), []byte(salt))
	return hex.EncodeToString(mac)
}

// MatchThreshold compares two Fingerprints maps and reports how many
// components match.  It returns the number of matched components, the
// total number of components compared, and whether the match count meets
// or exceeds the given threshold.
func MatchThreshold(expected, actual Fingerprints, threshold int) (matched int, total int, pass bool) {
	for _, c := range AllComponents {
		ev, eOK := expected[c]
		av, aOK := actual[c]
		if eOK && aOK {
			total++
			if ev == av {
				matched++
			}
		}
	}
	pass = matched >= threshold
	return matched, total, pass
}
