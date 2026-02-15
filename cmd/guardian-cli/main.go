package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ponder2000/guardian/internal/auth"
	"github.com/ponder2000/guardian/internal/config"
	"github.com/ponder2000/guardian/internal/crypto"
	"github.com/ponder2000/guardian/internal/fingerprint"
	"github.com/ponder2000/guardian/internal/license"
)

const defaultConfigPath = "/etc/guardian/guardian.conf"

// Set by -ldflags at build time.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
	author    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]

	// Handle help and version flags before dispatching
	if subcommand == "-h" || subcommand == "--help" || subcommand == "help" {
		printUsage()
		os.Exit(0)
	}
	if subcommand == "-v" || subcommand == "--version" || subcommand == "version" {
		fmt.Printf("guardian-cli %s (commit: %s, built: %s, author: %s)\n", version, commit, buildTime, author)
		os.Exit(0)
	}

	switch subcommand {
	case "status":
		cmdStatus(os.Args[2:])
	case "license-info":
		cmdLicenseInfo(os.Args[2:])
	case "hardware-info":
		cmdHardwareInfo(os.Args[2:])
	case "register":
		cmdRegister(os.Args[2:])
	case "list-services":
		cmdListServices(os.Args[2:])
	case "revoke":
		cmdRevoke(os.Args[2:])
	case "rotate":
		cmdRotate(os.Args[2:])
	case "export-hardware":
		cmdExportHardware(os.Args[2:])
	case "import-license":
		cmdImportLicense(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: guardian-cli <command> [flags]

Commands:
  status            Show daemon status (license validity, hardware match)
  license-info      Show license details (ID, dates, modules)
  hardware-info     Show hardware fingerprint comparison
  register          Register a new service token
  list-services     List all registered services
  revoke            Revoke a service token
  rotate            Rotate a service token
  export-hardware   Export hardware info as JSON
  import-license    Import a license file to the configured path

Common flags:
  --config <path>   Path to guardian.conf (default: %s)
`, defaultConfigPath)
}

// loadConfig parses the --config flag from the given FlagSet and loads the config file.
func loadConfig(fs *flag.FlagSet, args []string) (*config.Config, error) {
	configPath := fs.String("config", defaultConfigPath, "path to guardian.conf")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

// loadLicense loads and parses the license file specified in the config.
func loadLicense(cfg *config.Config) (*license.SignedLicense, error) {
	data, err := os.ReadFile(cfg.License.LicenseFile)
	if err != nil {
		return nil, fmt.Errorf("read license file: %w", err)
	}
	sl, err := license.ParseFile(data)
	if err != nil {
		return nil, fmt.Errorf("parse license: %w", err)
	}
	return sl, nil
}

// collectHardwareInfo collects hardware information, using placeholders on macOS.
func collectHardwareInfo() (*fingerprint.HardwareInfo, error) {
	if runtime.GOOS == "darwin" {
		return &fingerprint.HardwareInfo{
			MachineID:   "darwin-placeholder-machine-id",
			CPU:         "Apple Silicon (macOS placeholder)",
			Motherboard: "apple-motherboard-placeholder",
			DiskSerial:  "apple-disk-placeholder",
			NICMac:      "00:00:00:00:00:00",
		}, nil
	}
	return fingerprint.Collect()
}

// ---------- subcommands ----------

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Guardian Daemon Status ===")
	fmt.Println()

	// Load and check license
	sl, err := loadLicense(cfg)
	if err != nil {
		fmt.Printf("%-20s %s\n", "License:", "ERROR - "+err.Error())
		os.Exit(1)
	}

	// Verify signature
	masterPub, err := crypto.LoadPublicKey(cfg.License.MasterPub)
	if err != nil {
		fmt.Printf("%-20s %s\n", "Signature:", "ERROR - "+err.Error())
	} else {
		if verr := sl.Verify(masterPub); verr != nil {
			fmt.Printf("%-20s %s\n", "Signature:", "INVALID - "+verr.Error())
		} else {
			fmt.Printf("%-20s %s\n", "Signature:", "VALID")
		}
	}

	// Check expiry
	if exerr := sl.CheckExpiry(); exerr != nil {
		fmt.Printf("%-20s %s\n", "License:", "EXPIRED")
	} else {
		days := sl.DaysUntilExpiry()
		fmt.Printf("%-20s %s (%d days remaining)\n", "License:", "VALID", days)
	}

	// Check hardware
	hwInfo, err := collectHardwareInfo()
	if err != nil {
		fmt.Printf("%-20s %s\n", "Hardware:", "ERROR - "+err.Error())
	} else {
		matched, total, hwerr := sl.CheckHardware(hwInfo)
		if hwerr != nil {
			fmt.Printf("%-20s %s (%d/%d matched)\n", "Hardware:", "MISMATCH", matched, total)
		} else {
			fmt.Printf("%-20s %s (%d/%d matched)\n", "Hardware:", "OK", matched, total)
		}
	}

	// Uptime estimate from PID file
	if pidFile := cfg.Daemon.PIDFile; pidFile != "" {
		info, serr := os.Stat(pidFile)
		if serr == nil {
			uptime := time.Since(info.ModTime()).Truncate(time.Second)
			fmt.Printf("%-20s %s\n", "Uptime (est.):", uptime.String())
		} else {
			fmt.Printf("%-20s %s\n", "Uptime (est.):", "daemon not running")
		}
	}

	fmt.Println()
}

func cmdLicenseInfo(args []string) {
	fs := flag.NewFlagSet("license-info", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	sl, err := loadLicense(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	lic := sl.License

	fmt.Println("=== License Information ===")
	fmt.Println()
	fmt.Printf("%-20s %s\n", "License ID:", lic.LicenseID)
	fmt.Printf("%-20s %d\n", "Version:", lic.Version)
	fmt.Printf("%-20s %s\n", "Issued To:", lic.IssuedTo)
	fmt.Printf("%-20s %s\n", "Issued At:", lic.IssuedAt.Format(time.RFC3339))
	fmt.Printf("%-20s %s\n", "Expires At:", lic.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("%-20s %d days\n", "Days Remaining:", sl.DaysUntilExpiry())
	fmt.Printf("%-20s %s\n", "Signer:", sl.SignerFP)
	fmt.Println()

	// Hardware spec
	fmt.Println("--- Hardware Requirements ---")
	fmt.Printf("%-20s %d\n", "Match Threshold:", lic.Hardware.MatchThreshold)
	fmt.Printf("%-20s %d component(s)\n", "Fingerprints:", len(lic.Hardware.Fingerprints))
	fmt.Println()

	// Modules
	if len(lic.Modules) > 0 {
		fmt.Println("--- Licensed Modules ---")
		fmt.Println()
		fmt.Printf("%-20s %-10s %-30s %s\n", "MODULE", "ENABLED", "FEATURES", "LIMITS")
		fmt.Printf("%-20s %-10s %-30s %s\n",
			strings.Repeat("-", 20),
			strings.Repeat("-", 10),
			strings.Repeat("-", 30),
			strings.Repeat("-", 30))

		for name, mod := range lic.Modules {
			enabled := "no"
			if mod.Enabled {
				enabled = "yes"
			}

			features := strings.Join(mod.Features, ", ")
			if features == "" {
				features = "-"
			}

			limits := formatMetadata(mod.Metadata)
			if limits == "" {
				limits = "-"
			}

			fmt.Printf("%-20s %-10s %-30s %s\n", name, enabled, features, limits)
		}
		fmt.Println()
	}

	// Global limits
	if len(lic.GlobalLimits) > 0 {
		fmt.Println("--- Global Limits ---")
		for k, v := range lic.GlobalLimits {
			fmt.Printf("%-20s %v\n", k+":", v)
		}
		fmt.Println()
	}
}

func cmdHardwareInfo(args []string) {
	fs := flag.NewFlagSet("hardware-info", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	sl, err := loadLicense(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	hwInfo, err := collectHardwareInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error collecting hardware info: %v\n", err)
		os.Exit(1)
	}

	// Compute fingerprints with the license's salt
	actual := fingerprint.ComputeFingerprints(hwInfo, sl.License.Hardware.Salt)
	expected := sl.License.Hardware.Fingerprints

	fmt.Println("=== Hardware Fingerprint Comparison ===")
	fmt.Println()
	fmt.Printf("%-15s %-20s %-20s %s\n", "COMPONENT", "RAW VALUE", "STATUS", "FINGERPRINT (first 16 chars)")
	fmt.Printf("%-15s %-20s %-20s %s\n",
		strings.Repeat("-", 15),
		strings.Repeat("-", 20),
		strings.Repeat("-", 20),
		strings.Repeat("-", 28))

	matched := 0
	total := 0

	for _, comp := range fingerprint.AllComponents {
		rawValue := componentRawValue(hwInfo, comp)

		// Truncate raw value for display
		displayRaw := rawValue
		if len(displayRaw) > 18 {
			displayRaw = displayRaw[:15] + "..."
		}

		expectedFP, hasExpected := expected[comp]
		actualFP, hasActual := actual[comp]

		status := "N/A"
		fpDisplay := "-"

		if hasExpected && hasActual {
			total++
			if expectedFP == actualFP {
				matched++
				status = "MATCH"
			} else {
				status = "MISMATCH"
			}
			if len(actualFP) > 16 {
				fpDisplay = actualFP[:16] + "..."
			} else {
				fpDisplay = actualFP
			}
		} else if hasActual {
			status = "NOT IN LICENSE"
			if len(actualFP) > 16 {
				fpDisplay = actualFP[:16] + "..."
			} else {
				fpDisplay = actualFP
			}
		}

		fmt.Printf("%-15s %-20s %-20s %s\n", string(comp), displayRaw, status, fpDisplay)
	}

	fmt.Println()
	fmt.Printf("Result: %d/%d components matched (threshold: %d)\n",
		matched, total, sl.License.Hardware.MatchThreshold)

	if matched >= sl.License.Hardware.MatchThreshold {
		fmt.Println("Status: PASS")
	} else {
		fmt.Println("Status: FAIL")
	}
	fmt.Println()
}

func cmdRegister(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	serviceName := fs.String("service", "", "service name to register")
	modulesStr := fs.String("modules", "", "comma-separated list of modules (optional)")
	configPath := fs.String("config", defaultConfigPath, "path to guardian.conf")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *serviceName == "" {
		fmt.Fprintf(os.Stderr, "Error: --service is required\n")
		fmt.Fprintf(os.Stderr, "Usage: guardian-cli register --service=<name> [--modules=<mod1,mod2>]\n")
		os.Exit(1)
	}

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: load config: %v\n", err)
		os.Exit(1)
	}

	// Parse modules
	var modules []string
	if *modulesStr != "" {
		for _, m := range strings.Split(*modulesStr, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				modules = append(modules, m)
			}
		}
	}

	// Load daemon public key hex for token file
	daemonPubHex := ""
	pubKey, perr := crypto.LoadPublicKey(cfg.Crypto.DaemonPub)
	if perr == nil {
		daemonPubHex = hex.EncodeToString(pubKey)
	}

	// Token directory: same directory as the token DB
	tokenDir := filepath.Dir(cfg.Crypto.TokenDB)

	store := auth.NewTokenStore(cfg.Crypto.TokenDB, tokenDir)
	if err := store.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: load token store: %v\n", err)
		os.Exit(1)
	}

	st, err := store.Register(*serviceName, modules, daemonPubHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: register service: %v\n", err)
		os.Exit(1)
	}

	if err := store.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: save token store: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Service registered successfully.\n\n")
	fmt.Printf("%-20s %s\n", "Service ID:", st.ServiceID)
	fmt.Printf("%-20s %s\n", "Registered At:", st.RegisteredAt.Format(time.RFC3339))
	fmt.Printf("%-20s %s\n", "Modules:", strings.Join(st.Modules, ", "))
	fmt.Printf("%-20s %s\n", "Token File:", filepath.Join(tokenDir, *serviceName+".token"))
	fmt.Println()
}

func cmdListServices(args []string) {
	fs := flag.NewFlagSet("list-services", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	tokenDir := filepath.Dir(cfg.Crypto.TokenDB)
	store := auth.NewTokenStore(cfg.Crypto.TokenDB, tokenDir)
	if err := store.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: load token store: %v\n", err)
		os.Exit(1)
	}

	services := store.ListServices()
	if len(services) == 0 {
		fmt.Println("No registered services.")
		return
	}

	fmt.Println("=== Registered Services ===")
	fmt.Println()
	fmt.Printf("%-20s %-20s %-20s %s\n", "SERVICE", "REGISTERED", "LAST SEEN", "MODULES")
	fmt.Printf("%-20s %-20s %-20s %s\n",
		strings.Repeat("-", 20),
		strings.Repeat("-", 20),
		strings.Repeat("-", 20),
		strings.Repeat("-", 30))

	for _, st := range services {
		registered := st.RegisteredAt.Format("2006-01-02 15:04")
		lastSeen := "never"
		if !st.LastSeen.IsZero() {
			lastSeen = st.LastSeen.Format("2006-01-02 15:04")
		}
		modules := strings.Join(st.Modules, ", ")
		if modules == "" {
			modules = "(all)"
		}
		fmt.Printf("%-20s %-20s %-20s %s\n", st.ServiceID, registered, lastSeen, modules)
	}
	fmt.Println()
}

func cmdRevoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	serviceName := fs.String("service", "", "service name to revoke")
	configPath := fs.String("config", defaultConfigPath, "path to guardian.conf")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *serviceName == "" {
		fmt.Fprintf(os.Stderr, "Error: --service is required\n")
		fmt.Fprintf(os.Stderr, "Usage: guardian-cli revoke --service=<name>\n")
		os.Exit(1)
	}

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: load config: %v\n", err)
		os.Exit(1)
	}

	tokenDir := filepath.Dir(cfg.Crypto.TokenDB)
	store := auth.NewTokenStore(cfg.Crypto.TokenDB, tokenDir)
	if err := store.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: load token store: %v\n", err)
		os.Exit(1)
	}

	if err := store.Revoke(*serviceName); err != nil {
		fmt.Fprintf(os.Stderr, "Error: revoke service: %v\n", err)
		os.Exit(1)
	}

	if err := store.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: save token store: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Service %q has been revoked.\n", *serviceName)
}

func cmdRotate(args []string) {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	serviceName := fs.String("service", "", "service name to rotate")
	configPath := fs.String("config", defaultConfigPath, "path to guardian.conf")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *serviceName == "" {
		fmt.Fprintf(os.Stderr, "Error: --service is required\n")
		fmt.Fprintf(os.Stderr, "Usage: guardian-cli rotate --service=<name>\n")
		os.Exit(1)
	}

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: load config: %v\n", err)
		os.Exit(1)
	}

	// Load daemon public key hex
	daemonPubHex := ""
	pubKey, perr := crypto.LoadPublicKey(cfg.Crypto.DaemonPub)
	if perr == nil {
		daemonPubHex = hex.EncodeToString(pubKey)
	}

	tokenDir := filepath.Dir(cfg.Crypto.TokenDB)
	store := auth.NewTokenStore(cfg.Crypto.TokenDB, tokenDir)
	if err := store.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: load token store: %v\n", err)
		os.Exit(1)
	}

	if err := store.Rotate(*serviceName, daemonPubHex); err != nil {
		fmt.Fprintf(os.Stderr, "Error: rotate service: %v\n", err)
		os.Exit(1)
	}

	if err := store.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: save token store: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Token for service %q has been rotated.\n", *serviceName)
	fmt.Printf("New token file: %s\n", filepath.Join(tokenDir, *serviceName+".token"))
}

func cmdExportHardware(args []string) {
	fs := flag.NewFlagSet("export-hardware", flag.ExitOnError)
	// Accept --config for consistency, though not used here
	_ = fs.String("config", defaultConfigPath, "path to guardian.conf")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	hwInfo, err := collectHardwareInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error collecting hardware info: %v\n", err)
		os.Exit(1)
	}

	// Build a JSON-friendly representation
	output := map[string]interface{}{
		"collected_at": time.Now().UTC().Format(time.RFC3339),
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"components": map[string]string{
			string(fingerprint.CompMachineID):   hwInfo.MachineID,
			string(fingerprint.CompCPU):         hwInfo.CPU,
			string(fingerprint.CompMotherboard): hwInfo.Motherboard,
			string(fingerprint.CompDisk):        hwInfo.DiskSerial,
			string(fingerprint.CompNIC):         hwInfo.NICMac,
		},
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func cmdImportLicense(args []string) {
	fs := flag.NewFlagSet("import-license", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to guardian.conf")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintf(os.Stderr, "Error: license file path is required\n")
		fmt.Fprintf(os.Stderr, "Usage: guardian-cli import-license <file> [--config=<path>]\n")
		os.Exit(1)
	}

	sourcePath := remaining[0]

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: load config: %v\n", err)
		os.Exit(1)
	}

	// Read the source license file
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: read license file: %v\n", err)
		os.Exit(1)
	}

	// Validate by parsing
	sl, err := license.ParseFile(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid license file: %v\n", err)
		os.Exit(1)
	}

	// Ensure destination directory exists
	destDir := filepath.Dir(cfg.License.LicenseFile)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: create directory %s: %v\n", destDir, err)
		os.Exit(1)
	}

	// Copy file to the configured license path
	destFile, err := os.OpenFile(cfg.License.LicenseFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: create destination file: %v\n", err)
		os.Exit(1)
	}
	defer destFile.Close()

	srcFile, err := os.Open(sourcePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: reopen source file: %v\n", err)
		os.Exit(1)
	}
	defer srcFile.Close()

	if _, err := io.Copy(destFile, srcFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: copy license file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("License imported successfully.\n\n")
	fmt.Printf("%-20s %s\n", "Source:", sourcePath)
	fmt.Printf("%-20s %s\n", "Destination:", cfg.License.LicenseFile)
	fmt.Printf("%-20s %s\n", "License ID:", sl.License.LicenseID)
	fmt.Printf("%-20s %s\n", "Issued To:", sl.License.IssuedTo)
	fmt.Printf("%-20s %s\n", "Expires At:", sl.License.ExpiresAt.Format(time.RFC3339))
	fmt.Println()
}

// ---------- helpers ----------

// formatMetadata converts a metadata map to a compact display string.
func formatMetadata(meta map[string]interface{}) string {
	if len(meta) == 0 {
		return ""
	}
	parts := make([]string, 0, len(meta))
	for k, v := range meta {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return strings.Join(parts, ", ")
}

// componentRawValue returns the raw string for a given component from HardwareInfo.
func componentRawValue(info *fingerprint.HardwareInfo, c fingerprint.Component) string {
	switch c {
	case fingerprint.CompMachineID:
		return info.MachineID
	case fingerprint.CompCPU:
		return info.CPU
	case fingerprint.CompMotherboard:
		return info.Motherboard
	case fingerprint.CompDisk:
		return info.DiskSerial
	case fingerprint.CompNIC:
		return info.NICMac
	default:
		return ""
	}
}
