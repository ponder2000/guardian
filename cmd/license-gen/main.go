package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ponder2000/guardian/internal/crypto"
	"github.com/ponder2000/guardian/internal/fingerprint"
	"github.com/ponder2000/guardian/internal/license"
)

const usage = `license-gen - Guardian license generation tool

Usage:
  license-gen <command> [options]

Commands:
  init      Generate a new Ed25519 master key pair
  create    Create a signed license file
  verify    Verify a license file signature

Run 'license-gen <command> -h' for details on each command.
`

const initUsage = `Usage: license-gen init [options]

Generate a new Ed25519 master key pair (master.priv, master.pub).

Options:
`

const createUsage = `Usage: license-gen create [options]

Create a signed license file from hardware info and module definitions.

Options:
`

const verifyUsage = `Usage: license-gen verify [options]

Verify the signature of an existing license file.

Options:
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "init":
		cmdInit(os.Args[2:])
	case "create":
		cmdCreate(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}

// cmdInit generates a new Ed25519 master key pair and saves it to disk.
func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	outputDir := fs.String("output-dir", ".", "Directory to write master.priv and master.pub")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, initUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// Ensure the output directory exists.
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate key pair: %v\n", err)
		os.Exit(1)
	}

	privPath := filepath.Join(*outputDir, "master.priv")
	pubPath := filepath.Join(*outputDir, "master.pub")

	if err := kp.SavePrivateKey(privPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save private key: %v\n", err)
		os.Exit(1)
	}

	if err := kp.SavePublicKey(pubPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save public key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Master key pair generated successfully.\n")
	fmt.Printf("  Private key: %s\n", privPath)
	fmt.Printf("  Public key:  %s\n", pubPath)
}

// moduleFlags collects multiple --module flag values.
type moduleFlags []string

func (m *moduleFlags) String() string {
	return strings.Join(*m, ", ")
}

func (m *moduleFlags) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// cmdCreate creates a signed license file.
func cmdCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	hardwarePath := fs.String("hardware", "", "Path to hardware-info.json file")
	customer := fs.String("customer", "", "Customer name (issued_to)")
	expiresStr := fs.String("expires", "", "Expiration date in YYYY-MM-DD format")
	signWith := fs.String("sign-with", "", "Path to master.priv key file")
	output := fs.String("output", "", "Output path for the .license file")

	var modules moduleFlags
	fs.Var(&modules, "module", "Module definition: modname:key=val,key=val (repeatable)")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, createUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// Validate required flags.
	var missing []string
	if *hardwarePath == "" {
		missing = append(missing, "--hardware")
	}
	if *customer == "" {
		missing = append(missing, "--customer")
	}
	if *expiresStr == "" {
		missing = append(missing, "--expires")
	}
	if *signWith == "" {
		missing = append(missing, "--sign-with")
	}
	if *output == "" {
		missing = append(missing, "--output")
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "Missing required flags: %s\n", strings.Join(missing, ", "))
		fs.Usage()
		os.Exit(1)
	}

	// Parse expiration date.
	expiresAt, err := time.Parse("2006-01-02", *expiresStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid expiration date %q: expected YYYY-MM-DD format\n", *expiresStr)
		os.Exit(1)
	}
	// Set expiry to end of day in UTC.
	expiresAt = expiresAt.UTC().Add(23*time.Hour + 59*time.Minute + 59*time.Second)

	// Read hardware info JSON.
	hwData, err := os.ReadFile(*hardwarePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read hardware file: %v\n", err)
		os.Exit(1)
	}

	var hwJSON struct {
		MachineID   string `json:"machine_id"`
		CPU         string `json:"cpu"`
		Motherboard string `json:"motherboard"`
		Disk        string `json:"disk"`
		NIC         string `json:"nic"`
	}
	if err := json.Unmarshal(hwData, &hwJSON); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse hardware JSON: %v\n", err)
		os.Exit(1)
	}

	hwInfo := &fingerprint.HardwareInfo{
		MachineID:   hwJSON.MachineID,
		CPU:         hwJSON.CPU,
		Motherboard: hwJSON.Motherboard,
		DiskSerial:  hwJSON.Disk,
		NICMac:      hwJSON.NIC,
	}

	// Generate a random salt for fingerprint hashing.
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate random salt: %v\n", err)
		os.Exit(1)
	}
	salt := hex.EncodeToString(saltBytes)

	// Compute fingerprints.
	fps := fingerprint.ComputeFingerprints(hwInfo, salt)

	// Parse module flags.
	parsedModules := make(map[string]license.Module)
	for _, modStr := range modules {
		name, mod, err := parseModuleFlag(modStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --module flag %q: %v\n", modStr, err)
			os.Exit(1)
		}
		parsedModules[name] = mod
	}

	// Generate a license ID.
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate license ID: %v\n", err)
		os.Exit(1)
	}
	licenseID := fmt.Sprintf("LIC-%s", strings.ToUpper(hex.EncodeToString(idBytes)))

	// Build the License struct.
	lic := &license.License{
		LicenseID: licenseID,
		Version:   1,
		IssuedTo:  *customer,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: expiresAt,
		Hardware: license.HardwareSpec{
			Salt:           salt,
			Fingerprints:   fps,
			MatchThreshold: 3,
		},
		Modules:      parsedModules,
		GlobalLimits: map[string]interface{}{},
	}

	// Load the private key.
	privKey, err := crypto.LoadPrivateKey(*signWith)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load private key: %v\n", err)
		os.Exit(1)
	}

	// Derive the signer fingerprint from the public key portion of the
	// private key (the last 32 bytes of an Ed25519 private key are the
	// public key).
	pubKeyBytes := privKey.Public().(ed25519.PublicKey)
	signerHash := sha256.Sum256(pubKeyBytes)
	signerFP := hex.EncodeToString(signerHash[:])

	// Create the signed license file content.
	fileContent, err := license.CreateSignedFile(lic, privKey, signerFP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create signed license: %v\n", err)
		os.Exit(1)
	}

	// Write the output file.
	if err := os.WriteFile(*output, fileContent, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write license file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("License created successfully.\n")
	fmt.Printf("  License ID:  %s\n", licenseID)
	fmt.Printf("  Issued to:   %s\n", *customer)
	fmt.Printf("  Expires at:  %s\n", expiresAt.Format(time.RFC3339))
	fmt.Printf("  Modules:     %d\n", len(parsedModules))
	fmt.Printf("  Output:      %s\n", *output)
}

// parseModuleFlag parses a module flag string like "rdpms-core:max_users=50,max_sensors=500"
// into a module name and Module struct.
func parseModuleFlag(s string) (string, license.Module, error) {
	// Split name from key=val pairs.
	parts := strings.SplitN(s, ":", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", license.Module{}, fmt.Errorf("empty module name")
	}

	name := parts[0]
	mod := license.Module{
		Enabled:  true,
		Features: []string{},
		Limits:   make(map[string]interface{}),
	}

	if len(parts) == 2 && parts[1] != "" {
		kvPairs := strings.Split(parts[1], ",")
		for _, kv := range kvPairs {
			eqParts := strings.SplitN(kv, "=", 2)
			if len(eqParts) != 2 {
				return "", license.Module{}, fmt.Errorf("invalid key=value pair: %q", kv)
			}
			key := strings.TrimSpace(eqParts[0])
			val := strings.TrimSpace(eqParts[1])

			// Try to parse as a number first; fall back to string.
			var numVal json.Number = json.Number(val)
			if _, err := numVal.Int64(); err == nil {
				n, _ := numVal.Int64()
				mod.Limits[key] = n
			} else if _, err := numVal.Float64(); err == nil {
				f, _ := numVal.Float64()
				mod.Limits[key] = f
			} else {
				mod.Limits[key] = val
			}
		}
	}

	return name, mod, nil
}

// cmdVerify verifies the signature on a license file.
func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	licensePath := fs.String("license", "", "Path to the .license file")
	pubPath := fs.String("pub", "", "Path to master.pub key file")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, verifyUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// Validate required flags.
	var missing []string
	if *licensePath == "" {
		missing = append(missing, "--license")
	}
	if *pubPath == "" {
		missing = append(missing, "--pub")
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "Missing required flags: %s\n", strings.Join(missing, ", "))
		fs.Usage()
		os.Exit(1)
	}

	// Read the license file.
	licData, err := os.ReadFile(*licensePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read license file: %v\n", err)
		os.Exit(1)
	}

	// Parse the license file.
	sl, err := license.ParseFile(licData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse license file: %v\n", err)
		os.Exit(1)
	}

	// Load the public key.
	pubKey, err := crypto.LoadPublicKey(*pubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load public key: %v\n", err)
		os.Exit(1)
	}

	// Verify the signature.
	if err := sl.Verify(pubKey); err != nil {
		fmt.Fprintf(os.Stderr, "Signature verification FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Signature verification passed.\n")
	fmt.Printf("  License ID:  %s\n", sl.License.LicenseID)
	fmt.Printf("  Issued to:   %s\n", sl.License.IssuedTo)
	fmt.Printf("  Issued at:   %s\n", sl.License.IssuedAt.Format(time.RFC3339))
	fmt.Printf("  Expires at:  %s\n", sl.License.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("  Signer FP:   %s\n", sl.SignerFP)

	// Check expiry as a convenience.
	if err := sl.CheckExpiry(); err != nil {
		fmt.Printf("  WARNING: %v\n", err)
	} else {
		fmt.Printf("  Days until expiry: %d\n", sl.DaysUntilExpiry())
	}

	// List modules.
	if len(sl.License.Modules) > 0 {
		fmt.Printf("  Modules:\n")
		for name, mod := range sl.License.Modules {
			status := "disabled"
			if mod.Enabled {
				status = "enabled"
			}
			fmt.Printf("    - %s (%s)\n", name, status)
			for k, v := range mod.Limits {
				fmt.Printf("        %s = %v\n", k, v)
			}
		}
	}
}
