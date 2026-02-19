# License Tools Reference

`license-gen` is the command-line tool for creating, updating, inspecting, and verifying Guardian license files. It runs on your office/build machine — it is **not** deployed to target machines.

## Commands

### `init` — Generate Master Key Pair

Generate a new Ed25519 master key pair. This is a one-time setup step.

```bash
license-gen init --output-dir=/secure/vault/
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output-dir <dir>` | `.` (current directory) | Directory to write key files |

**Output files:**
- `master.priv` — Private signing key. **Keep this secret.** Never copy to target machines.
- `master.pub` — Public verification key. Ship this to target machines at `/etc/guardian/master.pub`.

**Key format:** Raw Ed25519 keys (32 bytes each), hex-encoded.

> Store `master.priv` in a secure vault, HSM, or encrypted volume. If compromised, an attacker can forge licenses.

---

### `create` — Create a New License

Create a signed license file from a hardware fingerprint and module definitions.

```bash
license-gen create \
    --hardware=hardware-info.json \
    --customer="ACME Corp - Production" \
    --expires=2027-12-31 \
    --match-threshold=3 \
    --module service_A:max_users=50,max_sensors=500 \
    --module service_B:max_cameras=20,region=us-east \
    --sign-with=/secure/vault/master.priv \
    --output=acme-prod.license
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--hardware <file>` | Yes | — | Path to hardware JSON (from `guardian-cli export-hardware`) |
| `--customer <name>` | Yes | — | Customer name (stored as `issued_to`) |
| `--expires <date>` | Yes | — | Expiration date in `YYYY-MM-DD` format |
| `--sign-with <file>` | Yes | — | Path to `master.priv` |
| `--output <file>` | Yes | — | Output `.license` file path |
| `--match-threshold <1-5>` | No | `3` | Number of hardware components that must match |
| `--module <spec>` | No | — | Module definition (repeatable). Format: `name:key=val,key=val` |

**Hardware JSON format** (from `guardian-cli export-hardware`):

```json
{
  "machine_id": "a1b2c3d4e5f6...",
  "cpu": "Intel Core i7-12700K 12-core",
  "motherboard": "SN-ABC123DEF456",
  "disk": "SERIAL-XYZ789",
  "nic": "aa:bb:cc:dd:ee:ff"
}
```

**What happens internally:**
1. Reads the hardware JSON
2. Generates a random 16-byte salt
3. Computes `HMAC-SHA256(component, salt)` for each of the 5 hardware components
4. Builds the license payload with customer info, expiry, modules, and hardware fingerprints
5. Signs the payload with `master.priv` (Ed25519)
6. Writes the `.license` file

---

### `update` — Modify an Existing License

Add modules, modify metadata, disable modules, change expiration, or adjust the match threshold — without creating a license from scratch. The license is re-signed.

```bash
license-gen update \
    --license=existing.license \
    --sign-with=/secure/vault/master.priv \
    --output=updated.license \
    [options...]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--license <file>` | Yes | Path to existing `.license` file |
| `--sign-with <file>` | Yes | Path to `master.priv` |
| `--output <file>` | Yes | Output path for updated license |
| `--module <spec>` | No | Add or modify a module (repeatable). Metadata keys are merged with existing values |
| `--disable <name>` | No | Disable a module (repeatable). Sets `enabled: false` |
| `--expires <date>` | No | Change expiration date (`YYYY-MM-DD`) |
| `--match-threshold <1-5>` | No | Change hardware match threshold |

You can combine multiple flags in a single command.

**Examples:**

```bash
# Add a new module
license-gen update --license=old.license --sign-with=master.priv \
    --module service_C:max_users=100,region=us-east \
    --output=new.license

# Modify metadata on existing module (merges keys)
license-gen update --license=old.license --sign-with=master.priv \
    --module service_A:max_users=100 \
    --output=new.license

# Disable a module
license-gen update --license=old.license --sign-with=master.priv \
    --disable service_B \
    --output=new.license

# Extend expiration
license-gen update --license=old.license --sign-with=master.priv \
    --expires=2028-12-31 \
    --output=new.license

# Change match threshold
license-gen update --license=old.license --sign-with=master.priv \
    --match-threshold=4 \
    --output=new.license

# Combine: add module + extend expiry + lower threshold
license-gen update --license=old.license --sign-with=master.priv \
    --module service_D:max_nodes=10 \
    --expires=2029-06-30 \
    --match-threshold=2 \
    --output=new.license
```

After updating, deploy the new `.license` file to the target machine and restart the daemon:

```bash
sudo guardian-cli import-license new.license
sudo systemctl restart guardian
# Or reload without restart:
sudo systemctl reload guardian
```

---

### `decode` — Inspect License Contents

Decode and display the full contents of a license file. Does not require the private key.

```bash
# Human-readable output
license-gen decode --license=acme.license

# JSON output (for scripting, piping to jq)
license-gen decode --license=acme.license --json
```

| Flag | Required | Description |
|------|----------|-------------|
| `--license <file>` | Yes | Path to `.license` file |
| `--json` | No | Output raw JSON instead of formatted text |

**Human-readable output example:**

```
License: LIC-2026-00451
  Issued To:   ACME Corp - Production
  Issued At:   2026-02-15
  Expires At:  2027-12-31

  Hardware:
    Salt:      a1b2c3d4e5f6...
    Threshold: 3 of 5
    Fingerprints:
      machine_id:  abcdef123456...
      cpu:         789abc456def...
      motherboard: 012345abcdef...
      disk:        fedcba654321...
      nic:         aabbccddee11...

  Modules:
    service_A (enabled)
      Metadata: max_users=50, max_sensors=500

    service_B (enabled)
      Metadata: max_cameras=20, region=us-east
```

**JSON output** can be piped to `jq` for further processing:

```bash
license-gen decode --license=acme.license --json | jq '.modules'
license-gen decode --license=acme.license --json | jq '.expires_at'
```

---

### `verify` — Verify License Signature

Verify the Ed25519 signature of a license file using the master public key.

```bash
license-gen verify --license=acme.license --pub=/secure/vault/master.pub
```

| Flag | Required | Description |
|------|----------|-------------|
| `--license <file>` | Yes | Path to `.license` file |
| `--pub <file>` | Yes | Path to `master.pub` |

**Output on success:**

```
Signature: VALID
Signer:    SHA256:abcdef123456...
License:   LIC-2026-00451
Expires:   2027-12-31
```

**Output on failure:**

```
Signature: INVALID
Error: signature verification failed
```

---

### `fingerprint` — Compute Hardware Fingerprints

Compute HMAC-SHA256 fingerprints from a hardware JSON file using a given salt. Useful for debugging hardware mismatches — compare the computed fingerprints against those stored in the license.

```bash
# Using salt from an existing license
license-gen fingerprint --hardware=hw.json --license=acme.license

# Using a raw salt string
license-gen fingerprint --hardware=hw.json --salt=a1b2c3d4e5f6...
```

| Flag | Required | Description |
|------|----------|-------------|
| `--hardware <file>` | Yes | Path to hardware JSON |
| `--license <file>` | One of `--license` or `--salt` | Extract salt from this license |
| `--salt <hex>` | One of `--license` or `--salt` | Use this raw hex salt |

**Output example:**

```
Hardware Fingerprints (salt: a1b2c3d4e5f6...):
  machine_id:  abcdef123456...
  cpu:         789abc456def...
  motherboard: 012345abcdef...
  disk:        fedcba654321...
  nic:         aabbccddee11...
```

Compare these against `license-gen decode --license=acme.license` to identify which components differ.

---

## End-to-End Workflow

### 1. One-time setup: generate keys

```bash
license-gen init --output-dir=/secure/vault/
# Keep master.priv safe. Ship master.pub to target machines.
```

### 2. Collect hardware from target machine

```bash
# On the target machine:
sudo guardian-cli export-hardware > hardware-info.json
# Transfer hardware-info.json to your office
```

### 3. Create the license

```bash
license-gen create \
    --hardware=hardware-info.json \
    --customer="ACME Corp - Production" \
    --expires=2027-12-31 \
    --module service_A:max_users=50,max_sensors=500 \
    --module service_B:max_cameras=20 \
    --sign-with=/secure/vault/master.priv \
    --output=acme-prod.license
```

### 4. Verify before shipping

```bash
license-gen verify --license=acme-prod.license --pub=/secure/vault/master.pub
license-gen decode --license=acme-prod.license
```

### 5. Deploy to target machine

```bash
# On the target machine:
sudo cp master.pub /etc/guardian/master.pub
sudo guardian-cli import-license acme-prod.license
sudo systemctl restart guardian
sudo guardian-cli status
```

### 6. Later: update the license

```bash
# At your office:
license-gen update \
    --license=acme-prod.license \
    --sign-with=/secure/vault/master.priv \
    --module service_C:max_users=200 \
    --expires=2028-12-31 \
    --output=acme-prod-v2.license

# Re-deploy to target machine
```

---

## License File Format

```
GUARDIAN-LICENSE-V1
PAYLOAD: <base64-encoded JSON payload>
SIGNATURE: <base64-encoded Ed25519 signature of payload>
SIGNER: <SHA256 fingerprint of the signing public key>
```

The format is text-based and can be safely transferred via email, chat, or file copy. The signature covers the exact payload bytes, so any modification invalidates it.
