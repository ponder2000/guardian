# Guardian CLI Reference

`guardian-cli` is the admin tool for managing a running Guardian daemon. It communicates with the daemon via configuration file paths and local state — it does not connect to the Unix socket directly.

## Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config <path>` | `/etc/guardian/guardian.conf` | Path to the daemon configuration file |

## Commands

### `status`

Show the current daemon status including license validity, hardware match, and uptime.

```bash
sudo guardian-cli status
```

**Output example:**

```
Guardian Status:
  PID:       12345
  Uptime:    2d 14h 32m
  License:   VALID (expires in 334 days)
  Hardware:  OK (5/5 components match, threshold: 3)
```

---

### `license-info`

Display full license details — ID, customer name, issue/expiry dates, modules with their features and metadata.

```bash
sudo guardian-cli license-info
```

**Output example:**

```
License Details:
  License ID:  LIC-2026-00451
  Issued To:   ACME Corp - Production
  Issued At:   2026-02-15
  Expires At:  2027-02-15 (334 days remaining)
  Threshold:   3 of 5

  Modules:
    service_A (enabled)
      Features: realtime-alerts, data-export
      Metadata: max_users=50, max_sensors=500

    service_B (enabled)
      Features: thermal-detection
      Metadata: max_cameras=20, max_zones=10
```

---

### `hardware-info`

Show hardware fingerprint comparison between the license and the current machine. Useful for debugging hardware mismatch issues.

```bash
sudo guardian-cli hardware-info
```

**Output example:**

```
Hardware Fingerprint Comparison:
  Component       License              Live                 Match
  ─────────       ───────              ────                 ─────
  machine_id      a1b2c3...            a1b2c3...            YES
  cpu             d4e5f6...            d4e5f6...            YES
  motherboard     789abc...            789abc...            YES
  disk            def012...            def012...            YES
  nic             345678...            aabbcc...            NO

  Result: 4/5 match (threshold: 3) — PASS
```

---

### `register`

Register a new service with the daemon. Creates a token file containing the shared secret and daemon public key.

```bash
sudo guardian-cli register --service=service_A --modules=service_A
```

| Flag | Required | Description |
|------|----------|-------------|
| `--service <name>` | Yes | Unique service identifier |
| `--modules <list>` | Yes | Comma-separated module names this service can access |

The token file is written to the token directory (same directory as the `token_db` configured in `guardian.conf`). For example, if `token_db = /etc/guardian/tokens.db`, the token is created at `/etc/guardian/tokens/service_A.token`.

**Token file format:**

```
TOKEN:<hex-encoded 256-bit shared secret>
DAEMON_PUB:<hex-encoded Ed25519 public key>
```

---

### `list-services`

List all registered services with their last-seen timestamps.

```bash
sudo guardian-cli list-services
```

**Output example:**

```
Registered Services:
  service_A    modules=[service_A]    last_seen=2026-02-19 10:32:00
  service_B    modules=[service_B]    last_seen=2026-02-19 10:30:15
  service_C    modules=[service_C]    last_seen=never
```

---

### `revoke`

Permanently revoke a service token. The service will fail authentication on its next connection attempt.

```bash
sudo guardian-cli revoke --service=service_A
```

| Flag | Required | Description |
|------|----------|-------------|
| `--service <name>` | Yes | Service to revoke |

After revoking, the daemon sends a `REVOKE_NOTICE` to the service if it is currently connected.

---

### `rotate`

Generate a new token for a service, invalidating the old one. Use this for periodic credential rotation.

```bash
sudo guardian-cli rotate --service=service_A
```

| Flag | Required | Description |
|------|----------|-------------|
| `--service <name>` | Yes | Service whose token to rotate |

After rotation:
- The old token is immediately invalid
- A new token file is written to disk
- If using Docker, restart the container to pick up the new mounted token
- If using systemd, restart the service to re-read the token file

---

### `export-hardware`

Export the current machine's hardware fingerprint as JSON. Send this file to the license issuer for license generation.

```bash
sudo guardian-cli export-hardware > hardware-info.json
```

**Output example (JSON):**

```json
{
  "machine_id": "a1b2c3d4e5f6...",
  "cpu": "Intel Core i7-12700K 12-core",
  "motherboard": "SN-ABC123DEF456",
  "disk": "SERIAL-XYZ789",
  "nic": "aa:bb:cc:dd:ee:ff"
}
```

The five components collected:

| Component | Source |
|-----------|--------|
| `machine_id` | `/etc/machine-id` |
| `cpu` | Model name + core count from `/proc/cpuinfo` |
| `motherboard` | DMI baseboard serial (`/sys/devices/virtual/dmi/id/board_serial`) |
| `disk` | Primary disk serial (`/sys/block/{device}/device/serial`) |
| `nic` | MAC address of first non-loopback, non-docker network interface |

---

### `import-license`

Import a license file to the path configured in `guardian.conf`.

```bash
sudo guardian-cli import-license /path/to/new.license
```

After importing, restart the daemon to load the new license:

```bash
sudo systemctl restart guardian
```

Or send `SIGHUP` to reload the license without a full restart:

```bash
sudo systemctl reload guardian
```

---

### `version`

Print version information including build commit and timestamp.

```bash
guardian-cli version
# or
guardian-cli -v
guardian-cli --version
```

---

### `help`

Print usage information for all commands.

```bash
guardian-cli help
guardian-cli -h
guardian-cli --help
```

## Environment Variables

The CLI reads configuration from the config file, but services using the client SDKs recognize these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDIAN_SOCKET` | `/var/run/guardian/guardian.sock` | Path to the daemon Unix socket |
| `GUARDIAN_TOKEN_PATH` | `/etc/guardian/token` | Path to the service token file |
