# Guardian License Service — Final System Architecture

**Version:** 1.0  
**Date:** February 15, 2026  
**Author:** Bitcomm Technologies  

---

## 1. System Overview

Guardian is a native Linux daemon that acts as the **root of trust** for license enforcement on a deployed machine. It hardware-binds a cryptographically signed license and provides license validation services to any application — whether running inside Docker containers or as native processes.

```
┌──────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE                               │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │              GUARDIAN DAEMON (systemd service)             │     │
│  │                                                            │     │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐   │     │
│  │  │  Hardware     │  │  License     │  │  Auth &       │   │     │
│  │  │  Fingerprint  │  │  Vault       │  │  Session Mgr  │   │     │
│  │  │  Engine       │  │              │  │               │   │     │
│  │  └──────────────┘  └──────────────┘  └───────────────┘   │     │
│  │                                                            │     │
│  │  ┌──────────────────────────────────────────────────┐     │     │
│  │  │         Unix Domain Socket Server                 │     │     │
│  │  │         /var/run/guardian/guardian.sock             │     │     │
│  │  └──────────────────┬───────────────────────────────┘     │     │
│  └─────────────────────┼────────────────────────────────────┘     │
│                        │                                           │
│           ┌────────────┴────────────────┐                         │
│           │                             │                         │
│  ┌────────▼────────┐          ┌────────▼────────┐                │
│  │  Docker Services │          │  Native Services │                │
│  │                  │          │                  │                │
│  │  ┌────┐ ┌────┐  │          │  ┌────┐ ┌────┐  │                │
│  │  │SvcA│ │SvcB│  │          │  │SvcC│ │SvcD│  │                │
│  │  └────┘ └────┘  │          │  └────┘ └────┘  │                │
│  └──────────────────┘          └──────────────────┘                │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Architecture

### 2.1 Key Components

```
guardian/
├── cmd/
│   ├── guardiand/              # Main daemon binary
│   ├── guardian-cli/            # Admin CLI tool
│   └── license-gen/             # License generation tool (your office only)
│
├── internal/
│   ├── fingerprint/             # Hardware fingerprint collection & hashing
│   ├── license/                 # License parsing, verification, storage
│   ├── protocol/                # UDS message protocol (binary framing)
│   ├── auth/                    # Handshake, HMAC, session key management
│   ├── crypto/                  # Ed25519 signing, AES-GCM encryption
│   ├── server/                  # Unix socket server, connection handling
│   └── watchdog/                # Periodic HW re-check, expiry monitor
│
├── client/
│   ├── go/                      # Go client SDK
│   └── python/                  # Python client SDK
│
├── configs/
│   └── guardian.service          # systemd unit file
│
└── go.mod
```

### 2.2 Tech Stack

| Component        | Technology         | Reason                                      |
|------------------|--------------------|---------------------------------------------|
| Language         | Go                 | Static binary, no runtime deps, good crypto |
| IPC              | Unix Domain Socket | No network exposure, kernel-enforced perms   |
| Signing          | Ed25519            | Fast, modern, 32-byte keys                  |
| HMAC             | HMAC-SHA256        | Industry standard, built into Go stdlib     |
| Session Encrypt  | AES-256-GCM        | Authenticated encryption, prevents tampering |
| Wire Format      | msgpack            | Compact binary, language-agnostic            |
| Service Manager  | systemd            | Native Linux, watchdog, auto-restart         |
| Build Hardening  | garble             | Go binary obfuscation                       |

---

## 3. Filesystem Layout

### 3.1 Directory Structure on Target Machine

```
/usr/local/bin/
├── guardiand                    # daemon binary
└── guardian-cli                  # admin CLI tool

/etc/guardian/
├── guardian.conf                 # daemon configuration
├── guardian.license              # signed license file from your office
├── master.pub                    # your office's Ed25519 public key
├── daemon.key                    # guardian's daemon Ed25519 private key (generated on first boot)
├── daemon.pub                    # guardian's daemon Ed25519 public key (generated on first boot)
├── tokens.db                     # registered service tokens (SQLite or flat file)
└── tokens/                       # per-service credential files
    ├── rdpms-core.token          # token + daemon_pub for rdpms-core
    ├── eids-processor.token      # token + daemon_pub for eids-processor
    └── analytics.token           # token + daemon_pub for analytics

/var/run/guardian/
└── guardian.sock                 # Unix domain socket (created at runtime)

/var/log/guardian/
└── guardian.log                  # daemon logs
```

### 3.2 File Permissions

Since all services (Docker and native) run as root, the token files are also owned by root. The directory permissions prevent listing while still allowing direct file access.

```
PATH                                 OWNER       PERMS    PURPOSE
────────────────────────────────────────────────────────────────────────
/etc/guardian/                       root:root   0700     Config directory
/etc/guardian/guardian.conf           root:root   0600     Daemon config
/etc/guardian/guardian.license        root:root   0600     Signed license
/etc/guardian/master.pub             root:root   0644     Office public key (not secret)
/etc/guardian/daemon.key             root:root   0600     Daemon private key (SECRET)
/etc/guardian/daemon.pub             root:root   0644     Daemon public key
/etc/guardian/tokens.db              root:root   0600     Token database
/etc/guardian/tokens/                root:root   0700     Token directory
/etc/guardian/tokens/*.token         root:root   0600     Per-service credentials

/var/run/guardian/                   root:root   0755     Socket directory
/var/run/guardian/guardian.sock       root:root   0666     UDS (any local process can connect)

/var/log/guardian/                   root:root   0700     Log directory
```

> **Note:** The socket has 0666 permissions intentionally — any process on the machine can
> connect. Authentication is handled by the handshake protocol, not filesystem permissions.
> This simplifies Docker volume mounting since containers don't need UID mapping.

### 3.3 Token File Format

Each service's token file contains both the authentication token and the guardian's daemon
public key. This is a simple INI-style format.

```ini
# /etc/guardian/tokens/rdpms-core.token
#
# Guardian credential file for: rdpms-core
# Generated: 2026-02-15T10:30:00Z
# DO NOT EDIT — regenerate with: guardian-cli rotate --service=rdpms-core

SERVICE_ID=rdpms-core
TOKEN=tok_a8f3e2b1c9d4e7f6a0b3c8d1e4f7a2b5c6d9e0f1a3b4c7d8e1f2a5b6c9d0
DAEMON_PUB=dpub_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1
```

---

## 4. Cryptographic Architecture

### 4.1 Key Hierarchy

```
YOUR OFFICE (License Issuer)
━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Master Key Pair (Ed25519)
  ├── master.priv  →  NEVER leaves your office
  └── master.pub   →  Embedded in guardian binary + shipped to machines

         │ signs license files
         ▼

TARGET MACHINE (Guardian Daemon)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Daemon Key Pair (Ed25519) — generated on first boot
  ├── daemon.key  →  Stored at /etc/guardian/daemon.key
  │                   Derived from: hardware_fingerprint + license_id + random_seed
  │                   Different per machine (hardware-bound)
  └── daemon.pub  →  Written into each service token file during registration

         │ proves guardian identity to services
         ▼

SERVICE TOKENS (Per-Service, HMAC-SHA256)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Each service gets:
  ├── TOKEN        →  Random 256-bit secret (shared between guardian DB and token file)
  └── DAEMON_PUB   →  Copy of daemon's public key (for verifying guardian's signature)
```

### 4.2 What Each Entity Holds

```
                    YOUR OFFICE     GUARDIAN DAEMON      MICROSERVICE
                    ───────────     ───────────────      ────────────
Master Private Key  ■ YES           ✗ NO                 ✗ NO
Master Public Key   ■ YES           ■ YES (embedded)     ✗ NO
Daemon Private Key  ✗ NO            ■ YES (secret)       ✗ NO
Daemon Public Key   ✗ NO            ■ YES                ■ YES (from token file)
Service Token       ✗ NO            ■ ALL tokens (DB)    ■ OWN token only (file)

■ = has it     ✗ = does not have it
```

---

## 5. Hardware Fingerprint

### 5.1 Components Collected

```
COMPONENT              SOURCE                         EXAMPLE VALUE
─────────────────────  ─────────────────────────────  ─────────────────────
Machine ID             /etc/machine-id                 a1b2c3d4e5f6...
CPU Model + Cores      /proc/cpuinfo                   "Intel Xeon E5-2680 v4 x28"
Motherboard Serial     dmidecode -s baseboard-serial   "W2KS42903817"
Primary Disk Serial    lsblk / hdparm / udevadm        "WD-WMC4N0K1LRJX"
Primary NIC MAC        ip link / /sys/class/net        "00:1a:2b:3c:4d:5e"
```

### 5.2 Fingerprint Computation

```
raw_fingerprint = concat(
    machine_id,
    cpu_model_and_cores,
    motherboard_serial,
    disk_serial,
    nic_mac
)

hardware_fingerprint = HMAC-SHA256(
    message: raw_fingerprint,
    key:     salt_from_license_file
)

Result: "hwfp_3a8f2b1c9d4e7f6a0b3c8d1e4f7a2b5..."  (256-bit hash)
```

### 5.3 Threshold Matching

To tolerate minor hardware changes (e.g., NIC replacement), the guardian computes
individual hashes for each component and requires **3 out of 5** to match the values
stored in the license file.

```
License file stores:     [hash_machineId, hash_cpu, hash_mobo, hash_disk, hash_nic]
Guardian computes live:  [hash_machineId, hash_cpu, hash_mobo, hash_disk, hash_nic_NEW]

Match count: 4/5 → PASS (threshold is 3)

If machine cloned to new hardware:
Live:  [hash_machineId_NEW, hash_cpu_NEW, hash_mobo_NEW, hash_disk_NEW, hash_nic_NEW]
Match count: 0/5 → FAIL
```

---

## 6. License File Structure

### 6.1 License JSON (Payload)

```json
{
  "license_id": "LIC-2026-00451",
  "version": 1,
  "issued_to": "Bitcomm Technologies - RDPMS Deployment",
  "issued_at": "2026-02-15T00:00:00Z",
  "expires_at": "2027-02-15T00:00:00Z",

  "hardware": {
    "salt": "random_salt_for_fingerprint_hmac",
    "fingerprints": {
      "machine_id": "hash_of_machine_id",
      "cpu": "hash_of_cpu_info",
      "motherboard": "hash_of_mobo_serial",
      "disk": "hash_of_disk_serial",
      "nic": "hash_of_nic_mac"
    },
    "match_threshold": 3
  },

  "modules": {
    "rdpms-core": {
      "enabled": true,
      "max_users": 50,
      "max_sensors": 500,
      "features": ["realtime-alerts", "historical-reports", "data-export"],
      "limits": {
        "max_data_retention_days": 365,
        "max_concurrent_connections": 100
      }
    },
    "eids": {
      "enabled": true,
      "max_cameras": 20,
      "max_zones": 10,
      "features": ["thermal-detection", "ai-classification", "alert-sms"],
      "limits": {
        "max_events_per_day": 10000
      }
    },
    "analytics": {
      "enabled": false,
      "features": [],
      "limits": {}
    }
  },

  "global_limits": {
    "max_total_users": 200,
    "max_registered_services": 20
  }
}
```

### 6.2 License File Format (Signed)

The actual `.license` file wraps the JSON payload with a signature:

```
┌────────────────────────────────────────────────────────────┐
│  GUARDIAN-LICENSE-V1                                         │
│  ──────────────────                                         │
│  PAYLOAD: <base64 encoded JSON from above>                  │
│  SIGNATURE: <Ed25519 signature of the payload bytes>        │
│  SIGNER: <fingerprint of master.pub that signed this>       │
└────────────────────────────────────────────────────────────┘
```

### 6.3 License Verification on Guardian Startup

```
1. Read guardian.license file
2. Parse PAYLOAD and SIGNATURE
3. Load master.pub (embedded in binary or from /etc/guardian/master.pub)
4. Verify: Ed25519_Verify(master.pub, PAYLOAD, SIGNATURE)
   → If INVALID: refuse to start, log error
5. Decode PAYLOAD JSON
6. Compute live hardware fingerprints
7. Compare against license.hardware.fingerprints using threshold
   → If < threshold match: refuse to start, log hardware mismatch
8. Check expiry: if expires_at < now → refuse to start
9. License loaded successfully → start accepting connections
```

---

## 7. Communication Protocol

### 7.1 Wire Format (Length-Prefixed Binary over Unix Socket)

Every message on the socket follows this frame format:

```
┌───────────────┬──────────────┬──────────────────────────────┐
│ 4 bytes       │ 1 byte       │ N bytes                      │
│ uint32 BE     │ uint8        │ msgpack payload               │
│ total length  │ message type │ (or encrypted blob post-auth) │
└───────────────┴──────────────┴──────────────────────────────┘

Total length = 1 (type) + N (payload)
```

### 7.2 Message Types

```
CODE   NAME               DIRECTION            PHASE
────   ────               ─────────            ─────
0x01   GUARDIAN_HELLO      guardian → service    Handshake
0x02   SERVICE_AUTH        service → guardian    Handshake
0x03   AUTH_RESULT         guardian → service    Handshake
0x04   LICENSE_REQUEST     service → guardian    Licensed (encrypted)
0x05   LICENSE_RESPONSE    guardian → service    Licensed (encrypted)
0x06   HEARTBEAT_PING      service → guardian    Licensed (encrypted)
0x07   HEARTBEAT_PONG      guardian → service    Licensed (encrypted)
0x08   REVOKE_NOTICE       guardian → service    Licensed (encrypted)
0xFF   ERROR               either direction      Any phase
```

---

## 8. Handshake Protocol — Complete Flow

### 8.1 Full Sequence Diagram

```
 SERVICE                                            GUARDIAN
    │                                                   │
    │──────── TCP Connect to UDS ──────────────────────▶│
    │                                                   │
    │                     ┌─────────────────────────────┐│
    │                     │ Generate random nonce (32B)  ││
    │                     │ Sign nonce with daemon.key   ││
    │                     └─────────────────────────────┘│
    │                                                   │
    │◀──────── 0x01 GUARDIAN_HELLO ─────────────────────│
    │  {                                                │
    │    guardian_nonce: "gn_8f2a...",                   │
    │    signature: "sig_e4f5..."                        │
    │  }                                                │
    │                                                   │
   ┌┤                                                   │
   ││ Load DAEMON_PUB from token file                   │
   ││ Verify(DAEMON_PUB, guardian_nonce, signature)      │
   ││ → TRUE: guardian is legitimate                     │
   ││ → FALSE: DISCONNECT (fake guardian)                │
   └┤                                                   │
    │                                                   │
    │  ┌─────────────────────────────────────────┐      │
    │  │ Generate client_nonce (32B)              │      │
    │  │ Read TOKEN from token file              │      │
    │  │ hmac = HMAC-SHA256(                     │      │
    │  │   message: guardian_nonce + client_nonce │      │
    │  │   key: TOKEN                            │      │
    │  │ )                                       │      │
    │  └─────────────────────────────────────────┘      │
    │                                                   │
    │──────── 0x02 SERVICE_AUTH ───────────────────────▶│
    │  {                                                │
    │    service_id: "rdpms-core",                      │
    │    client_nonce: "cn_7a8b...",                     │
    │    hmac: "hmac_3c4d..."                            │
    │  }                                                │
    │                                 ┌─────────────────┤
    │                                 │ Look up token    │
    │                                 │ for "rdpms-core" │
    │                                 │ from tokens.db   │
    │                                 │                  │
    │                                 │ Compute expected │
    │                                 │ HMAC with same   │
    │                                 │ inputs + token   │
    │                                 │                  │
    │                                 │ Compare HMACs    │
    │                                 │ → MATCH: trusted │
    │                                 │ → MISMATCH: reject│
    │                                 │                  │
    │                                 │ Derive session:  │
    │                                 │ session_key =    │
    │                                 │  HMAC-SHA256(    │
    │                                 │   gn + cn,       │
    │                                 │   token+"sess"   │
    │                                 │  )               │
    │                                 └─────────────────┤
    │                                                   │
    │◀──────── 0x03 AUTH_RESULT ────────────────────────│
    │  {                                                │
    │    status: "ok",                                  │
    │    session_id: "sess_f1e2d3..."                   │
    │  }                                                │
    │                                                   │
   ┌┤                                                   │
   ││ Service also derives same session_key             │
   ││ (it has the same inputs: gn, cn, token)           │
   └┤                                                   │
    │                                                   │
    │  ════════ ENCRYPTED CHANNEL ESTABLISHED ═════════ │
    │  All further messages encrypted with AES-256-GCM  │
    │  using session_key                                │
    │                                                   │
    │──────── 0x04 LICENSE_REQUEST (encrypted) ────────▶│
    │  AES_GCM_Encrypt(                                 │
    │    plaintext: {"module":"rdpms-core"},             │
    │    key: session_key                               │
    │  )                                                │
    │                                                   │
    │◀──────── 0x05 LICENSE_RESPONSE (encrypted) ──────│
    │  AES_GCM_Encrypt(                                 │
    │    plaintext: {                                    │
    │      "valid": true,                               │
    │      "module": "rdpms-core",                      │
    │      "max_users": 50,                             │
    │      "features": ["realtime-alerts", ...],        │
    │      "expires_at": "2027-02-15T00:00:00Z"         │
    │    },                                             │
    │    key: session_key                               │
    │  )                                                │
    │                                                   │
```

### 8.2 Session Key Derivation (Both Sides Compute Independently)

```
Both guardian and service know:
  - guardian_nonce  (sent in GUARDIAN_HELLO)
  - client_nonce   (sent in SERVICE_AUTH)
  - token          (from their respective storage)

session_key = HMAC-SHA256(
    message: guardian_nonce || client_nonce,
    key:     token || "guardian-session-v1"
)

This produces a 256-bit key used for AES-256-GCM.

Properties:
  - Unique per connection (nonces are random each time)
  - Cannot be computed without knowing the token
  - Both sides arrive at the same key independently (no key exchange needed)
```

---

## 9. Service Deployment Patterns

### 9.1 Docker Services (docker-compose.yml)

```yaml
version: "3.8"

services:
  rdpms-core:
    image: rdpms-core:latest
    volumes:
      # Mount the Unix socket (read-only)
      - /var/run/guardian/guardian.sock:/var/run/guardian/guardian.sock:ro
      # Mount THIS service's token file (read-only)
      - /etc/guardian/tokens/rdpms-core.token:/etc/guardian/token:ro
    # Service code reads:
    #   Socket: /var/run/guardian/guardian.sock
    #   Token:  /etc/guardian/token  (standard path inside container)

  eids-processor:
    image: eids-processor:latest
    volumes:
      - /var/run/guardian/guardian.sock:/var/run/guardian/guardian.sock:ro
      - /etc/guardian/tokens/eids-processor.token:/etc/guardian/token:ro
```

> **Note:** Each container sees its own token at `/etc/guardian/token` — a consistent
> path regardless of which service it is. The host maps the correct file.

### 9.2 Native Systemd Services

```ini
# /etc/systemd/system/analytics.service
[Unit]
Description=Analytics Service
After=guardian.service
Requires=guardian.service

[Service]
Type=simple
ExecStart=/usr/local/bin/analytics-service
Environment=GUARDIAN_SOCKET=/var/run/guardian/guardian.sock
Environment=GUARDIAN_TOKEN_PATH=/etc/guardian/tokens/analytics.token
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 9.3 Any Other Application (Manual/Script)

```bash
# Python
export GUARDIAN_SOCKET="/var/run/guardian/guardian.sock"
export GUARDIAN_TOKEN_PATH="/etc/guardian/tokens/myapp.token"
python3 myapp.py

# Java
java -Dguardian.socket=/var/run/guardian/guardian.sock \
     -Dguardian.token=/etc/guardian/tokens/myapp.token \
     -jar myapp.jar
```

### 9.4 Universal Client Code Pattern

Regardless of deployment method, the client code is identical:

```go
// Works the same in Docker, systemd, or bare metal
client := guardian.NewClient(
    guardian.WithSocket(os.Getenv("GUARDIAN_SOCKET")),        // default: /var/run/guardian/guardian.sock
    guardian.WithTokenFile(os.Getenv("GUARDIAN_TOKEN_PATH")), // default: /etc/guardian/token
)

info, err := client.CheckLicense("rdpms-core")
if err != nil {
    log.Fatal("License check failed:", err)
}

if !info.Valid {
    log.Fatal("License invalid for module rdpms-core")
}

fmt.Printf("Max users: %d\n", info.MaxUsers)
fmt.Printf("Features: %v\n", info.Features)
```

---

## 10. Guardian Daemon Lifecycle

### 10.1 Systemd Unit File

```ini
# /etc/systemd/system/guardian.service
[Unit]
Description=Guardian License Service
After=network.target
Before=docker.service

[Service]
Type=notify
ExecStart=/usr/local/bin/guardiand --config /etc/guardian/guardian.conf
ExecReload=/bin/kill -HUP $MAINPID

Restart=on-failure
RestartSec=3
WatchdogSec=30

# Security hardening
ProtectSystem=strict
ReadWritePaths=/var/run/guardian /var/log/guardian /etc/guardian
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

### 10.2 Startup Sequence

```
guardiand process starts
    │
    ├─ 1. Load /etc/guardian/guardian.conf
    │
    ├─ 2. Load /etc/guardian/master.pub (office public key)
    │
    ├─ 3. Load /etc/guardian/guardian.license
    │     ├─ Parse payload + signature
    │     ├─ Verify signature against master.pub
    │     └─ FAIL → exit with error
    │
    ├─ 4. Compute live hardware fingerprint
    │     ├─ Read machine-id, cpu, mobo, disk, nic
    │     ├─ Compare against license.hardware.fingerprints
    │     ├─ Check threshold (3/5 match required)
    │     └─ FAIL → exit with error
    │
    ├─ 5. Check license expiry
    │     └─ FAIL → exit with error
    │
    ├─ 6. Load or generate daemon key pair
    │     ├─ If /etc/guardian/daemon.key exists → load it
    │     └─ If first boot → generate Ed25519 pair, save to daemon.key + daemon.pub
    │
    ├─ 7. Load token database (tokens.db)
    │
    ├─ 8. Create Unix socket at /var/run/guardian/guardian.sock
    │
    ├─ 9. Notify systemd: ready
    │
    └─ 10. Start accepting connections + start watchdog timer
           ├─ Watchdog: re-verify hardware every 5 minutes
           ├─ Watchdog: check license expiry every 1 minute
           └─ On failure: send REVOKE_NOTICE to all active sessions, shut down
```

---

## 11. Admin CLI — guardian-cli

### 11.1 Service Registration

```bash
# Register a new service (generates token + writes credential file)
$ guardian-cli register --service=rdpms-core
✓ Generated token for rdpms-core
✓ Written to /etc/guardian/tokens/rdpms-core.token
✓ Registered in guardian database
✓ Permissions: root:root 0600

# Register with specific modules allowed
$ guardian-cli register --service=eids-processor --modules=eids,analytics
```

### 11.2 Service Management

```bash
# List all registered services
$ guardian-cli list-services
SERVICE           REGISTERED          LAST SEEN      STATUS    MODULES
rdpms-core        2026-02-15 10:30    2 minutes ago  active    rdpms-core
eids-processor    2026-02-15 10:31    5 minutes ago  active    eids
analytics         2026-02-15 10:32    never          inactive  analytics

# Revoke a service (immediate disconnect + delete token file)
$ guardian-cli revoke --service=analytics

# Rotate a token (new token, service must restart)
$ guardian-cli rotate --service=rdpms-core

# Show guardian status
$ guardian-cli status
Guardian Status:
  License:     VALID (expires 2027-02-15)
  Hardware:    MATCH (5/5 components)
  Uptime:      3 days 14 hours
  Active:      2 sessions
  Socket:      /var/run/guardian/guardian.sock
```

### 11.3 License Information

```bash
# Show loaded license details
$ guardian-cli license-info
License ID:    LIC-2026-00451
Issued To:     Bitcomm Technologies - RDPMS Deployment
Issued At:     2026-02-15
Expires At:    2027-02-15
Hardware:      5/5 match (OK)

Modules:
  rdpms-core:      ENABLED  (50 users, 500 sensors)
  eids:            ENABLED  (20 cameras, 10 zones)
  analytics:       DISABLED

# Show hardware fingerprint details
$ guardian-cli hardware-info
Component        Status    Detail
machine-id       MATCH     a1b2c3d4...
cpu              MATCH     Intel Xeon E5-2680 v4 x28
motherboard      MATCH     W2KS42903817
disk             MATCH     WD-WMC4N0K1LRJX
nic              MATCH     00:1a:2b:3c:4d:5e
Overall:         5/5 PASS (threshold: 3)
```

---

## 12. License Generation (Your Office)

### 12.1 One-Time Setup

```bash
# Generate master key pair (do this ONCE, store private key securely)
$ license-gen init
✓ Generated master key pair
✓ Private key: /secure/path/master.priv  ← GUARD THIS WITH YOUR LIFE
✓ Public key:  /secure/path/master.pub   ← ship this with guardian
```

### 12.2 Generating a License for a Customer Machine

```bash
# Step 1: Customer sends you their hardware info
# (guardian-cli can export this)
$ guardian-cli export-hardware > hardware-info.json

# Step 2: At your office, generate the license
$ license-gen create \
    --hardware=hardware-info.json \
    --customer="Bitcomm - RDPMS Railway Division" \
    --expires=2027-02-15 \
    --module rdpms-core:max_users=50,max_sensors=500 \
    --module eids:max_cameras=20,max_zones=10 \
    --sign-with=/secure/path/master.priv \
    --output=customer-001.license

# Step 3: Send customer-001.license to the customer
# They place it at /etc/guardian/guardian.license
```

---

## 13. Security Attack Matrix

```
ATTACK VECTOR                    PROTECTION                         RESULT
──────────────────────────────   ──────────────────────────────     ──────
Clone VM / disk to new machine   Hardware fingerprint mismatch       BLOCKED
                                 (different CPU, mobo, disk, NIC)

Edit license (change max_users)  Ed25519 signature verification      BLOCKED
                                 (signature breaks without priv key)

Fake guardian on socket           Service verifies daemon_pub          BLOCKED
                                 signature from token file

Rogue container connects          No valid token → HMAC mismatch      BLOCKED

Replay captured handshake         Random nonces per connection         BLOCKED
                                 (old HMAC won't match new nonces)

Eavesdrop on Unix socket          AES-256-GCM encrypted after         BLOCKED
                                 handshake (session key per conn)

Attacker reads token file         File perms 0600 root:root           BLOCKED
(non-root user)                  (only root can read)

Reverse engineer binary           garble obfuscation + keys           DIFFICULT
                                 derived at runtime from hardware

License expires mid-operation     Watchdog checks every 1 minute       DETECTED
                                 → REVOKE_NOTICE to all sessions

Hardware changes mid-operation    Watchdog re-checks every 5 min       DETECTED
                                 → REVOKE_NOTICE to all sessions

Full root compromise              ✗ No software defense possible       NOT IN
                                 (true for any system)                SCOPE
```

---

## 14. Periodic Health Checks

### 14.1 Service-Side Polling

Services should not just check once at startup. They must poll periodically:

```
STARTUP
   │
   ├─ Connect to guardian
   ├─ Handshake (mutual authentication)
   ├─ Check license → OK → start normally
   │
   │  ┌──── EVERY 5 MINUTES ────┐
   │  │                          │
   │  ├─ Send HEARTBEAT_PING     │
   │  │                          │
   │  ├─ Receive HEARTBEAT_PONG  │
   │  │  {                       │
   │  │   hw_status: "ok",       │
   │  │   license_status: "ok",  │
   │  │   expires_in_days: 334   │
   │  │  }                       │
   │  │                          │
   │  └──── LOOP ────────────────┘
   │
   │  IF HEARTBEAT FAILS or REVOKE_NOTICE received:
   │  ├─ Log warning
   │  ├─ Enter degraded mode (read-only / limited features)
   │  └─ After N consecutive failures → shut down gracefully
```

### 14.2 Guardian-Side Watchdog

```
GUARDIAN WATCHDOG (runs in background goroutine)
    │
    ├─ Every 1 minute:  Check license expiry
    ├─ Every 5 minutes: Re-compute hardware fingerprint
    ├─ Every 1 hour:    Rotate daemon nonce seed (forward secrecy)
    │
    └─ On any failure:
        ├─ Send REVOKE_NOTICE to ALL active sessions
        ├─ Log detailed reason
        └─ If hardware mismatch: shut down daemon
```

---

## 15. Configuration File

```ini
# /etc/guardian/guardian.conf

[daemon]
socket_path = /var/run/guardian/guardian.sock
log_path = /var/log/guardian/guardian.log
log_level = info
pid_file = /var/run/guardian/guardian.pid

[license]
license_file = /etc/guardian/guardian.license
master_pub = /etc/guardian/master.pub

[crypto]
daemon_key = /etc/guardian/daemon.key
daemon_pub = /etc/guardian/daemon.pub
token_db = /etc/guardian/tokens.db

[watchdog]
hardware_check_interval = 5m
license_check_interval = 1m
session_timeout = 30m

[security]
max_connections = 50
max_auth_attempts = 3
auth_timeout = 10s
nonce_size = 32
```

---

## 16. Complete Trust Chain — End to End

```
YOUR OFFICE                    TARGET MACHINE                  MICROSERVICE
────────────                   ──────────────                  ────────────

1. Generate master              
   key pair                    
   (master.priv + .pub)        
         │                     
         │ ship master.pub     
         ├────────────────────▶ 2. Install guardian binary
         │                        (has master.pub embedded)
         │                     
         │                      3. Guardian first boot:
         │                         - generates daemon key pair
         │                         - daemon.key + daemon.pub
         │                     
         │                      4. Admin exports hardware info:
         │                         guardian-cli export-hardware
         │◀────────────────────    sends hardware-info.json
         │                     
5. Generate signed license     
   using master.priv +         
   hardware-info.json          
         │                     
         │ ship .license file  
         ├────────────────────▶ 6. Place at /etc/guardian/guardian.license
         │                     
         │                      7. Guardian verifies license:
         │                         - signature OK (master.pub)
         │                         - hardware OK (fingerprint match)
         │                         - expiry OK
         │                     
         │                      8. Admin registers services:
         │                         guardian-cli register --service=X
         │                         → creates /etc/guardian/tokens/X.token
         │                         → contains TOKEN + DAEMON_PUB
         │                     
         │                                    │
         │                                    │ mount token file
         │                                    │ mount guardian.sock
         │                                    ▼
         │                                                      9. Service starts:
         │                                                         reads token file
         │                                                         connects to socket
         │                                                         mutual handshake
         │                                                         requests license info
         │                                                         ✓ OPERATIONAL
```

---

## 17. Quick Reference — CLI Commands

```bash
# === ON YOUR OFFICE MACHINE ===
license-gen init                              # Generate master key pair (once)
license-gen create --hardware=hw.json ...      # Create signed license

# === ON TARGET MACHINE ===
# Installation
sudo cp guardiand /usr/local/bin/
sudo cp guardian-cli /usr/local/bin/
sudo cp guardian.service /etc/systemd/system/
sudo systemctl enable --now guardian

# Setup
sudo guardian-cli import-license customer.license
sudo guardian-cli register --service=rdpms-core
sudo guardian-cli register --service=eids-processor

# Operations
sudo guardian-cli status                       # Overall health
sudo guardian-cli license-info                 # License details
sudo guardian-cli hardware-info                # Hardware check
sudo guardian-cli list-services                # All services
sudo guardian-cli rotate --service=rdpms-core  # Rotate token
sudo guardian-cli revoke --service=analytics   # Remove service
sudo guardian-cli export-hardware              # For license renewal
```
