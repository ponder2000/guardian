# Guardian

A hardware-bound license enforcement daemon for Linux. Guardian runs as a systemd service and provides license validation to any application — Docker containers or native processes — over a Unix domain socket with mutual authentication and encrypted communication.

## How It Works

1. **License Generation** — Generate an Ed25519 master key pair and sign a license file bound to the target machine's hardware fingerprint.
2. **Daemon Startup** — `guardiand` verifies the license signature, checks hardware fingerprint (3-of-5 threshold match), and opens a Unix domain socket.
3. **Service Authentication** — Each service connects and performs a mutual handshake: the daemon proves identity via Ed25519 signature, the service proves it holds a valid token via HMAC-SHA256.
4. **Encrypted Channel** — All post-handshake communication is AES-256-GCM encrypted with a per-session key derived from handshake nonces.
5. **Periodic Checks** — The watchdog re-verifies hardware and license expiry. On failure, a `REVOKE_NOTICE` is broadcast to all connected services.

## Components

| Component | Purpose |
|-----------|---------|
| `guardiand` | Main daemon — listens on Unix socket, validates licenses |
| `guardian-cli` | Admin CLI — register services, check status, rotate tokens |
| `license-gen` | License tool — generate keys, create/update/decode/verify licenses |
| `guardian-manager` | Web admin panel — manage keys, projects, licenses, users |
| `client/go` | Go client SDK |
| `client/python` | Python client SDK |
| `client/java` | Java client SDK |

## Tech Stack

| What | Technology |
|------|------------|
| Language | Go (static binary, no runtime deps) |
| IPC | Unix Domain Socket |
| Signing | Ed25519 |
| Auth | HMAC-SHA256 mutual authentication |
| Encryption | AES-256-GCM |
| Wire Format | msgpack (length-prefixed binary) |

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, wire protocol, handshake flow, security model, configuration reference |
| [CLI Reference](docs/cli.md) | All `guardian-cli` commands, flags, and usage examples |
| [License Tools](docs/license-tools.md) | `license-gen` commands for key generation, license creation, updates, and verification |
| [Manager Setup](docs/manager.md) | Guardian Manager web panel — deployment, features, and workflow |

## Quick Start

```bash
# Build all binaries
make build

# Or build individually
go build -o guardiand ./cmd/guardiand
go build -o guardian-cli ./cmd/guardian-cli
go build -o license-gen ./cmd/license-gen

# Run tests
make test
```

### Debian Package

```bash
make package-deb
sudo dpkg -i bin/guardian_0.1.0_amd64.deb
```

### Guardian Manager (Docker)

```bash
docker run -d -p 8080:8080 -v ./data:/app/data jaysaha/guardian-manager:latest
# Open http://localhost:8080 — default login: admin / changeme
```

## Examples

<!--
TODO: Add Guardian Manager screenshots and walkthrough examples
- Dashboard overview
- Key generation
- Project creation
- Hardware config upload
- License creation and download
- Service registration
- SDK integration examples
-->

*Coming soon — Guardian Manager screenshots and end-to-end walkthrough.*

## License

Proprietary. All rights reserved.
