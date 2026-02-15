# Guardian License Service

## Project Overview
Guardian is a native Linux daemon that acts as the root of trust for license enforcement. It hardware-binds a cryptographically signed license and provides license validation services via Unix domain sockets.

## Build & Test

```bash
# Run all tests
go test ./... -v

# Run tests for a specific package
go test ./internal/crypto/ -v
go test ./internal/protocol/ -v
go test ./internal/server/ -v

# Build all binaries
go build -o bin/guardiand ./cmd/guardiand/
go build -o bin/guardian-cli ./cmd/guardian-cli/
go build -o bin/license-gen ./cmd/license-gen/

# Run with race detector
go test -race ./...
```

## Architecture
- `internal/crypto/` - Ed25519 signing, AES-256-GCM encryption, HMAC-SHA256
- `internal/fingerprint/` - Hardware fingerprint collection and threshold matching
- `internal/license/` - License file parsing, signature verification, expiry checks
- `internal/protocol/` - Binary wire format (length-prefixed msgpack over UDS)
- `internal/auth/` - Handshake protocol, token management, session keys
- `internal/server/` - Unix domain socket server, connection handling
- `internal/watchdog/` - Periodic hardware and license re-checks
- `internal/config/` - INI-style configuration file parser
- `client/go/` - Go client SDK for services
- `cmd/guardiand/` - Main daemon binary
- `cmd/guardian-cli/` - Admin CLI tool
- `cmd/license-gen/` - License generation tool (issuer's office)

## Key Design Decisions
- Wire format: 4-byte BE length + 1-byte type + msgpack payload
- Mutual authentication via HMAC-SHA256 handshake
- Session keys derived independently by both sides (no key exchange)
- Hardware fingerprint uses 3-of-5 threshold matching for tolerance
- All post-handshake communication is AES-256-GCM encrypted

## Dependencies
- `github.com/vmihailenco/msgpack/v5` - Compact binary serialization
- Go stdlib only for crypto (ed25519, aes, hmac, sha256)
