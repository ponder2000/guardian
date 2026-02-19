# Guardian Manager Setup

Guardian Manager is a self-contained web admin panel for managing keys, projects, hardware configs, licenses, users, and audit logs — replacing the need for CLI-based license management in day-to-day operations.

## Quick Start

### Docker Compose (Recommended)

```yaml
# docker-compose.yml
services:
  guardian-manager:
    image: jaysaha/guardian-manager:latest
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

```bash
docker compose up -d
```

Open `http://localhost:8080` and log in with the default credentials:

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `changeme` |

> **Change the default password immediately** after first login.

The SQLite database is persisted in the `./data` directory on the host.

### Docker Run

```bash
docker run -d \
  --name guardian-manager \
  -p 8080:8080 \
  -v ./data:/app/data \
  --restart unless-stopped \
  jaysaha/guardian-manager:latest
```

### From Source

```bash
# Clone the repo
git clone https://github.com/ponder2000/guardian.git
cd guardian

# Run directly
make run-manager

# Or build and run
go build -o bin/guardian-manager ./cmd/guardian-manager/
./bin/guardian-manager --listen=:8080 --db=data/guardian-manager.db
```

## Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--db <path>` | `data/guardian-manager.db` | Path to SQLite database file |
| `--listen <addr>` | `:8080` | HTTP listen address |
| `--version` | — | Show version and exit |

---

## Features

### Dashboard

The dashboard provides an at-a-glance view of:
- Total license count
- Licenses expiring soon
- Recent administrative activity

### User Management

Guardian Manager supports multiple users with role-based access:

| Role | Permissions |
|------|-------------|
| **Admin** | Full access — manage users, keys, projects, licenses, access control |
| **Viewer** | Read-only access to assigned projects |

**Operations:**
- Create, edit, and delete users
- Assign roles (admin/viewer)
- Password-based authentication

### Key Management

Manage Ed25519 master key pairs used for signing licenses.

**Operations:**
- **Generate** a new key pair directly in the browser
- **Import** an existing key pair (from `license-gen init`)
- **Download** public keys for deployment to target machines
- **Set default** signing key for new licenses

### Project Management

Organize licenses by customer or deployment. Each project can contain:
- One or more hardware configurations
- One or more licenses
- Access grants for specific users

**Operations:**
- Create, edit, and delete projects
- Assign hardware configs and licenses to projects
- Grant/revoke user access per project

### Hardware Configurations

Store hardware fingerprints collected from target machines.

**Operations:**
- **Upload** hardware JSON files (from `guardian-cli export-hardware`)
- **Edit** individual component values
- Associate with a project for license generation

### License Management

Create, update, and distribute signed license files.

**Operations:**
- **Create** a new license from a hardware config, selecting modules and metadata
- **Update** modules, metadata, expiration, or match threshold on existing licenses
- **Download** `.license` files for deployment
- **View** full license details (decoded payload)

### Access Control

Fine-grained user-project access matrix:
- Grant users access to specific projects
- Revoke access when no longer needed
- Admin users bypass access restrictions

### Audit Log

Every administrative action is logged:
- License creation and updates
- Key generation and imports
- User management changes
- Access control changes
- Failed login attempts
- Searchable by action type, user, and date

### Repository

A download center for distributing files to target machines:
- Browse and download public keys
- Browse and download license files

### Export / Import

Backup and restore the entire manager database:
- **Export** — downloads a JSON file containing all projects, licenses, keys, hardware configs, and users
- **Import** — restores from a previously exported JSON file

---

## Typical Workflow

### 1. Initial Setup

1. Deploy Guardian Manager (Docker or source)
2. Log in with default credentials, change password
3. Create additional user accounts as needed

### 2. Generate Keys

1. Go to **Keys** and click **Generate New Key Pair**
2. Set the new key as the **default signing key**
3. Download `master.pub` for deployment to target machines

### 3. Create a Project

1. Go to **Projects** and create a new project (e.g., "ACME Corp - Production")
2. Grant access to relevant users

### 4. Add Hardware Config

1. On the target machine, run:
   ```bash
   sudo guardian-cli export-hardware > hardware-info.json
   ```
2. In Guardian Manager, go to the project and click **Add Hardware Config**
3. Upload `hardware-info.json`

### 5. Create a License

1. In the project, click **Create License**
2. Select the hardware config
3. Set expiration date
4. Add modules with features and metadata
5. Set match threshold (default: 3 of 5)
6. Click **Create** — the license is signed with the default key

### 6. Deploy

1. Download the `.license` file and `master.pub` from the **Repository**
2. Copy to the target machine:
   ```bash
   sudo cp master.pub /etc/guardian/master.pub
   sudo cp customer.license /etc/guardian/guardian.license
   sudo systemctl restart guardian
   ```

### 7. Ongoing Management

- **Extend licenses** — edit expiration date, re-download
- **Add modules** — update the license, re-deploy
- **Rotate keys** — generate a new key pair, re-sign affected licenses
- **Audit** — review the audit log for compliance

---

## Production Considerations

### Reverse Proxy

For production, run Guardian Manager behind a reverse proxy with TLS:

```nginx
server {
    listen 443 ssl;
    server_name guardian.example.com;

    ssl_certificate     /etc/ssl/certs/guardian.pem;
    ssl_certificate_key /etc/ssl/private/guardian.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Backup

The entire state is in a single SQLite file. Back it up regularly:

```bash
# Simple copy (stop the service first for consistency)
cp data/guardian-manager.db data/guardian-manager.db.bak

# Or use the built-in Export feature for a JSON backup
```

### Data Persistence (Docker)

Always mount a host volume for the data directory:

```yaml
volumes:
  - ./data:/app/data
```

Without this, the database is lost when the container is recreated.
