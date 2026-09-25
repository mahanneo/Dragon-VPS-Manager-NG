# 🐉 Dragon VPS Manager NG

A modern, web-based VPS management foundation inspired by the operational goals of the legacy DRAGON VPS Manager project, implemented as a clean-room architecture focused on safer browser administration.

> **Status:** `v0.1.0-alpha` — testing foundation, not production-certified yet.

## Current features

- Responsive black/gold Web Admin Panel
- Secure signed HttpOnly administrator sessions
- Scrypt password hashing
- Unique bootstrap administrator password per installation
- Live CPU / RAM / Disk / Load / Uptime / Network dashboard
- SSH system-user listing, creation, lock/unlock and deletion
- Allowlisted systemd service control (no arbitrary web shell)
- Audit trail for security-sensitive actions
- Ubuntu 22.04 LTS and Ubuntu 24.04 LTS installer
- Nginx reverse proxy and systemd service
- Backup, update and uninstall helpers
- Health endpoint and CI checks

## Quick install

Use a **fresh test VPS** first. Run as root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mahanneo/Makia-VPS-Manager/main/install.sh)
```

At the end of installation the terminal prints:

- panel URL
- username `admin`
- a unique generated bootstrap password

Sign in and change the password immediately.

## Server requirements

- Ubuntu 22.04 LTS or Ubuntu 24.04 LTS
- Root access
- Recommended minimum: 1 vCPU, 1 GB RAM, 10 GB free storage
- TCP 80 temporarily available for the alpha web panel

## Update

```bash
sudo dragon-update
```

The updater creates a data backup before replacing application code and runs a local health check afterward.

## Backup

```bash
sudo dragon-backup
```

Backups are stored under `/var/backups/dragon-vps-manager-ng/` with root-only permissions.

## Uninstall

```bash
sudo dragon-uninstall
```

The uninstall helper preserves backups.

## Architecture

```text
Browser
  ↓
Nginx
  ↓
FastAPI UI/API (127.0.0.1:8787)
  ↓
Allowlisted privileged operations
  ↓
Linux / systemd / SSH users
```

The browser never receives a generic root shell endpoint. New privileged features must be added as explicit, validated operations.

## Security notes

Before production use:

1. Enable HTTPS.
2. Restrict administration by firewall, VPN or trusted IPs where possible.
3. Change the generated bootstrap password immediately.
4. Review every newly allowlisted system service and privileged operation.
5. Do not add arbitrary command execution endpoints.
6. Test upgrades and rollback behavior on a disposable VPS before production rollout.

See [`docs/SECURITY.md`](docs/SECURITY.md) for additional notes.

## Development branches

- `main` — public release line
- `develop` — integration/development line
- `feature/*` — isolated feature work

## Roadmap

Planned milestones include online SSH sessions, per-user connection limits, expiration enforcement, disconnect controls, protocol/port management, Stunnel/WebSocket configuration, HTTPS, firewall/Fail2ban controls, backup/restore UI, Telegram integration, 2FA and versioned rollback.

## License

See [`LICENSE`](LICENSE). When migrating functionality from third-party projects, verify their licenses before reusing source code. Prefer clean-room reimplementation where licensing is unclear.
