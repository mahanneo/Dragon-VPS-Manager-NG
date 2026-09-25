# Changelog

All notable changes to Dragon VPS Manager NG are documented here.

## [0.1.0-alpha] - 2026-09-25

### Added
- Responsive black/gold administration panel.
- Signed HttpOnly admin sessions and scrypt password hashing.
- CPU, memory, disk, load, uptime and network overview.
- SSH system-user create/list/lock/unlock/delete operations.
- Allowlisted systemd service management.
- Audit log for security-sensitive actions.
- Ubuntu 22.04/24.04 source installer with Nginx and systemd.
- GitHub-first bootstrap installer, updater, backup and uninstall helpers.
- Basic CI syntax/security checks.

### Security
- No arbitrary shell execution endpoint.
- Removed shared default administrator password. The installer generates a unique bootstrap password for each installation.

> This is an alpha foundation release. It is not yet production-certified.
