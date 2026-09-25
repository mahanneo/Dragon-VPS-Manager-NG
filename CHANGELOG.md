# Changelog

## [0.2.0-alpha] - 2026-09-26

### Changed
- Product renamed to **Makia VPS Manager**.
- New premium dark/glass dashboard direction with stronger visual hierarchy.
- Added richer host telemetry and live SSH session visibility.
- Navigation reorganized for future Accounts, Sessions, Services, Security, Backups, Updates and Settings modules.
- Legacy DRAGON environment variable names remain temporarily accepted as migration aliases.

### Added
- Hostname, kernel, CPU core, memory byte, swap and disk byte telemetry.
- Live SSH session list sourced from the host.
- New dashboard KPI and operational status surfaces.

## [0.1.0-alpha] - 2026-09-25

### Added
- Initial web management foundation.
- Signed HttpOnly admin sessions and scrypt password hashing.
- CPU, memory, disk, load, uptime and network overview.
- SSH account create/list/lock/unlock/delete operations.
- Allowlisted systemd service management.
- Audit log, installer, backup, update, uninstall and CI scaffolding.
