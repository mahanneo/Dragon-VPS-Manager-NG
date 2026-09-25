# Makia VPS Manager — Product Roadmap

## Product principle
Makia is a web-first VPS control plane. The browser never receives an unrestricted root shell. Every privileged capability must be implemented through a typed, validated adapter with audit logging and rollback where configuration changes are involved.

## v0.2 — Account & Session Center
- Account lifecycle: create, edit, suspend, resume, delete
- Expiration date and remaining-days state
- Traffic quota model and reset action
- Concurrent session / IP policy model
- Live sessions with source IP and login time
- Controlled disconnect
- Search, filters, sorting and bulk actions
- Expiring-soon / quota-near-limit dashboard widgets

## v0.3 — Xray & Protocol Center
- Xray process integration with explicit config ownership
- VLESS / VMess / Trojan / Shadowsocks adapters where validated
- Inbound CRUD
- Port collision validation
- TLS / Reality-related configuration only where supported by the installed core
- Share links and QR codes
- Subscription endpoint and per-account subscription page
- Config validation before restart and automatic rollback on failed health check

## v0.4 — Security Center
- UFW/nftables abstraction
- Fail2ban status and jails
- Trusted admin IP allowlist
- HTTPS certificate automation
- Login throttling and lockout policy
- TOTP 2FA
- Active admin sessions and revoke
- Scoped API tokens
- Security event timeline

## v0.5 — Multi-node
- Register remote Makia nodes
- Node heartbeat / health
- CPU, RAM, disk, bandwidth and account counts per node
- Central account provisioning
- Capacity-aware placement
- Node maintenance mode
- Safe configuration synchronization

## v0.6 — Analytics & Automation
- Historical host metrics
- Daily/monthly traffic analytics
- Heavy-use and anomaly views
- Expiry and quota notifications
- Telegram integration
- Webhooks
- Scheduled backups
- Operational alert rules

## v0.7 — Backup & Update Center
- Versioned application/data backups
- Restore preview
- Release manifest + checksum verification
- Preflight checks
- Atomic update
- Post-update health gate
- One-click rollback
- Changelog UI

## v0.8 — UX & Platform
- Persian / English UI
- RTL / LTR
- Global search and command palette
- Theme system
- PWA install
- Mobile navigation
- Accessibility pass
- Import/export workflows

## v1.0 — Stable
Production readiness requires real Ubuntu 22.04/24.04 host UAT, upgrade/rollback tests, security review, protocol integration tests, browser/mobile UAT, and documented recovery procedures.
