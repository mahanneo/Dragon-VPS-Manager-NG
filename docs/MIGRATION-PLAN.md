# Legacy DRAGON → Dragon NG migration plan

## Phase 0 — Foundation (this release)
Web UI, authentication, telemetry, service allowlist, SSH accounts, audit trail, packaging.

## Phase 1 — Legacy capability inventory
Map every script from Install/, Modulos/ and Sistema/ into one of: retain, rewrite, retire. Identify required packages, ports, state files and systemd services.

## Phase 2 — Network services
Add explicit adapters for services actually required by the deployment (for example OpenSSH, Stunnel and other verified legacy services). Each adapter gets input validation, status probe, idempotent configuration, restart policy and rollback.

## Phase 3 — Account policy
Expiry, concurrent-session policy, quotas where technically reliable, online session visibility, forced disconnect and bulk operations. Avoid fragile process-name parsing when native system APIs are available.

## Phase 4 — Web hardening
HTTPS automation, CSRF defense, rate limiting, optional TOTP 2FA, admin roles, IP allowlist and backup encryption.

## Phase 5 — Updater
Signed/versioned releases, preflight, backup, atomic apply, health check and rollback. Never pipe remote scripts directly to a privileged shell.

## Phase 6 — Telegram integration
Optional read/operate bot consuming the same authenticated service layer; no separate business logic.
