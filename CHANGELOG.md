# Changelog

## [0.7.0-rc1] - 2026-09-26

### Protocol Hub
- Added real protocol catalog/status for Xray, WireGuard, OpenVPN, SSH and Stunnel.
- Added apt-backed installation for WireGuard, OpenVPN and Stunnel.
- Added WireGuard server bootstrap and peer provisioning with downloadable client configuration.
- Added OpenVPN PKI/server bootstrap and client `.ovpn` provisioning.
- Added Xray quick inbound provisioning for VLESS, VMess, Trojan and Shadowsocks with config validation, backup, restart health check, rollback, share links and QR.
- Xray is detected and managed when installed; Makia does not run an unverified remote installer for the Xray binary.

### Domain, TLS and language
- Added persistent Persian/English panel language preference with RTL/LTR shell behavior.
- Added validated panel-domain configuration.
- Added Nginx `server_name` apply with syntax validation and rollback.
- Added optional Let's Encrypt certificate issuance through Certbot after DNS is configured.

### UX
- Rebuilt Protocol Hub as a card-based operational surface.
- Added capability strip, status badges, configuration modals and one-click copy/download actions.
- Upgraded shell, top bar, responsive layout and domain/environment indicator.
- Removed fake protocol actions: unavailable operations are explicitly marked unavailable instead of rendering non-functional buttons.

### Quality
- Added domain and protocol validation unit tests.
- CI continues to enforce Python compile, unit tests, Bash syntax, JavaScript syntax and dangerous-pattern checks.

### Release status
This is a release candidate. Stable status requires host UAT on clean Ubuntu 22.04/24.04, protocol provisioning tests, update/rollback tests and TLS/domain tests.

## [0.6.0-alpha] - 2026-09-26

### Account Center V2
- Added server-side cryptographic generation for 4-digit PIN, 6-digit PIN, Easy-8 and strong user passwords.
- Added automatic username suggestion.
- Added 1/7/30/60/90-day expiry presets.
- Added account search and status filters.
- Added bulk expiry extension in addition to lock/unlock/disconnect.
- Added GB-oriented quota entry while preserving MB canonical storage.
- Added improved one-time credential card for copying account details to the user.

### UX
- Added global Makia command palette with Ctrl/Cmd + K.
- Added new provisioning, security and update surfaces.
- Added richer mobile behavior and visual hierarchy.

### Security
- Fresh installations now install and enable Fail2ban with an SSH brute-force baseline.
- Existing installations receive the same Fail2ban baseline through `makia-update`.
- 4-character user PINs remain optional; administrator password policy is unchanged.

### Update Center
- Added online VERSION comparison against the main GitHub repository.
- Web-triggered self-update remains intentionally disabled until atomic rollback/release verification is complete.


## [0.4.0-alpha] - 2026-09-26

### Protocol Center
- Added real Xray binary/version/service/config discovery.
- Added safe inbound summary with protocol, listen address, port and client count.
- Added Xray to the service allowlist.
- No fabricated protocol data or fake traffic metrics.

### Account policy enforcement
- Added `makia-policy-enforcer` systemd service.
- Connection limits are now actively enforced for SSH login sessions.
- Excess sessions are disconnected and recorded in the audit trail.

### Security
- State-changing API requests require the Makia management header.
- Session cookies become Secure automatically when served through HTTPS.
- User PINs may still be as short as four characters by operator choice; admin credentials remain stronger.

### UI
- Added Protocol Center navigation.
- Update Center now references `makia-update`.

## [0.3.0-alpha] - 2026-09-26

### Product
- Product/runtime identity migrated to **Makia VPS Manager**.
- New premium dark control center and responsive navigation.
- New `/opt/makia-vps-manager` runtime and `makia-vps-manager` systemd service.
- Legacy Dragon command aliases retained temporarily for migration compatibility.

### Accounts
- Professional account creation and editing.
- 4-digit PIN, 6-digit PIN and strong-password workflow.
- Expiry date, plan, internal note, connection-limit policy and traffic-quota policy.
- Lock/unlock/delete and disconnect-all actions.
- Dashboard counters for expiring accounts and connection-limit violations.

### Sessions
- Live SSH session list.
- Controlled per-terminal disconnect.

### Operations
- Security Center status for UFW, Fail2ban and OpenSSH.
- Controlled in-panel data backup creation and backup list.
- Updater performs backup then health check.
- Existing alpha data can be migrated from the previous runtime location.

### Security notes
- User PINs may be 4 characters by operator choice.
- Administrator passwords remain stronger.
- Traffic quota is currently a stored policy; usage accounting/enforcement is not fabricated.

## [0.1.0-alpha] - 2026-09-25
- Initial web management foundation.
