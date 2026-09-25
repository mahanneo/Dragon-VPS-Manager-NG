# Changelog

## [0.8.0-rc1] - 2026-09-26

### Account Center V3
- Separated SSH Session Limit from Device/IP Limit.
- Added real enforcement for account expiry, concurrent sessions and distinct source IPs.
- Added 1/3/7/15/30/60/90-day presets, unlimited expiry and extend-from-existing-expiry behavior.
- Removed misleading enforced-traffic claims from SSH accounts where reliable per-user accounting is not available.

### Xray / Protocol Clients
- Added first-class protocol client records with secure subscription IDs.
- Added cumulative persistent traffic accounting for VLESS, VMess, Trojan and Hysteria2 using Xray Stats API.
- Added real manual and recurring traffic resets.
- Added automatic quota suspension and automatic reactivation at the next reset boundary.
- Added expiry enforcement and manual suspend/reactivate against the live Xray config.
- Added online Xray IP/device visibility and IP-limit violation state when supported by the installed Xray core.
- Added generated subscription endpoint in Base64 or raw format.
- Added Hysteria2 guided provisioning.
- Added RAW/TCP, WebSocket, gRPC, HTTPUpgrade, XHTTP and mKCP transport options.
- Added TLS certificate-backed profiles.
- Added VLESS REALITY with generated X25519 key material and Short ID.
- Added validated Advanced Xray JSON editor for routing, outbounds, fallbacks and other advanced features.
- Xray config mutations use test-before-apply, backup, restart validation and rollback.

### WireGuard / OpenVPN
- Kept guided WireGuard bootstrap and peer configuration workflow.
- Modernized OpenVPN TCP server/client mode and data cipher configuration.

### Admin / Security
- Added persistent admin login throttling.
- Hardened SQLite database file permission to 0600.
- Added disable-reason tracking for reliable protocol renewal.
- Added host diagnostic command: `makia-doctor`.

### UI / PWA
- Added Midnight, AMOLED and Graphite themes.
- Added Comfortable and Compact density.
- Added installable PWA manifest/service worker shell.
- Added live Protocol Client usage, quota, expiry, subscription and IP surfaces.
- Capability Matrix now distinguishes Guided, Advanced and Unavailable functionality.

### Packaging
- Added `makia-protocol-traffic.service`.
- Fixed updater to deploy the protocol traffic collector service unit.
- Installer/updater deploy `makia-doctor`.
- Uninstaller removes the new worker and diagnostic command.

### Explicitly not claimed as guided in this RC
- TUIC
- AmneziaWG
- MTProto
- automatic Xray over-limit IP banning

These remain unavailable or visibility-only until dedicated adapters and host UAT exist.

### Release status
Release candidate only. Promotion to Stable requires the host matrix in `docs/UAT-0.8.0-RC1.md`.


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
