# Changelog

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
