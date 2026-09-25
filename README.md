# ⚡ Makia VPS Manager

**Makia VPS Manager** is a modern web control center for administering Linux VPS services, accounts, sessions and operational health from a responsive browser interface.

> **Current development line:** `v0.2.0-alpha`  
> Not production-certified yet. Test on a disposable VPS first.

## Design direction

Makia is being built as a clean-room, modular control panel with a premium dark/glass interface and an explicit separation between the web control plane and privileged host operations.

The project uses 3x-ui / Sanaei as a **feature benchmark**, not as a code or visual clone.

## Available now

- Premium Makia dashboard shell
- CPU / memory / disk / swap / load / uptime telemetry
- Network byte counters
- SSH account creation, lock/unlock and deletion
- Live SSH login sessions
- Allowlisted systemd service control
- Security audit trail
- Admin password management
- Backup / Update / Uninstall CLI helpers
- Ubuntu 22.04 / 24.04 installer
- Nginx reverse proxy
- GitHub Actions CI

## Planned product modules

- Account traffic quota and expiry lifecycle
- Concurrent connection / IP limits
- Live session disconnect controls
- Search, filters and bulk account operations
- Xray integration layer
- VLESS / VMess / Trojan / Shadowsocks / WireGuard family adapters where supported and tested
- Share links, QR codes and subscription endpoints
- TLS certificate automation
- Firewall and Fail2ban center
- Multi-node management
- Backup / Restore UI with rollback
- Update Center with release verification
- Scoped REST API tokens
- Telegram notifications / administration
- TOTP 2FA
- PWA / mobile install
- Dark / light theme and multilingual UI

## Quick install

The public installer tracks the `main` release branch:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mahanneo/Makia-VPS-Manager/main/install.sh)
```

To test the new Makia development branch:

```bash
MAKIA_REF=develop bash <(curl -fsSL https://raw.githubusercontent.com/mahanneo/Makia-VPS-Manager/develop/install.sh)
```


## Architecture

```text
Admin Browser
      │
      ▼
  HTTPS/Nginx
      │
      ▼
 Makia Web/API
      │
      ├── Audit / Auth / Settings
      ├── Accounts / Sessions
      ├── Service adapters
      └── Future Xray / Node adapters
              │
              ▼
       Linux host services
```

Makia does **not** expose a generic root shell through the web UI. Privileged functionality is implemented as explicit, validated operations.

## Development

- `main`: release line
- `develop`: integration branch
- `feature/*`: isolated work

## License

GPL-3.0-or-later. Third-party functionality must be reimplemented or incorporated only where its license and attribution requirements are compatible.
