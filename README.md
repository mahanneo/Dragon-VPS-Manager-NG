# ⚡ Makia VPS Manager

Modern, web-first VPS control center for Linux servers.

> **Current release:** `v0.7.0-rc1`  
> This is an active alpha. Use a disposable VPS for first installation and validate host behavior before production use.

## Highlights

- Premium responsive dark control center
- Global command palette (Ctrl/Cmd + K)
- Live CPU / RAM / disk / swap / load / network telemetry
- Professional SSH Account Center
- Server-side 4-digit PIN, 6-digit PIN, Easy-8 and strong password generation
- Professional Account Center with search/filter, expiry presets, plan, notes, bulk extend, enforced connection limit and quota policy
- Live session visibility, controlled disconnect and bulk disconnect
- Background Policy Enforcer for concurrent SSH connection limits
- Xray Protocol Center with real binary/service/config/inbound discovery
- Service start / stop / restart through an allowlist
- Security Center status for UFW, Fail2ban and OpenSSH
- Fail2ban baseline automatically enabled on fresh installs and upgrades
- Audit trail
- In-panel backup creation and backup listing
- CLI updater with pre-update backup and post-update health check
- GitHub version awareness in Update Center
- Ubuntu 22.04 / 24.04 installer
- Migration path from the earlier Dragon alpha runtime

## Quick install

Run as root on a fresh Ubuntu 22.04 or 24.04 VPS:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mahanneo/Makia-VPS-Manager/main/install.sh)
```

The installer prints a unique administrator bootstrap password. Change it immediately after login.

## Commands

```bash
sudo makia-update
sudo makia-backup
sudo makia-uninstall
```

Legacy command aliases such as `dragon-update` remain temporarily available for migration compatibility.

## Account passwords

Makia allows user passwords/PINs with a minimum of **4 characters** for operator convenience. This does **not** mean 4-digit SSH PINs are recommended on an unrestricted public SSH service.

If simple PINs are used:
- enable Fail2ban;
- use firewall/IP restrictions where possible;
- avoid exposing administration endpoints unnecessarily;
- prefer 6-digit PINs or strong generated passwords for higher-risk accounts.

Administrator passwords still require stronger minimums.

## Quota policy

The current Account Center stores a traffic quota policy for each account, but it does **not invent traffic consumption data**. Reliable per-account accounting/enforcement will be connected to the protocol/Xray accounting layer in the next protocol milestone.

## Runtime layout

```text
/opt/makia-vps-manager
├── app
├── data
├── .venv
└── VERSION

/etc/systemd/system/makia-vps-manager.service
/etc/nginx/sites-available/makia-vps-manager
/var/backups/makia-vps-manager
```

## Architecture

```text
Admin Browser
      │
      ▼
    Nginx
      │
      ▼
Makia Web/API :8787 (localhost only)
      │
      ├── Authentication
      ├── Account metadata
      ├── Live sessions
      ├── Audit
      ├── Backup
      └── Validated privileged adapters
              │
              ▼
          Linux host
```

Makia intentionally does not expose a generic root shell endpoint.

## Roadmap

Next major work:
- Full validated Xray inbound management
- VLESS / VMess / Trojan / Shadowsocks adapters where validated
- QR and share links
- Subscription endpoints
- reliable traffic accounting and quota enforcement
- TLS automation
- TOTP 2FA
- scoped API tokens
- multi-node control
- notification/webhook/Telegram integration
- signed release verification and one-click rollback
- PWA and bilingual UI

See `docs/ROADMAP.md` on the development line for the full roadmap.

## License

GPL-3.0-or-later. Third-party code must only be incorporated when license and attribution requirements are compatible.

## Protocol Hub (RC1)

Makia now has operational adapters for:

- **Xray family:** VLESS, VMess, Trojan and Shadowsocks quick inbounds when Xray is already installed. Config changes are tested before apply and rolled back if restart/health fails.
- **WireGuard:** package installation, server bootstrap, peer provisioning and downloadable client config.
- **OpenVPN:** package/PKI bootstrap, server configuration and downloadable client profiles.
- **SSH:** account lifecycle, expiry, PIN/password generation, live sessions and disconnect controls.
- **Stunnel:** installation/status and service integration.

The panel intentionally does not label unimplemented actions as working. Unsupported operations are surfaced as unavailable until a tested adapter exists.

## Domain / TLS

Settings → Domain & TLS can persist the panel domain, apply it to Nginx after config validation, and request Let's Encrypt via Certbot. DNS must already point to the VPS before certificate issuance.

## UI direction

The interface uses a modern card-driven control-center layout inspired by current infrastructure panels and high-conversion marketplace UX patterns, while keeping Makia's code and visual identity independent.
