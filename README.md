# ⚡ Makia VPS Manager

Modern web-first VPS and access-infrastructure control center for Ubuntu.

> **Current release candidate:** `v0.8.0-rc2`  
> CI-validated, but **not yet production-certified**. A real-host UAT is required before a `1.0.0 Stable` label.

## What Makia manages today

### SSH Account Center
- Server-side PIN 4 / PIN 6 / Easy-8 / strong-password generation
- 1 / 3 / 7 / 15 / 30 / 60 / 90 day presets and custom date
- Extend from the existing future expiry date
- Unlimited-expiry mode
- **Session Limit** and **Device/IP Limit** as separate policies
- Real background enforcement for expiry, concurrent sessions and distinct SSH source IPs
- Search, filters, bulk lock/unlock/disconnect and bulk renewal
- Live source-IP visibility
- Fail2ban baseline on fresh installs/upgrades

> SSH traffic quota is deliberately **not presented as enforced** until a reliable per-user host accounting layer is available.

### Protocol Hub
Guided, operational adapters:
- Xray: VLESS, VMess, Trojan, Shadowsocks, Hysteria2
- WireGuard
- OpenVPN
- SSH
- Stunnel

Validated Xray transports:
- RAW/TCP
- WebSocket
- gRPC
- HTTPUpgrade
- XHTTP
- mKCP

Xray security:
- None
- TLS using the panel-managed Let's Encrypt certificate
- VLESS REALITY with generated X25519 keys and Short ID

Advanced Xray JSON editor:
- Read the live config
- Validate with the installed Xray binary before apply
- Backup before change
- Restart/health gate
- Automatic rollback on failed apply

This advanced surface can be used for Xray features such as routing, outbounds, fallbacks, HTTP/SOCKS, Tunnel/Dokodemo and TUN while dedicated guided forms are still being built.

### Protocol Clients
- First-class protocol-client records
- Secure subscription IDs and `/sub/<id>` endpoint
- QR/share links
- Expiry
- Traffic quota for Xray clients with per-user stats support
- Persistent cumulative traffic counters across Xray restarts
- Manual traffic reset
- Recurring 7/30/custom-day traffic reset cycles
- Automatic quota suspension
- Automatic reactivation at the next quota-reset boundary
- Live Xray online-IP/device visibility where supported by the installed Xray core
- IP-limit violation visibility
- Manual suspend/reactivate that actually modifies the Xray config

Per-client traffic enforcement currently applies to VLESS, VMess, Trojan and Hysteria2. Shadowsocks quick profiles are clearly marked as not having independent per-client accounting in this RC.

### WireGuard
- Package install
- Server bootstrap
- IP forwarding/NAT
- Peer provisioning
- Downloadable client configuration

### OpenVPN
- Package/Easy-RSA install
- CA and server PKI bootstrap
- Server configuration
- UDP or TCP-server mode
- NAT/IP forwarding
- Client certificate generation
- Downloadable inline `.ovpn` profile

### Infrastructure / Admin
- CPU/RAM/disk/swap/load/network telemetry
- 24-hour metrics history
- Service health/control allowlist
- Audit log
- Backups
- Update Center
- Multi-node heartbeat foundation
- Admin 2FA
- Scoped API tokens
- Persistent login-rate limiting
- Owner-only SQLite permissions
- Domain management + Nginx validation/rollback
- Let's Encrypt via Certbot
- Persian / English shell
- Midnight / AMOLED / Graphite themes
- Comfortable / Compact density
- Installable PWA shell
- `makia-doctor` host diagnostics

## Capability honesty

Makia does not render an unimplemented feature as a working button.

The Protocol Hub labels capabilities as:
- **Guided** — dedicated tested Makia workflow exists.
- **Advanced** — supported through the validated Xray configuration editor.
- **Unavailable** — no tested adapter exists in this release.

TUIC, AmneziaWG and MTProto are currently listed as unavailable rather than being simulated.

## Quick install

Run as root on a **fresh Ubuntu 22.04 or 24.04 VPS**:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mahanneo/Makia-VPS-Manager/main/install.sh)
```

The installer prints a unique administrator bootstrap password. Change it immediately.

## Update

For installations already on v0.8.0-rc2 or newer:

```bash
sudo makia-upgrade
```

`makia-upgrade` first fetches the newest updater from GitHub, then executes it. This prevents an older local updater from missing newly introduced service units.

### One-time upgrade from v0.7.x or older

Use the bootstrap updater once:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mahanneo/Makia-VPS-Manager/main/upgrade.sh)
```

After that, future updates can use `sudo makia-upgrade`.

The updater:
1. creates a backup;
2. downloads the current `main`;
3. updates application and all service units;
4. restarts Makia workers;
5. performs a backend health check;
6. runs `makia-doctor`.

## Diagnostics

```bash
sudo makia-doctor
```

It checks the Makia backend, Nginx, Policy Enforcer, Metrics Sampler, Protocol Traffic Collector, Fail2ban and installed optional protocol tooling.

## Other commands

```bash
sudo makia-backup
sudo makia-uninstall
```

## Runtime layout

```text
/opt/makia-vps-manager
├── app
├── data
├── .venv
└── VERSION

/etc/systemd/system/
├── makia-vps-manager.service
├── makia-policy-enforcer.service
├── makia-metrics-sampler.service
└── makia-protocol-traffic.service

/etc/nginx/sites-available/makia-vps-manager
/var/backups/makia-vps-manager
```

## Security design

The browser is not given a generic root-shell endpoint. Privileged operations are explicit and validated.

Important:
- Admin passwords remain stronger than SSH user PINs.
- Four-digit SSH PINs are optional and intentionally labelled low-security.
- Use HTTPS before exposing the admin panel publicly.
- Keep Fail2ban active.
- Prefer trusted admin IPs/VPN access where possible.
- Test Xray/WireGuard/OpenVPN changes on a disposable VPS before production.

## Release gate

`v0.8.0-rc2` must pass:
- Python compilation
- unit tests
- Bash syntax
- JavaScript syntax
- dangerous-pattern guard
- packaging contract
- real Ubuntu 22.04/24.04 host UAT

See `docs/UAT-0.8.0-RC2.md`.

## License

GPL-3.0-or-later. Third-party source is only incorporated where its license and attribution requirements are compatible.
