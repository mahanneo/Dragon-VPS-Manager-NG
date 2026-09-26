# Makia VPS Manager v0.9.0-rc1 — Host UAT

Do not promote this release candidate to Stable until every critical item below passes on real hosts.

## Test matrix

Run on:
- fresh Ubuntu 22.04 LTS VPS
- fresh Ubuntu 24.04 LTS VPS
- upgrade from v0.8.0-rc2
- at least one host with current Xray installed

## 0. Upgrade

On an existing v0.8.x installation:

```bash
sudo makia-upgrade
sudo makia-doctor
cat /opt/makia-vps-manager/VERSION
```

Expected version: `0.9.0-rc1`.

## 1. Core health

Verify:
- Makia backend active
- Nginx active and valid
- Policy Enforcer active
- Metrics Sampler active
- Protocol Traffic Collector active
- Fail2ban active
- `/healthz` returns `0.9.0-rc1`

## 2. SSH Account Center

Create disposable accounts and verify:
- PIN 4 / PIN 6 / Easy-8 / strong password
- expiry presets 1/3/7/15/30/60/90
- custom date and unlimited expiry
- extend from current future expiry
- Session Limit independently enforced
- Device/IP Limit independently enforced from distinct SSH source IPs
- bulk lock/unlock/disconnect/renew
- edit password and limits
- delete cleans Linux account and Makia profile

Do not treat SSH traffic quota as enforced; Makia intentionally does not claim that capability yet.

## 3. Xray guided profiles

With a current Xray core, test connection import and real traffic for:
- VLESS RAW
- VLESS WebSocket
- VLESS gRPC
- VLESS XHTTP
- VLESS REALITY
- VMess WebSocket
- Trojan TLS
- Hysteria2 TLS
- Shadowsocks
- HTTP Proxy
- SOCKS5

For each:
- port-collision check works
- Xray config test passes before apply
- backup is created
- Xray stays active
- generated link imports/connects where the client supports that URI
- disable/reactivate works when supported

For HTTP/SOCKS/Shadowsocks, confirm Makia does not falsely show reliable per-client quota accounting.

## 4. Xray Tunnel / Dokodemo

Create disposable forwards for:
- TCP
- UDP
- TCP+UDP

Verify:
- requested listen port opens
- traffic reaches target host/port
- invalid target/port is rejected
- duplicate port is rejected
- Xray stays healthy after apply

## 5. Protocol Client policy

For a VLESS/VMess/Trojan/Hysteria2 disposable client:
- quota presets 10/20/50/100/200 GB
- unlimited quota
- expiry presets 1/3/7/15/30/60/90
- IP/device presets 1/2/3/5/10
- reset cycle 0/7/30/60/90
- live traffic increases
- manual reset zeroes the counter
- low quota triggers suspension
- reset boundary re-enables according to policy
- expiry suspends access
- online-IP display/violation appears where the installed Xray exposes that API

## 6. Subscription surfaces

For an active protocol client verify:
- `/sub/<id>?format=base64`
- `/sub/<id>?format=raw`
- `/sub/<id>?format=json`
- `/client/<id>` public status page

Then expire/disable/exhaust the quota and verify the subscription payload returns 403 rather than leaking an active config.

## 7. WireGuard

- install from Protocol Hub
- bootstrap server
- create peer
- download/import config
- connect and reach Internet
- reboot VPS and retest

## 8. OpenVPN

- install OpenVPN/Easy-RSA
- bootstrap UDP server
- create/import client profile
- connect and test DNS/routing
- repeat on disposable host using TCP mode
- reboot and retest

## 9. Advanced Xray

- export JSON
- edit routing/outbound harmlessly
- Validate
- Apply
- intentionally submit invalid JSON/config and verify rejection/rollback
- verify backup under `/var/backups/makia-vps-manager`

## 10. Domain / HTTPS

With disposable DNS:
- save panel domain
- Apply Nginx
- verify Nginx test/rollback
- issue Let's Encrypt certificate
- verify HTTPS login and secure session cookie
- renew/test certificate path

## 11. API

Create tokens with individual combinations:
- `status:read`
- `accounts:read`
- `protocols:read`
- `nodes:read`

Verify access is denied outside the selected scopes.

## 12. Admin / UX regressions

- password change
- login throttling
- TOTP 2FA
- audit log
- backup
- update check
- node heartbeat
- Persian RTL / English LTR
- Midnight / AMOLED / Graphite
- Comfortable / Compact
- PWA shell
- desktop 1920×1080 / laptop 1366×768 / mobile width 390

## 13. Explicit parity boundary

Verify the UI does **not** pretend the following are working:
- TUIC v5
- AmneziaWG
- MTProto
- true client HWID fingerprint enforcement
- Telegram/Discord bot
- PostgreSQL mode

They remain pending until their sidecar/runtime adapters pass install, config, health, recovery and host UAT.

## Stable gate

Promote only with:
- no data loss
- no broken upgrade
- no authentication regression
- no Xray destructive apply
- no protocol worker crash
- no false feature claims
- successful Ubuntu 22.04 and 24.04 host matrix
