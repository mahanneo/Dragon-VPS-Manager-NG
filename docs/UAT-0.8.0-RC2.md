# Makia VPS Manager v0.8.0-rc2 — Host UAT

Do not promote this release candidate to Stable until the required checks pass on real Ubuntu hosts.

## Test matrix

Run on:
- Ubuntu 22.04 LTS fresh VPS
- Ubuntu 24.04 LTS fresh VPS
- Upgrade from the current v0.7.0-rc1 installation

## 0. Upgrade bootstrap from v0.7.x

On an existing v0.7.x server run:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mahanneo/Makia-VPS-Manager/main/upgrade.sh)
```

Then verify:

```bash
command -v makia-upgrade
command -v makia-doctor
systemctl status makia-protocol-traffic --no-pager
cat /opt/makia-vps-manager/VERSION
```

Expected version: `0.8.0-rc2`.

## 1. Core installation

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mahanneo/Makia-VPS-Manager/main/install.sh)
makia-doctor
```

Expected:
- Makia backend active
- Nginx active and valid
- Policy Enforcer active
- Metrics Sampler active
- Protocol Traffic Collector active
- Fail2ban active
- /healthz returns the installed version

## 2. SSH account lifecycle

Create a disposable account and verify:
- PIN 4 and PIN 6 creation
- custom password
- 1/3/7/15/30/60/90 day expiry presets
- custom expiry
- unlimited expiry
- password change
- lock/unlock
- delete
- bulk +7/+30/+90 renewal

### Session limit
Set Session Limit = 1. Open two sessions. The policy worker must close the excess session.

### Device/IP limit
Set Device/IP Limit = 1. Connect the same account from two distinct public source IPs. The policy worker must remove sessions from the extra source IP.

## 3. WireGuard

From Protocol Hub:
- Install WireGuard
- Bootstrap wg0
- Create peer
- import downloaded config on a client
- verify Internet reachability
- reboot VPS
- verify wg0 starts again

## 4. OpenVPN

From Protocol Hub:
- Install OpenVPN
- Bootstrap UDP server
- create client
- import .ovpn and connect
- verify routing and DNS
- reboot and retest

Repeat on a disposable host with TCP mode.

## 5. Xray

Use an already installed, current Xray core.

### Guided profiles
Test:
- VLESS RAW
- VLESS WebSocket
- VLESS gRPC
- VLESS XHTTP
- VLESS REALITY
- VMess WebSocket
- Trojan TLS
- Hysteria2 TLS
- Shadowsocks quick profile

For every generated profile:
- Xray config test succeeds
- Xray stays active after apply
- share link imports into a compatible client
- connection succeeds

### Accounting
For VLESS/VMess/Trojan/Hysteria2:
- generate traffic
- confirm cumulative usage rises
- restart Xray and confirm historical usage remains
- reset traffic manually
- configure a low disposable quota and confirm auto-suspension
- set a short reset cycle in a test DB/time-adjusted scenario and confirm automatic re-enable

### Online IP
On an Xray core exposing the online-IP API:
- connect from two different public source IPs
- verify both IPs appear
- verify IP-limit violation appears when over policy

## 6. Advanced Xray editor

- export live JSON
- make a harmless valid change and Validate
- Apply it
- submit an intentionally invalid config and verify it is rejected before destructive apply
- verify a backup exists under /var/backups/makia-vps-manager

## 7. Domain / HTTPS

Point a disposable domain A record to the VPS:
- save domain
- Apply to Nginx
- verify DNS display
- issue Let's Encrypt certificate
- verify HTTPS login
- verify Secure session cookie behavior

## 8. Admin security

- six failed admin passwords trigger login throttling
- wait/block expiry behavior works
- successful login clears failures
- enable TOTP 2FA
- logout/login with TOTP
- create/revoke API token

## 9. Upgrade

From v0.7.0-rc1:
```bash
makia-update
makia-doctor
```

Verify:
- data preserved
- admin login preserved
- SSH users preserved
- existing backup created
- new protocol traffic service installed and active
- dashboard version is 0.8.0-rc2

## 10. Responsive/browser

Test current Chrome/Edge/Firefox:
- desktop 1920×1080
- laptop 1366×768
- mobile width 390
- Persian RTL
- English LTR
- Midnight / AMOLED / Graphite
- Compact / Comfortable

## Stable gate

Only promote after all critical items pass with no data loss, service outage, broken update, invalid Xray apply, or authentication regression.
