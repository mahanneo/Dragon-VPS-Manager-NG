# Makia VPS Manager v0.10.0-rc1 — Access Center Host UAT

This release must not be promoted to Stable until the real-host checks below pass.

## Test hosts
- Ubuntu 22.04 LTS clean VPS
- Ubuntu 24.04 LTS clean VPS
- Upgrade from v0.9.3-rc1
- One host with no Xray installed
- One host with current Xray installed

## 1. Upgrade and health
```bash
sudo makia-upgrade
sudo makia-doctor
cat /opt/makia-vps-manager/VERSION
curl -fsS http://127.0.0.1:8787/healthz
```

Expected version: `0.10.0-rc1`.

## 2. Access Center navigation
- Sidebar shows Access Center.
- Access Center loads SSH/Xray/WireGuard/OpenVPN entries.
- Search and filters work.
- Protocol Hub remains available for engine-level setup.
- No duplicate or fake access entries are shown.

## 3. SSH access delivery
- Create PIN 4, PIN 6 and strong-password accounts.
- Verify login, expiry, session and device policy.
- Native export downloads an OpenSSH config fragment.
- OpenSSH config must not contain the password.
- Protected ZIP opens only with the selected ZIP password.
- ZIP contains SSH config + credentials file.
- Changing the SSH password refreshes the encrypted delivery artifact.
- Deleting from Access Center deletes Linux user/profile/artifact.

Legacy SSH:
- Old account without artifact is marked Legacy.
- Reset password once; export becomes available.

## 4. Xray install and guided clients
On a host without Xray:
- Access Center → Xray → Install Xray Core.
- Xray service becomes active.
- Protocol Hub changes from Not installed to Running.
- Existing Makia health stays green.

Create and connect:
- VLESS RAW
- VLESS REALITY
- VMess WebSocket
- Trojan TLS
- Shadowsocks
- Hysteria2
- HTTP Proxy
- SOCKS5

For each created Xray client:
- Access Center entry appears.
- Profile file downloads.
- Protected ZIP opens with the chosen password.
- ZIP contains profile/share information and QR SVG.
- Subscription URL works where applicable.
- Revoke removes/disables live Xray access and removes the Makia record.

## 5. WireGuard
- Install WireGuard if needed.
- Bootstrap wg0.
- Create peer from Access Center.
- Native `.conf` imports into official WireGuard client.
- QR from protected bundle represents the same config.
- Connection reaches Internet.
- Protected ZIP requires correct password.
- Revoke removes peer from live `wg` state and persisted wg0.conf.

Legacy peer:
- Existing peer without retained private key is shown as Legacy / Reissue export.
- Makia must not fabricate a private key or claim the old config is recoverable.

## 6. OpenVPN
- Install OpenVPN/Easy-RSA if needed.
- Bootstrap server.
- Create client from Access Center.
- Native `.ovpn` imports and connects.
- Protected ZIP contains `.ovpn`.
- Revoke adds client certificate to CRL.

Legacy OpenVPN:
- Existing issued client appears.
- Native export is regenerated from existing PKI.
- Generated profile connects before revoke.

## 7. Protected delivery security
For SSH/WireGuard/OpenVPN/Xray:
- Create protected package with six-digit PIN.
- Confirm ZIP cannot be opened without the PIN.
- Confirm wrong PIN fails.
- Confirm expected files decrypt with correct PIN.
- Confirm raw credentials/config text is not visible by searching the ZIP binary.
- Confirm `data/makia.db` contains encrypted artifact payload rather than raw config/password text.
- Confirm `data/.secret` remains mode 0600 and data backup contains it.

## 8. Recovery and backups
- Run `sudo makia-backup` while metrics/policy workers are writing.
- Backup completes without `file changed as we read it`.
- Run upgrade on current version; health stays green.
- Deliberately fail a disposable update and confirm runtime rollback works.

## 9. Browser / UX
- Chrome desktop 1920×1080
- Chrome laptop 1366×768
- Android Chrome ~390px
- Persian RTL / English LTR
- Midnight / AMOLED / Graphite
- Comfortable / Compact

Verify Access Center cards, table overflow, modals, native downloads and ZIP downloads.

## Stable gate
- app import CI PASS
- unit tests PASS
- JavaScript syntax PASS
- Bash syntax PASS
- upgrade/rollback PASS
- all four access families PASS on real hosts
- no credential plaintext regression
- no false feature claims
