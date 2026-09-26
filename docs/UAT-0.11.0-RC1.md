# Makia VPS Manager v0.11.0-rc1 — Production UAT

این سند Gate ارتقای نسخه RC به Stable است. هیچ موردی با حدس یا صرفاً ظاهر UI پاس محسوب نمی‌شود.

## A. نصب، ارتقا و Recovery
1. ارتقا از v0.10.0-rc1 با `sudo makia-upgrade`.
2. `cat /opt/makia-vps-manager/VERSION` باید `0.11.0-rc1` باشد.
3. `sudo makia-doctor` بدون خطای Backend/Nginx/Worker اجرا شود.
4. `sudo bash /opt/makia-vps-manager/../makia-vps-manager/scripts/uat-smoke.sh` در سورس checkout یا اسکریپت متناظر از مخزن اجرا شود.
5. `curl -fsS http://127.0.0.1:8787/healthz` پاسخ سالم بدهد.
6. Backup حین فعالیت Workerها بدون `file changed as we read it` ساخته شود.
7. روی VPS آزمایشی یک Update عمداً خراب شود و Auto Rollback نسخه قبلی را سالم برگرداند.

## B. Shell و Navigation
- تمام گزینه‌های Sidebar باز شوند: Overview, Access Center, Live Sessions, Protocols, Services, Nodes, Security, Backups, Audit, Update Center, Settings.
- Active state فقط روی صفحه جاری باشد.
- Search Makia با Ctrl/Cmd+K باز شود و Navigation از نتایج کار کند.
- Refresh صفحه جاری را بدون logout اجرا کند.
- CTA «ساخت دسترسی جدید» از Sidebar Wizard را باز کند.
- فارسی RTL و English LTR هر دو تست شوند.

## C. Dashboard
- CPU/RAM/Disk/Uptime/Network با مقادیر واقعی Host تطبیق داده شوند.
- تعداد Managed Access با Access Center برابر باشد.
- Service count با systemd تطبیق داده شود.
- نمودار 24h فقط داده واقعی Metrics Sampler را نشان دهد.
- Live Sessions با `who`/`ss` و وضعیت واقعی SSH مقایسه شود.
- Run Self-Test باید DB، Secret permissions، encrypted artifacts، AES ZIP و Protocol Catalog را گزارش کند.

## D. Protected ZIP — Gate بحرانی
برای SSH، Xray، WireGuard و OpenVPN:
1. روی Protected ZIP کلیک شود؛ Modal رمز باید باز شود.
2. PIN پیشنهادی تغییر داده شود.
3. Download ZIP باید Download واقعی Browser ایجاد کند.
4. ZIP بدون Password باز نشود.
5. Password اشتباه Fail شود.
6. Password صحیح فایل‌ها را باز کند.
7. Native config داخل ZIP با Native export همان Client تطابق داشته باشد.
8. محتوای Credential در Binary ZIP به صورت plaintext قابل جستجو نباشد.
9. Audit Log باید `access_protected_export` ثبت کند.

## E. Native Export
- SSH: فایل OpenSSH config دانلود شود و Password داخل config نباشد.
- WireGuard: `.conf` در WireGuard رسمی Android/Windows Import و Connect شود.
- OpenVPN: `.ovpn` در OpenVPN Connect Import و Connect شود.
- Xray: Share/Profile file با Client سازگار Import شود؛ QR نیز اسکن شود.
- خطای Backend باید در UI نمایش داده شود، نه اینکه دکمه بی‌اثر بماند.

## F. Provisioning Wizard
- Step 1 Protocol: فقط Engineهای آماده Create نشان دهند و Engine آماده‌نشده Setup بخواهد.
- SSH: Username, PIN4/PIN6/Easy8/Strong, Expiry, Session Limit, Device/IP Limit.
- Xray: VLESS/VMess/Trojan/Shadowsocks/Hysteria2/HTTP/SOCKS، Port، Transport، Security، Quota، Expiry، IP limit، Reset.
- WireGuard: Peer name, Endpoint, DNS.
- OpenVPN: Client name, Endpoint, Port, UDP/TCP.
- Back/Next اطلاعات را از دست ندهد.
- Review دقیقاً داده نهایی را نشان دهد.
- Create هنگام عملیات Disable شود و Duplicate submit رخ ندهد.
- Success screen Native و Protected delivery را ارائه دهد.

## G. SSH Runtime
- Login واقعی با PIN4 و PIN6.
- Lock/Unlock.
- Expiry و قطع Session.
- Concurrent Session Limit.
- Distinct Device/IP Limit.
- Password reset و Export مجدد Artifact.
- Revoke از Access Center واقعاً Linux user را حذف کند.

## H. WireGuard Runtime
- Install و Bootstrap روی Ubuntu 22.04 و 24.04.
- NAT/IP forwarding.
- Peer جدید اتصال Internet داشته باشد.
- Revoke از Runtime و wg0.conf حذف کند.
- Legacy peer بدون Private Key باید فقط Reissue ارائه دهد.
- Reissue Peer قبلی را باطل و config جدید قابل اتصال بسازد.

## I. OpenVPN Runtime
- Install Easy-RSA/OpenVPN.
- Bootstrap UDP و یک بار TCP روی Host آزمایشی.
- Client certificate/profile ساخته و وصل شود.
- Revoke → CRL update و اتصال قبلی رد شود.
- Legacy client از PKI دوباره Export شود.

## J. Xray Runtime
- Install Xray Core از مسیر رسمی.
- VLESS TCP.
- VLESS REALITY.
- VMess WebSocket.
- Trojan TLS.
- Shadowsocks.
- Hysteria2.
- HTTP Proxy.
- SOCKS5.
- Config قبل از Apply با Xray test شود.
- در Failure config قبلی Rollback شود.
- Subscription/QR/Profile صحیح باشد.
- Quota/Expiry/Traffic reset روی پروتکل‌هایی که Accounting دارند تست شود.
- Revoke inbound اختصاصی را حذف و Port را آزاد کند.

## K. Services و Protocol Hub
- Start/Stop/Restart فقط Allowlist.
- Nginx، OpenSSH، Fail2ban، Workers و Xray status واقعی باشند.
- Capabilityهای Unavailable دکمه جعلی نداشته باشند.
- Advanced Xray JSON: Validate، Apply، Backup و Rollback.

## L. Security
- Admin password minimum policy.
- Login throttling.
- 2FA setup/enable/login/disable.
- Session cookie روی HTTPS Secure باشد.
- `data/.secret` mode = 0600.
- DB artifact payloadها plaintext credential نباشند.
- API Token فقط یک بار نمایش داده شود و DB فقط Hash نگه دارد.

## M. Domain/TLS
- Domain validation.
- Nginx apply + syntax gate.
- DNS mismatch به کاربر گفته شود.
- Let's Encrypt issuance روی دامنه واقعی.
- HTTP→HTTPS رفتار و Secure cookie.

## N. Backups
- Create backup.
- SQLite integrity backup.
- Restore در VPS آزمایشی.
- Artifact Secret همراه Backup حفظ شود تا Exportهای رمز‌شده بعد از Restore قابل باز شدن باشند.

## O. Nodes
- Node token creation.
- Copy install command.
- Agent heartbeat.
- CPU/RAM/Disk values.
- Revoke token و توقف پذیرش heartbeat.

## P. Audit و API
- Create/Edit/Revoke/Export/Service action/Settings change همگی Audit داشته باشند.
- Scoped tokens فقط Scope مجاز را بخوانند.
- Revoked token 403 بدهد.

## Q. Responsive / Browser
- Chrome desktop 1920×1080.
- 1366×768.
- Android Chrome حدود 390px.
- Edge desktop.
- Sidebar compact mobile.
- Wizard scroll/keyboard.
- Download روی Chrome/Edge و Android.
- Midnight/AMOLED/Graphite + Compact/Comfortable.

## R. Negative Cases
- Duplicate username/client.
- Invalid port.
- Port in use.
- Invalid domain.
- Xray unavailable.
- WireGuard/OpenVPN not bootstrapped.
- Expired profile.
- Wrong ZIP password.
- Missing artifact.
- Legacy SSH without retained password.
- Browser refresh وسط Modal.
- Backend restart وسط Export؛ UI باید Error نشان دهد.

## Stable Gate
Stable فقط وقتی مجاز است که:
- Main CI و Browser Smoke PASS باشند.
- `scripts/uat-smoke.sh` روی Host واقعی PASS باشد.
- چهار خانواده SSH/Xray/WireGuard/OpenVPN روی Client واقعی PASS باشند.
- Protected ZIP و Native Export روی Browser واقعی PASS باشند.
- Update + Rollback PASS باشد.
- هیچ Action قابل کلیک بدون Backend واقعی باقی نماند.
- هیچ Critical security/credential leakage پیدا نشود.
