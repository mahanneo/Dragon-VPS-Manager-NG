# Makia VPS Manager v0.13.1-rc1 — Xray Runtime / Client Guide UAT

این نسخه **Release Candidate** است و تا UAT واقعی روی VPS Stable محسوب نمی‌شود.

## 1. Upgrade از v0.13.0-rc1
- `sudo makia-upgrade`
- `cat /opt/makia-vps-manager/VERSION` → `0.13.1-rc1`
- Nginx/Certbot config فعال حفظ شود.
- `sudo makia-doctor` اجرا شود.
- `sudo makia-uat-smoke` اجرا شود.

## 2. بازتولید Failure قدیمی Xray
روی یک VPS آزمایشی که Xray با User غیر-root اجرا می‌شود:
- `systemctl show xray -p User --value` مقدار واقعی User را نشان دهد.
- Config قدیمی root-owned/0600 در صورت وجود توسط Diagnose شناسایی شود.
- در Services، Xray در صورت Failure فقط «Stopped» نمایش داده نشود؛ Diagnose و Repair در دسترس باشند.
- Diagnose باید Root validation و Service-user validation را جدا نمایش دهد.
- آخرین `journalctl -u xray` در UI قابل مشاهده باشد.

## 3. Repair & Restart
- قبل از Repair یک Backup در `/var/backups/makia-vps-manager` ایجاد شود.
- Repair نباید UUID/Password/REALITY keyهای موجود را تغییر دهد.
- Config فعال با Permission امن برای User واقعی Xray قابل خواندن شود.
- Validation با root PASS شود.
- Validation با User واقعی systemd PASS شود.
- Xray پس از Repair روی `active` قرار گیرد.
- اگر Repair شکست خورد، Config قبلی Restore شود.

## 4. Xray Core version
- نصب جدید Xray از داخل Makia باید Core `v26.3.27` را نصب کند.
- `xray version` بررسی شود.
- Diagnose در صورت Core متفاوت Warning نشان دهد.
- CI real-core matrix باید روی همین نسخه اجرا شود.

## 5. TLS / Let's Encrypt
برای یک Domain واقعی:
- از Settings گواهی Let's Encrypt بگیر.
- یک VLESS/Trojan TLS یا Hysteria2 TLS ایجاد کن.
- فایل‌های Runtime زیر `/usr/local/etc/xray/tls/<domain>/` وجود داشته باشند.
- Certificate و Private Key فقط برای User سرویس Xray و root قابل استفاده باشند.
- Xray با User غیر-root بتواند Config را Validate و سرویس را Start کند.
- Certbot deploy hook در `/etc/letsencrypt/renewal-hooks/deploy/makia-xray-sync` نصب باشد.
- `certbot renew --dry-run` یا renewal staging روی VPS آزمایشی اجرا شود.
- بعد از renewal، Xray config validation و restart PASS باشد.

## 6. Xray guided protocol matrix
CI و سپس VPS واقعی باید Configهای زیر را Validate کنند:
- VLESS + XHTTP + REALITY
- VMess + WebSocket
- Trojan + TLS
- Shadowsocks
- Hysteria2 + TLS
- HTTP Proxy
- SOCKS5
- Advanced JSON custom config

برای هر Profile قابل‌تحویل:
- QR / Share Link یا Native config معتبر باشد.
- Protected ZIP باز شود.
- `connection-guide-fa.txt` داخل Package وجود داشته باشد.

## 7. راهنمای اتصال عمومی
بدون Login:
- `/help/connect` با HTTP 200 باز شود.
- Anchorهای زیر وجود داشته باشند:
  - `#xray`
  - `#wireguard`
  - `#openvpn`
  - `#ssh`
- صفحه Responsive و RTL باشد.
- هیچ Credential کاربری در صفحه عمومی وجود نداشته باشد.

## 8. Client Guides داخل پنل
- Sidebar → «راهنمای اتصال» باز شود.
- کارت Xray، WireGuard، OpenVPN و SSH/NPV وجود داشته باشد.
- Open guide مسیر عمومی صحیح را باز کند.
- Copy guide link URL صحیح همان Protocol را کپی کند.
- Access Center برای هر Profile دکمه Guide داشته باشد.
- Xray Share Center لینک «راهنمای کاربر» داشته باشد.
- Public Xray Client Page لینک «راهنمای نصب و اتصال» داشته باشد.

## 9. Services / Diagnostics UX
- Xray Running: Diagnose در دسترس باشد.
- Xray Failed: Diagnose + Repair در دسترس باشند.
- Restart ساده جایگزین Diagnose/Repair نشود.
- علت‌هایی مانند Permission denied، Config invalid، Certificate access و Address already in use در Diagnostics قابل مشاهده باشند.

## 10. Full browser/runtime regression
- تمام Sidebar views بدون JavaScript Page Error:
  - Overview
  - Access Center
  - Live Sessions
  - Protocols
  - Client Guides
  - Services
  - Nodes
  - Security
  - Backups
  - Audit Logs
  - Update Center
  - Settings
- تمام Settings tabs باز شوند.
- Self-Test PASS یا فقط Warningهای محیط CI داشته باشد؛ Xray نصب‌شده و خراب باید Critical Failure باشد.
- Protected ZIP / Native export / QR / Subscription / Portable Migration همچنان PASS باشند.

## 11. Stable gate
Stable فقط بعد از:
- CI کامل PASS
- Browser Smoke PASS
- Xray 26.3.27 real-core matrix PASS
- Upgrade روی VPS دارای Xray failed واقعی
- Diagnose → Repair → Active PASS
- TLS renewal rehearsal PASS
- اتصال واقعی حداقل VLESS/REALITY و یک TLS profile از Client خارجی PASS
- Gateهای مهاجرت و WireGuard نسخه v0.13.0 نیز همچنان PASS
