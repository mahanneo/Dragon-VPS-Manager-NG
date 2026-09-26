# Makia VPS Manager v0.14.0-rc1 — Glass Aurora / OpenVPN Domain UAT

این نسخه **Release Candidate** است. Stable فقط بعد از تست واقعی روی VPS و Client بیرونی.

## 1. Upgrade و Version
- `sudo makia-upgrade`
- `cat /opt/makia-vps-manager/VERSION` → `0.14.0-rc1`
- `sudo makia-doctor` → PASS
- `sudo makia-uat-smoke` → PASS
- Update نباید Domain/Nginx/Certbot، Xray runtime یا Credentialهای قبلی را تغییر غیرمجاز دهد.

## 2. Glass Aurora migration
بعد از Upgrade:
- Theme پیش‌فرض نصب قبلی یک‌بار به `glass` منتقل شود.
- `body[data-theme="glass"]` در Dashboard وجود داشته باشد.
- Login و 2FA نیز Glass styling داشته باشند.
- Dashboard شامل این Structure باشد:
  - Glass service-health hero
  - چهار Summary Card
  - Service Grid
  - CPU / RAM / Disk rings
  - Network history
  - Access breakdown
  - Live sessions
- Themeهای Midnight / AMOLED / Graphite همچنان قابل انتخاب و Save باشند.
- Service Worker cache نسل `makia-shell-v0140` را استفاده کند.
- RTL فارسی و English LTR در Desktop/Mobile شکسته نشوند.

## 3. تمام صفحات پنل
صفحات زیر بدون JavaScript Error و Action شکسته باز شوند:
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

Modalها، Wizard، Protected ZIP، Native Export، QR/Share، Diagnostics و Portable Migration در Glass Theme خوانا باشند.

## 4. OpenVPN — مفهوم Domain و TLS
OpenVPN را با HTTPS پنل اشتباه نکنید:
- Nginx/Let's Encrypt برای Web Panel است.
- OpenVPN از EasyRSA CA/Certificate خودش استفاده می‌کند.
- Domain فقط Endpoint فایل OVPN است.
- رکورد VPN باید A مستقیم به IPv4 همین VPS داشته باشد.
- Cloudflare/HTTP CDN در حالت Proxied نباید برای OpenVPN خام استفاده شود؛ رکورد VPN باید DNS-only باشد.

## 5. Domain Diagnostics
Settings → WG / OpenVPN → Domain Diagnostics:
- Service state نمایش داده شود.
- Listener state نمایش داده شود.
- Port و Proto نمایش داده شوند.
- A/IPv4 نمایش داده شود.
- AAAA/IPv6 در صورت وجود نمایش داده شود.
- IPv4های Global VPS نمایش داده شوند.
- اگر A با VPS Match نیست Warning داده شود.
- اگر AAAA وجود دارد، توضیح داده شود که Profile با udp4/tcp4 قفل می‌شود.
- اگر Service/Listener خاموش است Warning داده شود.
- اگر TCP/443 انتخاب شده، تداخل با Nginx HTTPS/TCP 443 Warning داده شود.
- UDP/443 به‌عنوان Transport جدا از HTTPS/TCP 443 قابل استفاده است.

## 6. OpenVPN IPv4 runtime normalization
روی OpenVPN قدیمی با `proto udp` یا `proto tcp-server`:
- Normalize IPv4 runtime را اجرا کن.
- Backup `server.conf.makia-*.bak` ساخته شود.
- UDP → `udp4`
- TCP → `tcp4-server`
- `local 0.0.0.0` وجود داشته باشد.
- Service restart و active شود.
- Listener روی Port واقعی دیده شود.
- در Failure فایل قبلی Restore شود.

## 7. OpenVPN Client with Domain
یک Client با Domain واقعی بساز:
- `remote vpn.example.com PORT`
- UDP Profile: `proto udp4`
- TCP Profile: `proto tcp4-client`
- `resolv-retry infinite`
- `connect-retry 2 300`
- `auth-nocache`
- `remote-cert-tls server`
- `verify-x509-name server name`
- CA/Client Cert/Client Key/tls-crypt داخل OVPN موجود باشند.

Client را روی شبکه بیرونی تست کن:
- Domain profile وصل شود.
- همان Profile با تغییر DNS A به VPS مقصد بعد از propagation بدون Reissue Certificate کار کند.

## 8. Legacy OpenVPN Export
برای Client قدیمی که Artifact آن IP قدیمی دارد:
- Panel Domain را روی Domain واقعی تنظیم کن.
- Native Export بگیر.
- فایل خروجی باید Domain فعلی را در `remote` داشته باشد.
- Profile باید `udp4` یا `tcp4-client` باشد.
- Client Certificate/Key قدیمی باید همان قبلی باقی بماند.
- Protected ZIP نیز فایل re-render شده فعلی را داشته باشد.

## 9. DNS scenarios
این حالات را تست و ثبت کن:
- A صحیح مستقیم → PASS
- A اشتباه → Diagnostics Warning / Client expected FAIL
- Cloudflare Proxied → Diagnostics mismatch/proxy warning؛ DNS-only الزامی
- AAAA اشتباه + A صحیح → Profile udp4/tcp4 باید IPv4 را استفاده کند
- Domain بدون A → Warning
- IP مستقیم → همچنان پشتیبانی شود

## 10. Port collision
- Nginx روی TCP/443 فعال باشد.
- OpenVPN TCP/443 روی همان IP نباید به‌عنوان ترکیب معمول توصیه شود و Diagnostics Warning بدهد.
- OpenVPN UDP/443 می‌تواند هم‌زمان با Nginx TCP/443 تست شود.
- Firewall Provider و UFW هر دو جداگانه بررسی شوند.

## 11. Services
Services باید Allowlist واقعی زیر را نیز نمایش دهد:
- OpenVPN = `openvpn-server@server`
- WireGuard = `wg-quick@wg0`

Start/Stop/Restart فقط همان allowlisted unitها را کنترل کند.

## 12. Regression Gates
- Python compile/import PASS
- Unit tests PASS
- Bash syntax PASS
- JavaScript syntax PASS
- Packaging contracts PASS
- UAT v0.11 / v0.12 / v0.13 / v0.13.1 / v0.14 contracts PASS
- Playwright Browser Smoke PASS
- Xray 26.3.27 guided matrix PASS
- Protected ZIP PASS
- Portable Migration PASS
- All Sidebar views PASS
- No browser page errors

## Stable Gate
Stable فقط اگر:
- Glass UI روی Desktop و Mobile واقعی UAT شود.
- OpenVPN Domain روی DNS-only A record واقعی از Client بیرونی PASS شود.
- Upgrade یک OpenVPN قدیمی و re-export آن PASS شود.
- `makia-doctor` و `makia-uat-smoke` روی VPS واقعی PASS شوند.
- Xray/WireGuard/Migration gateهای نسخه‌های قبل Regression نداشته باشند.
