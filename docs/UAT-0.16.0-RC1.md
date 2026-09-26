# Makia v0.16.0-rc1 — Owner Control Center / Remote Support UAT

این نسخه Release Candidate است.

## Client Upgrade
- makia-upgrade
- VERSION = 0.16.0-rc1
- makia-doctor PASS
- makia-uat-smoke PASS
- License Offline قبلی همچنان معتبر باشد.

## Remote Support
- مدیر محلی یک Grant Read-only 15 دقیقه‌ای بسازد.
- Code فقط یک بار Login شود.
- Login دوم با همان Code Fail شود.
- Banner Remote Support نمایش داده شود.
- Expiry Session مطابق Grant باشد.
- Revoke فوری Session را در Request بعدی نامعتبر کند.
- Grant جدید، Grant قبلی را لغو کند.
- Read-only نتواند Mutation انجام دهد.
- Operator بتواند Diagnostics/Runtime actionهای مجاز را انجام دهد.
- Password / 2FA / API Token / License Remove / Credential Export / Backup برای Remote Support 403 باشند.
- تمام عملیات Audit شوند.

## Owner Control Center
- Service با user makia-owner و bind 127.0.0.1:8790 بالا بیاید.
- Private Key فقط /etc/makia-owner-console و permission محدود داشته باشد.
- Owner login به Password + TOTP نیاز داشته باشد.
- 5 Login ناموفق Rate Limit ایجاد کند.
- Customer create PASS.
- Installation registration PASS.
- Issue Full/Custom License PASS.
- Installation متعلق به Customer دیگری قابل Issue نباشد.
- Ticket Ingest بدون Bearer Token = 403.
- Ticket Ingest با Token صحیح = PASS.
- Private API بدون Owner Session = 401.

## Online License
- Activation Code به Installation ID قفل باشد.
- اولین Sync Signed Lease فعال بگیرد.
- Renew Revision را افزایش دهد.
- Client قدیمی در Sync بعدی replacement license دریافت کند.
- Revoke Signed Lease revoked ایجاد کند.
- Client بعد از Sync به Community برگردد.
- Control Center outage با Lease معتبر وارد Grace محدود شود.
- پس از پایان Lease + Grace Premium بسته شود.
- Owner Offline License بدون Online Required همچنان مستقل کار کند.

## Security
- هیچ Private Signing Key در GitHub/client package نباشد.
- CI مسیر owner_console را هم برای BEGIN PRIVATE KEY اسکن کند.
- Owner service hardening systemd بررسی شود.
- Support Code در DB plaintext ذخیره نشود.
- Ticket Token در root-only env ذخیره شود.
- CSP/No-store/HSTS روی Control Center پشت HTTPS بررسی شود.

## Regression
- Unit PASS
- Browser Smoke PASS
- Xray 26.3.27 Matrix PASS
- OpenVPN Domain tests PASS
- Glass UI PASS
- Community SSH-only PASS
- Full Access PASS
- Portable Migration PASS
