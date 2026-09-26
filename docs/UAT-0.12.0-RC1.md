# Makia VPS Manager v0.12.0-rc1 — QR / NPV / Settings UAT

این Release فقط وقتی Stable می‌شود که موارد زیر روی VPS واقعی و Client واقعی پاس شوند.

## 1. Upgrade and host health
- `sudo makia-upgrade`
- `cat /opt/makia-vps-manager/VERSION` → `0.12.0-rc1`
- `sudo makia-doctor` PASS
- `sudo makia-uat-smoke` PASS
- Xray 26.3.27 active config validation PASS when Xray is installed.

## 2. Xray direct QR
برای یک VLESS + XHTTP + REALITY واقعی:
- Create از Access Center.
- دکمه `QR / Share` باز شود.
- QR مستقیم نمایش داده شود.
- Copy Import Link دقیقاً همان URI ذخیره‌شده Client باشد.
- SVG QR دانلود شود.
- QR در v2rayNG یا Hiddify یا NPV Client اسکن شود.
- اتصال واقعی از شبکه بیرونی برقرار شود.
- Revoke باعث قطع/نامعتبرشدن دسترسی شود.

## 3. Xray subscription QR
- QR Subscription در Share Center نمایش داده شود.
- URL از Domain/Origin فعلی پنل ساخته شود، نه Domain قدیمی Artifact.
- QR در Client سازگار به‌عنوان Subscription اضافه شود.
- `/sub/<id>?format=base64` پروفایل معتبر بدهد.
- Expired/disabled/quota-exhausted client از Subscription پاسخ 403 بگیرد.

## 4. Public client portal QR
- `/client/<subscription_id>` بدون دسترسی مدیریتی باز شود.
- فقط داده همان Client نمایش داده شود.
- QR اتصال مستقیم و QR اشتراک هر دو نمایش داده شوند.
- هیچ Admin token، server secret، private panel setting یا Client دیگر افشا نشود.

## 5. SSH → NPV Tunnel / NapsternetV
برای یک SSH User جدید:
- NPV delivery در Settings فعال باشد.
- Access Center → `NPV Import` باز شود.
- `npvt-ssh://` تولید شود.
- JSON داخل Base64 شامل Host, Port, Username, Password و SSH-Direct باشد.
- QR همان `npvt-ssh://` را encode کند.
- لینک با Copy Clipboard در NPV Tunnel/NapsternetV-compatible Client Import شود.
- QR با Scan QR در Client Import شود.
- اتصال واقعی SSH برقرار شود.
- Password/PIN، Expiry، Session limit و Device/IP limit سمت Makia همچنان اعمال شوند.
- Protected ZIP شامل OpenSSH config، credentials، NPV link و NPV QR باشد.

## 6. NPV settings
- Profile prefix روی Remarks خروجی اعمال شود.
- DNS mode UDP/TCP روی JSON خروجی اعمال شود.
- UDPGW port روی JSON خروجی اعمال شود.
- Transparent DNS فقط در صورت وجود زیرساخت واقعی UDPGW فعال شود.
- با NPV delivery = Disabled، User جدید NPV link/QR نگیرد.
- User قدیمی دارای encrypted credential در صورت Enabled شدن NPV بتواند Share Artifact را Upgrade کند.

## 7. Settings Center V2
تمام Tabها تست شوند:
- Panel: Language, Theme, Density, Panel Domain.
- Domain & TLS: DNS status, Nginx apply, Let's Encrypt issue/renew.
- Delivery: Profile prefix, QR display, NPV enable, DNS mode, UDPGW port, transparent DNS.
- Provisioning: SSH defaults, Xray defaults, WG DNS, OpenVPN port/protocol.
- Security: Session lifetime, admin password, 2FA.
- API: token create, one-time secret display, scoped access, revoke.

## 8. Provisioning defaults
- SSH Password mode در Wizard جدید استفاده شود.
- SSH expiry/session/device defaults دقیقاً از Settings بیایند.
- Xray protocol/port/transport/security/path/SNI/target/quota/expiry/IP/reset defaults از Settings بیایند.
- WireGuard DNS و OpenVPN port/proto از Settings بیایند.
- Browser reload باعث برگشت به hard-coded defaults نشود.

## 9. Session lifetime
- مقدار 5 دقیقه، 720 دقیقه و یک مقدار سفارشی تست شود.
- Cookie جدید بعد از login دارای lifetime تنظیم‌شده باشد.
- تغییر مقدار Session نشست فعلی را ناگهانی باطل نکند و روی login بعدی اعمال شود.
- HTTPS همچنان Secure cookie داشته باشد.

## 10. QR and credential safety
- `/api/access/*/*/share` بدون Admin session پاسخ ندهد.
- `/api/access/*/*/qr.svg` بدون Admin session پاسخ ندهد.
- QR/Share حاوی Credential است؛ فقط Admin آن را ببیند.
- Protected ZIP همچنان AES-256 و password-protected باشد.
- DB artifact payload plaintext credential نباشد.
- Audit برای protected export و عملیات مدیریتی باقی بماند.

## 11. Browser matrix
- Chrome 1920×1080.
- Chrome/Edge 1366×768.
- Android Chrome حدود 390px.
- Settings tabs روی موبایل horizontal-scroll/usable باشند.
- QR modal روی موبایل overflow نداشته باشد.
- Copy link و QR download در Chrome/Edge کار کنند.

## Stable gate
- Main CI test PASS.
- Browser Smoke PASS.
- Xray 26.3.27 real-core smoke PASS.
- `makia-uat-smoke` روی Host واقعی PASS.
- Xray direct QR connection PASS.
- Xray subscription QR PASS.
- NPV SSH Clipboard import PASS.
- NPV SSH QR import PASS.
- No credential leakage outside intended authenticated/public-secret surfaces.
