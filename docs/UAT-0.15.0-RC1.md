# Makia VPS Manager v0.15.0-rc1 — License / Security / OpenVPN Hybrid UAT

این Release Candidate سه هدف اصلی دارد: **OpenVPN Domain+IP Smart Fallback**، **Community SSH-only + Full Access License** و **سخت‌سازی پنل/توزیع**.

## 1. Upgrade / rollback gate

روی VPS واقعی:

```bash
sudo makia-upgrade
cat /opt/makia-vps-manager/VERSION
sudo makia-doctor
sudo makia-uat-smoke
```

نسخه باید `0.15.0-rc1` باشد. Updater باید قبل از جایگزینی Runtime بکاپ بگیرد و Failure را rollback کند.

## 2. OpenVPN Domain + IP Smart Fallback

با دامنه‌ای که A آن مستقیم به IPv4 VPS اشاره می‌کند:

- Diagnostics باید Service=ACTIVE و Listener=READY نشان دهد.
- `hybrid_available=true` باشد.
- `hybrid_fallback_ipv4` باید IPv4 عمومی همان VPS باشد.
- Export یک Client قدیمی و Client جدید را بررسی کن.
- Profile باید ابتدا Domain و بعد IPv4 مستقیم را داشته باشد:

```text
proto udp4
remote vpn.example.com 1194
remote 203.0.113.10 1194
resolv-retry 5
server-poll-timeout 8
connect-retry 2 30
```

برای TCP، `proto tcp4-client` استفاده شود.

### تست واقعی Client

1. DNS Client سالم: اتصال باید با Domain برقرار شود.
2. DNS دامنه روی Client عمداً Fail/Block شود ولی IP سرور Reachable باشد: همان Profile باید بعد از Timeout به IPv4 دوم برود.
3. Profile مستقیم IP نیز همچنان باید متصل شود.
4. اگر A دامنه به VPS اشاره نمی‌کند، fallback نباید از IP نامرتبط ساخته شود.
5. Cloudflare/CDN Proxied برای OpenVPN خام به‌عنوان مسیر صحیح تلقی نشود.

## 3. Community mode

بدون Activation Code:

- License status = `community`.
- SSH create/edit/lock/unlock/disconnect/native delivery کار کند.
- Xray creation/config/diagnostics/repair در Backend با HTTP 403 و `license_required` رد شود.
- WireGuard bootstrap/peer با 403 رد شود.
- OpenVPN bootstrap/client/diagnostics/repair با 403 رد شود.
- Multi-node و Portable Migration قفل باشند.
- Protected ZIP قفل باشد.
- Access Center سه کارت Xray/WireGuard/OpenVPN را با **Full Access** نشان دهد.
- Protocols و Nodes صفحه Lock حرفه‌ای نمایش دهند.
- سرویس‌های Premium نباید Start/Restart/Stop قابل اجرا داشته باشند.
- حذف License از یک Full install باید بدون Restart فوراً Community gate را فعال کند.

## 4. Full Access signed license

Private Key نباید روی GitHub یا VPS مشتری قرار گیرد.

در ماشین امن مالک:

```bash
python tools/license_issue.py \
  --private-key /secure/makia-license-private-key.pem \
  --installation-id MK-XXXXXXXXXXXXXXXXXXXX \
  --customer "Customer Name" \
  --days 365
```

در پنل مشتری:

**License & Support → Activation Code → Activate**

Gateها:
- Signature Ed25519 معتبر باشد.
- Installation ID دقیقاً Match باشد.
- License دستکاری‌شده Reject شود.
- License متعلق به Installation دیگر Reject شود.
- Expired License به Community برگردد.
- Full Access باید Xray/WireGuard/OpenVPN/Protected Delivery/Subscriptions/Portable Migration/Nodes را باز کند.

## 5. Support / access request

در Community:

- Installation ID قابل Copy باشد.
- فرم Ticket با Subject/Message کار کند.
- Ticket همیشه در SQLite محلی ذخیره شود.
- اگر `MAKIA_SUPPORT_WEBHOOK_URL` تنظیم نشده، وضعیت Local باشد و متن آماده Copy شود.
- اگر HTTPS webhook معتبر تنظیم شده، JSON Ticket ارسال و Delivery status ثبت شود.
- اگر `MAKIA_SUPPORT_TELEGRAM` تنظیم شده، دکمه Telegram به `https://t.me/<username>` برود.
- هیچ signing private key/token در API support status افشا نشود.

## 6. Owner configuration

```bash
sudo makia-owner-config --telegram YOUR_USERNAME
sudo systemctl restart makia-vps-manager
```

برای webhook:

```bash
sudo makia-owner-config --webhook https://support.example.com/makia/tickets
sudo systemctl restart makia-vps-manager
```

فایل `/etc/makia-vps-manager/makia.env` باید owner=root و mode=0600 باشد.

## 7. Optional admin network allowlist

برای محدود کردن Login/Admin API به IP/CIDRهای مورد اعتماد:

```bash
sudo makia-owner-config --admin-cidrs "203.0.113.4/32,10.0.0.0/8"
sudo systemctl restart makia-vps-manager
```

- Login از CIDR مجاز PASS.
- Login از IP غیرمجاز HTTP 403.
- `/healthz`, public client/subscription pages و static assets همچنان قابل دسترسی باشند.
- اگر مدیر خودش را Lockout کرد، از SSH مقدار `--admin-cidrs ""` را پاک کند و سرویس را Restart کند.

## 8. HTTP / session hardening

بررسی Headerها:
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: no-referrer
- Permissions-Policy
- Content-Security-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Resource-Policy
- HSTS روی HTTPS
- Cache-Control: no-store برای Admin/API

Mutationها:
- Header `X-Makia-Request: 1` لازم باشد.
- Cross-origin Origin رد شود.
- `Sec-Fetch-Site: cross-site` رد شود.
- Login rate-limit و 2FA قبلی Regression نداشته باشند.

## 9. Host/source permissions

بعد از install/update:

```bash
stat -c '%U:%G %a %n' /opt/makia-vps-manager/app
find /opt/makia-vps-manager/app -maxdepth 1 -type f -printf '%u:%g %m %p\n'
stat -c '%U:%G %a %n' /etc/makia-vps-manager/makia.env
```

انتظار:
- Application files root-owned
- Directories 0750
- Source files 0640
- Owner env 0600

توجه: کاربری که **root خود VPS** را در اختیار دارد، در معماری local Python هیچ‌گاه از نظر رمزنگاری از مشاهده Runtime بازداشته نمی‌شود. این Permissionها برای جلوگیری از خواندن توسط کاربران غیر-root همان Host هستند، نه DRM علیه root.

## 10. Private release path

v0.15 updater باید این متغیرها را از root-only env بخواند:

- `MAKIA_RELEASE_ARCHIVE_URL`
- `MAKIA_RELEASE_BEARER_TOKEN`

Updater نباید فایل env را با shell `source`/eval کند؛ فقط keyهای allowlist را parse کند.

برای مشتری‌ای که root دارد، GitHub PAT مالک را روی VPS ذخیره نکن. برای توزیع تجاری از Release Proxy یا URL کوتاه‌عمر استفاده شود.

## 11. Nginx / client IP

- `server_tokens off`
- `X-Forwarded-For` و `X-Forwarded-Host` به Backend پاس داده شوند.
- Login/Audit/Admin allowlist باید IP واقعی Client را ببیند.
- Nginx config قبل از reload با `nginx -t` PASS شود.

## 12. Regression gates

- Python compile PASS
- Unit tests PASS
- JavaScript syntax PASS
- Bash syntax PASS
- Dangerous-pattern guard PASS
- Licensing tests PASS
- Community browser smoke PASS
- Full browser smoke PASS
- OpenVPN Hybrid tests PASS
- Xray 26.3.27 Core matrix PASS
- UAT v0.11 تا v0.15 contract PASS
- Protected ZIP در Full mode PASS
- Portable Migration در Full mode PASS
- No browser page errors

## Stable gate

این RC فقط وقتی Stable شود که:
- روی VPS واقعی فعلی Upgrade شود؛
- OpenVPN Hybrid از حداقل یک Client موبایل و یک Desktop تست شود؛
- Community → Full → Community round-trip واقعی PASS شود؛
- یک Activation Code واقعی با Private Key مالک صادر و روی Installation واقعی فعال شود؛
- Support/Telegram تنظیم شود؛
- `makia-doctor` و `makia-uat-smoke` PASS باشند.
