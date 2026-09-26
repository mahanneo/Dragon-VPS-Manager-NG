# Makia VPS Manager v0.13.0-rc1 — Migration / Domain / WireGuard / Xray UAT

این نسخه **Release Candidate** است و تا پایان UAT واقعی روی دو VPS و Client واقعی Stable نیست.

## 1. Upgrade and host health
روی VPS مبدا:
- `sudo makia-upgrade`
- `cat /opt/makia-vps-manager/VERSION` → `0.13.0-rc1`
- `sudo makia-doctor` → PASS
- `sudo makia-uat-smoke` → PASS
- اگر Xray نصب است، validation کانفیگ فعال با Xray Core PASS باشد.
- اگر WireGuard `wg0` وجود دارد، `wg show wg0` PASS باشد.

## 2. Domain / Nginx / HTTPS
- یک دامنه واقعی مثل `vpn.example.com` روی VPS مبدا قرار گیرد.
- Settings → Domain / Nginx / HTTPS:
  - Apply domain to Nginx
  - `nginx -t` PASS
  - Let’s Encrypt issue/renew PASS
  - پنل با `https://vpn.example.com` باز شود.
- Login cookie روی HTTPS دارای Secure باشد.
- Client/Subscription URLها Domain فعلی پنل را استفاده کنند.

## 3. Migration-safe client endpoints
- هنگام ساخت Xray، WireGuard و OpenVPN، Endpoint پیش‌فرض همان Panel Domain باشد.
- حداقل یک Xray و یک WireGuard Client با **دامنه** ساخته شوند، نه IP.
- Share/QR را اسکن و اتصال واقعی از بیرون VPS بررسی کن.
- قبل از Migration لینک‌ها/Configها را ذخیره کن؛ بعد از Migration نباید Credential یا key عوض شده باشد.

## 4. WireGuard compatibility
Settings → WG / OpenVPN:
- Compatibility preset:
  - UDP port = 443
  - MTU = 1280
  - PersistentKeepalive = 15
  - AllowedIPs = `0.0.0.0/0`
- Bootstrap جدید با Port/CIDR/MTU اعمال شود.
- Peer جدید شامل:
  - Endpoint دامنه
  - MTU انتخاب‌شده
  - Keepalive انتخاب‌شده
  - AllowedIPs انتخاب‌شده
  - DNS انتخاب‌شده
- QR و Native config با هم یکسان باشند.
- تست واقعی حداقل روی Wi-Fi و Mobile Data انجام شود.
- اگر WireGuard در شبکه هدف protocol-level block است، این مورد به‌عنوان محدودیت شبکه ثبت شود؛ از Xray/REALITY به‌عنوان مسیر جایگزین استفاده شود.

## 5. Xray guided + full-core mode
- Guided create برای VLESS / VMess / Trojan / Shadowsocks / Hysteria2 بررسی شود.
- VLESS + XHTTP + REALITY واقعی ساخته و از Client خارجی وصل شود.
- TLS mode با Domain و گواهی Let’s Encrypt واقعی تست شود.
- Settings → Xray Defaults → Advanced JSON:
  - Config فعلی Load شود.
  - Validate بدون Apply PASS شود.
  - یک تغییر بی‌خطر روی JSON تست شود.
  - Apply → Xray core validation → restart → active PASS.
  - JSON نامعتبر یا config نامعتبر نباید جایگزین config فعال شود.
  - Rollback در Failure بررسی شود.
- Advanced JSON مسیر Full Xray Core است؛ پنل نباید arbitrary Core capability را با whitelist نمایشی محدود کند.

## 6. Portable Migration Bundle
از پنل مبدا:
- Backups → Portable Migration
- Password حداقل ۱۰ کاراکتر
- ZIP دانلود شود.
- ZIP بدون Password باز نشود.
- با Password صحیح موارد زیر وجود داشته باشند:
  - `manifest.json`
  - `payload/data.tar.gz`
  - `payload/ssh-users.json`
  - Xray/WireGuard/OpenVPN/TLS/Nginx payloadها در صورت نصب بودن سرویس مربوط
- `manifest.json` شامل Domain و نسخه باشد.
- `.secret` داخل data snapshot حفظ شود تا Access Artifactها بعد از Restore decrypt شوند.

## 7. Destination VPS restore
روی VPS دوم:
1. نسخه همان Makia را Fresh Install کن.
2. Bundle را به سرور منتقل کن.
3. ابتدا فقط Validate:
   `sudo makia-restore-portable /path/to/bundle.zip`
4. سپس:
   `sudo makia-restore-portable /path/to/bundle.zip --apply`
5. خروجی Portable restore PASS باشد.
6. `sudo makia-doctor` و `sudo makia-uat-smoke` PASS باشند.

بعد از Restore:
- Admin login با اطلاعات قبلی کار کند.
- 2FA قبلی در صورت فعال بودن کار کند.
- Access Artifactهای رمزگذاری‌شده باز شوند.
- Xray config و REALITY keyها همان مبدا باشند.
- WireGuard server public key همان مبدا باشد.
- WireGuard peerها همان public key/allowed IP را داشته باشند.
- OpenVPN PKI/Client certificateها همان قبلی باشند.
- SSH Userهای مدیریت‌شده با همان username/password hash و expiry قابل ورود باشند.

## 8. DNS cutover
- TTL دامنه قبل از Migration کاهش داده شود.
- بعد از Restore و UAT مقصد، DNS A/AAAA همان Domain به VPS جدید تغییر کند.
- روی Clientهای قبلی هیچ Link/QR/Config جدیدی Import نشود.
- Xray Client قبلی پس از DNS propagation وصل شود.
- WireGuard Client قبلی با همان config وصل شود.
- Subscription URL قبلی همچنان پاسخ دهد.
- Client Page قبلی همچنان باز شود.
- HTTPS certificate روی مقصد معتبر باشد.
- قطعی کوتاه ناشی از DNS propagation قابل انتظار است؛ معیار PASS این است که Credentialها نیاز به Reissue نداشته باشند.

## 9. Security
- Portable Bundle فقط authenticated admin + mutation header قابل ساخت باشد.
- ZIP با AES-256 password protection باشد.
- Password در audit log ذخیره نشود.
- Bundle شامل plaintext SSH password نباشد؛ فقط password hash سیستم برای migration نگهداری شود.
- فایل migration با permission امن نگهداری و پس از انتقال از محل‌های عمومی حذف شود.
- Restore archive path traversal را رد کند.

## 10. Regression
- Unit tests PASS.
- JavaScript syntax PASS.
- Browser Smoke PASS.
- Xray 26.3.27 real-core smoke PASS.
- Protected ZIP tests PASS.
- NPV share-link tests PASS.
- تمام Sidebar views PASS.
- تمام Settings V2 tabs PASS.
- Portable Migration browser download PASS.
- WireGuard settings persistence PASS.

## Stable gate
Stable فقط پس از این موارد:
- CI کامل PASS
- Source PR merge شده روی main
- دو-VPS migration واقعی PASS
- Domain/TLS cutover واقعی PASS
- Xray external client PASS
- WireGuard real-network test ثبت‌شده
- `makia-uat-smoke` روی VPS مقصد PASS
- هیچ Credential Reissue برای Clientهای دامنه‌محور لازم نباشد
