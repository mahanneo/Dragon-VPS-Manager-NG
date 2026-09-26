# Makia VPS Manager v0.12.0-rc2 — Network / Domain / Portable Recovery UAT

این نسخه فقط Release Candidate است. Stable شدن آن نیازمند UAT واقعی روی VPS و Clientهای بیرونی است.

## 1. Upgrade and base health

روی VPS فعلی:

```bash
sudo makia-upgrade
cat /opt/makia-vps-manager/VERSION
sudo makia-doctor
sudo makia-uat-smoke
```

انتظار:
- VERSION = `0.12.0-rc2`
- Backend/Nginx/Workers سالم
- Xray config validation در صورت نصب Xray PASS
- WireGuard runtime در صورت وجود `wg0.conf` فعال باشد
- Portable backup encryption/verification PASS

## 2. Domain + Nginx + HTTPS

در Settings → Domain / Nginx / HTTPS:
1. یک Domain ثابت مانند `vpn.example.com` تعریف شود.
2. رکورد A/AAAA به VPS فعلی اشاره کند.
3. Apply domain to Nginx اجرا شود.
4. `nginx -t` PASS باشد.
5. Let's Encrypt صادر شود.
6. پنل با `https://vpn.example.com` باز شود.
7. Login/2FA/API/QR download روی HTTPS تست شود.

نکته: Nginx پنل TCP/443 را مصرف می‌کند. WireGuard UDP/443 می‌تواند همزمان استفاده شود چون UDP و TCP Socket جدا هستند. دو سرویس UDP نمی‌توانند همزمان همان UDP Port را بگیرند.

## 3. Xray Guided Builder

حداقل این ترکیب‌ها روی Xray Core 26.3.27 واقعی ساخته و از شبکه خارجی تست شوند:
- VLESS + XHTTP + REALITY
- Trojan + XHTTP + REALITY
- VLESS + gRPC + TLS با Certificate همان Domain
- VMess + WebSocket + TLS
- Shadowsocks guided profile
- Hysteria2 + TLS روی یک UDP Port آزاد

برای هر Client:
- Share Link معتبر باشد.
- Direct QR قابل Import باشد.
- Subscription QR قابل Import باشد.
- Client Page فقط اطلاعات همان Client را نمایش دهد.
- Protected ZIP و Native export سالم باشند.
- Expiry / quota / IP policy مطابق قابلیت همان Protocol اعمال شود.

## 4. Full Xray Config Studio

Protocol Hub → Full Xray Config Studio:
- Config فعلی خوانده شود.
- یک تغییر بی‌خطر روی JSON آزمایشی انجام شود.
- Validate بدون Apply با خود Xray PASS شود.
- Apply فقط بعد از Validate انجام شود.
- در خطای Config نسخه قبلی Rollback شود.
- Routing / DNS / Outbounds / Fallbacks و ساختارهای پیشرفته‌ای که Guided UI ندارد از همین مسیر قابل مدیریت باشند.

Guided Builder فقط ترکیب‌هایی را ارائه می‌دهد که Makia می‌تواند Share/QR قابل اتکا برایشان بسازد؛ Advanced JSON نباید به چند Preset محدود شود.

## 5. WireGuard standard profile

- Server bootstrap با UDP 51820 و MTU Auto.
- Client با Domain ثابت ساخته شود، نه IP.
- PersistentKeepalive = 25 تست شود.
- QR/.conf Import روی Android و Windows تست شود.
- Handshake و اینترنت از شبکه Wi-Fi عادی PASS باشد.
- Restart سرور باعث از دست رفتن Peer/Key نشود.

## 6. WireGuard restricted-network preset

Settings → WG / OpenVPN → Restricted-network preset:
- UDP Port = 443
- MTU = 1280
- PersistentKeepalive = 25

سپس Server و Peer جدید با همین Profile تست شود:
- Mobile data
- Wi-Fi/ISP دیگر
- حداقل یک شبکه‌ای که قبلاً WireGuard استاندارد روی آن مشکل داشته است

اگر WireGuard روی یک شبکه هیچ Handshake نمی‌دهد ولی همان Profile روی شبکه دیگری کار می‌کند، این موضوع به‌عنوان Network/UDP filtering ثبت شود؛ Makia نباید WireGuard را TCP معرفی کند. در چنین شبکه‌ای Xray TLS/REALITY باید جداگانه تست شود.

## 7. TCP/UDP port coexistence

- Panel HTTPS روی TCP 443 فعال باشد.
- WireGuard روی UDP 443 Bootstrap شود؛ نباید فقط به‌خاطر TCP 443 رد شود.
- در صورت آزاد بودن UDP 443، Hysteria2 UDP 443 نیز باید از دید Port-family check مستقل از Nginx TCP 443 باشد.
- اگر WireGuard قبلاً UDP 443 را گرفته، Hysteria2 روی همان UDP 443 باید با Conflict واقعی رد شود.

## 8. Domain continuity readiness

Settings → Backup / Recovery:
- Panel Domain باید تنظیم شده باشد.
- Certificate باید حاضر باشد.
- Xray managed clients باید Domain همان پنل را در Share Link داشته باشند.
- WireGuard/OpenVPN/SSH profileهای جدید باید Domain را به‌عنوان Endpoint/Host داشته باشند.
- SSH artifactهای دارای Password رمزگذاری‌شده باید Recoverable نمایش داده شوند.

Profile قدیمی که IP دارد «seamless migration ready» محسوب نشود؛ قبل از Migration باید Profile/Subscription آن Refresh و روی Client اعمال شود.

## 9. Portable encrypted backup

از Settings یا API:
- Download Portable Bundle با Password حداقل ۸ کاراکتر.
- Bundle باید AES-256 protected باشد.
- بدون Password صحیح باز نشود.
- شامل `manifest.json` و `makia-portable.tar.gz` باشد.
- SQLite از Online Backup تهیه شده باشد، نه Copy خام DB/WAL.
- در صورت وجود شامل موارد زیر باشد:
  - Makia data + server secret
  - Xray config/REALITY keys
  - WireGuard config/server private key
  - OpenVPN PKI
  - Nginx site
  - Let's Encrypt certificate material
  - Makia Fail2ban override

## 10. Restore to a fresh VPS

روی یک VPS تازه با Ubuntu 22.04/24.04:
1. Makia همین RC2 نصب شود.
2. Bundle کپی شود.
3. ابتدا فقط Validate:

```bash
sudo makia-restore /root/makia-portable.zip
```

4. سپس Apply:

```bash
sudo makia-restore /root/makia-portable.zip --apply
```

انتظار:
- قبل از Apply مقصد Safety Backup ساخته شود.
- Engineهای Xray/WireGuard/OpenVPN موردنیاز اگر نصب نیستند نصب شوند.
- DB/Secret و Config/Key/PKI بازیابی شوند.
- Xray config قبل از Start با Core validate شود.
- SSH users دارای Credential قابل بازیابی دوباره ساخته/Update شوند.
- User فاقد Credential قابل بازیابی صریحاً برای Reset دستی گزارش شود.
- Nginx config PASS شود.
- `makia-uat-smoke` در پایان PASS باشد.

## 11. DNS cutover / client continuity

قبل از Migration بهتر است TTL رکورد DNS کاهش داده شود.

بعد از Restore:
- A/AAAA همان Domain به IP VPS جدید تغییر کند.
- Client profileها تغییر داده نشوند.
- Xray Subscription و Direct profileهای Domain-based دوباره Connect شوند.
- WireGuard Domain-based peer با همان Server key و Client key Connect شود.
- OpenVPN Domain-based profile با همان PKI Connect شود.
- SSH user با همان Username/Password روی Domain Connect شود.

اتصال TCP/UDP باز روی VPS قبلی نمی‌تواند فیزیکی بدون وقفه به VPS جدید منتقل شود؛ معیار این UAT این است که Client بدون Reissue/Reimport Credential/Profile، پس از DNS/network reconnection دوباره متصل شود.

## 12. Security

- Portable Bundle خارج از پنل Cache نشود.
- Audit برای ساخت Portable Backup ثبت شود.
- Restore بدون `--apply` فقط Validate کند.
- Archive traversal/symlink unsafe payload رد شود.
- فایل‌های Secret/DB و WireGuard configs با Permission مناسب باقی بمانند.
- Admin API و Share Center همچنان Authentication/Mutation header لازم داشته باشند.

## 13. Stable gate

Stable فقط در صورت PASS کامل:
- Unit / syntax / packaging contracts
- Browser Smoke
- Xray Core 26.3.27 VLESS REALITY
- Xray Core 26.3.27 Trojan REALITY
- Portable Backup round-trip
- Host `makia-uat-smoke`
- Panel HTTPS واقعی
- WireGuard standard real-client test
- WireGuard restricted preset real-client test
- Xray external-client test
- Portable restore روی VPS دوم
- DNS cutover و reconnect بدون Reissue برای Profileهای Domain-based

تا قبل از این موارد نسخه باید `v0.12.0-rc2` باقی بماند و Stable نامیده نشود.
