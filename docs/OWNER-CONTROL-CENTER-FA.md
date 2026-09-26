# راهنمای Owner Control Center — Makia v0.16

Owner Control Center روی **سرور خود مالک پروژه** نصب می‌شود و روی VPS مشتری نصب نمی‌شود. Private Key صدور License فقط روی همین سرور قرار می‌گیرد.

## معماری

- Client VPS: فقط Public Key، Activation Code و Signed Lease را دارد.
- Owner Control Center: Private Key، مشتری‌ها، Installationها، Licenseها، Ticketها و Audit را نگه می‌دارد.
- License تجاری به یک Installation ID مشخص متصل است.
- Renew از Control Center، Revision جدید همان License را صادر می‌کند.
- Client در Sync بعدی Revision جدید را دریافت و بدون Paste مجدد فعال می‌کند.
- Revoke در Control Center یک Signed Lease با وضعیت revoked برمی‌گرداند؛ Client در Sync بعدی به Community برمی‌گردد.
- اگر Control Center موقتاً در دسترس نباشد، Lease فعال حداکثر تا Grace تعریف‌شده ادامه پیدا می‌کند. مقدار پیش‌فرض Lease یک روز و Grace سه روز است.
- Licenseهای Offline که با tools/license_issue.py ساخته می‌شوند همچنان مستقل از Control Center هستند و برای Owner یا محیط‌های بدون Online Revocation مناسب‌اند.

## نصب Owner Control Center

روی VPS اختصاصی مالک:

```bash
sudo bash tools/install-owner-console.sh \
  --private-key /secure/makia-license-private-key.pem \
  --public-url https://owner.example.com
```

Password به‌صورت مخفی Prompt می‌شود. Installer یک TOTP Secret و Ticket Ingest Token تولید می‌کند. همان لحظه TOTP را وارد Authenticator خود کنید.

Service فقط روی:

```text
127.0.0.1:8790
```

Listen می‌کند. برای دسترسی عمومی، Nginx Reverse Proxy + HTTPS لازم است. نمونه در `owner_console/nginx.example.conf` قرار دارد.

## اتصال پنل مشتری به Ticket Center

Ticket Endpoint:

```text
https://owner.example.com/api/public/tickets
```

روی VPS مشتری:

```bash
sudo makia-owner-config \
  --control-plane https://owner.example.com \
  --support-token YOUR_INGEST_TOKEN

sudo systemctl restart makia-vps-manager
```

## جریان فروش License

1. مشتری Makia را نصب می‌کند و Installation ID را ارسال می‌کند.
2. در Owner Console مشتری را ایجاد کنید.
3. Installation ID را زیر همان مشتری Register کنید.
4. License صادر کنید: 30 / 90 / 365 روز یا 0 برای بدون انقضا.
5. Activation Code را یک‌بار برای مشتری بفرستید.
6. بعد از Activation، Client Signed Lease دریافت می‌کند.
7. برای تمدید، از Owner Console روی Renew بزنید؛ Client در Sync خودکار Revision جدید را دریافت می‌کند.
8. برای ابطال، Revoke کنید؛ Client در Sync بعدی Premium را می‌بندد.

## نکته امنیتی مهم

Owner Console **Master Login به VPS مشتری نیست**. ورود پشتیبانی از Remote Support Code محلی و رضایت صریح مشتری استفاده می‌کند. Private Key License نیز هرگز به پنل مشتری منتقل نمی‌شود.
