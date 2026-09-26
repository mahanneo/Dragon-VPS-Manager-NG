# راهنمای اتصال کاربران Makia

این فایل برای ارسال به کاربران نهایی طراحی شده است. برای راهنمای عمومی روی خود پنل نیز می‌توان از آدرس زیر استفاده کرد:

```text
https://YOUR-PANEL-DOMAIN/help/connect
```

## Xray — VLESS / VMess / Trojan / Shadowsocks / Hysteria2

### روش QR

1. برنامه سازگار مانند v2rayNG، Hiddify یا NekoBox را باز کنید.
2. گزینه Scan QR / Add from QR را انتخاب کنید.
3. QR اتصال مستقیم را اسکن کنید.
4. Profile ساخته‌شده را انتخاب و Connect کنید.

### روش Copy Link

1. Share Link دریافتی را Copy کنید.
2. در Client گزینه Import from Clipboard را بزنید.
3. Profile Import شده را ذخیره و فعال کنید.

### روش Subscription

1. Subscription URL یا QR اشتراک را دریافت کنید.
2. در قسمت Subscription برنامه، Add را بزنید.
3. URL را Paste یا QR را Scan کنید.
4. Update / Refresh subscription را اجرا کنید.

**نکته:** در REALITY مقادیر SNI، Public Key، Short ID و Fingerprint را دستکاری نکنید.

## WireGuard

### Android / iPhone

1. برنامه رسمی WireGuard را باز کنید.
2. روی + بزنید.
3. Create from QR code یا Import from file را انتخاب کنید.
4. QR را اسکن یا فایل `.conf` را انتخاب کنید.
5. Tunnel را روشن کنید.

### Windows / macOS

1. WireGuard را اجرا کنید.
2. Import tunnel(s) from file را انتخاب کنید.
3. فایل `.conf` را Import کنید.
4. Activate را بزنید.

اگر روی یک شبکه وصل نشد، Wi-Fi و Mobile Data را جداگانه امتحان کنید. Endpoint، Port، MTU و DNS را بدون هماهنگی تغییر ندهید.

## OpenVPN

1. OpenVPN Connect را نصب و اجرا کنید.
2. Upload File / Import Profile را انتخاب کنید.
3. فایل `.ovpn` را Import کنید.
4. Add و سپس Connect را بزنید.

فایل OVPN اختصاصی است و نباید برای کاربر دیگری ارسال شود.

## SSH / NPV Tunnel / NapsternetV

### NPV

1. لینک `npvt-ssh://` را Copy کنید یا QR مربوط به NPV را باز کنید.
2. در نسخه سازگار NPV Tunnel / NapsternetV گزینه Import from Clipboard یا Scan QR را انتخاب کنید.
3. Profile را ذخیره و Connect کنید.

### SSH معمولی

از اطلاعات زیر استفاده کنید:

- Server
- Port
- Username
- Password

نمونه:

```bash
ssh USER@SERVER -p PORT
```

OpenSSH رمز عبور را داخل فایل config ذخیره نمی‌کند.

## اگر اتصال برقرار نشد

- اینترنت دستگاه را بررسی کنید.
- تاریخ و ساعت دستگاه صحیح باشد.
- VPN دیگری هم‌زمان فعال نباشد.
- Wi-Fi و Mobile Data را جداگانه تست کنید.
- QR یا Link را دوباره از منبع اصلی Import کنید.
- Credentialها را دستی تغییر ندهید.
- برای پشتیبانی، نام Profile، نام برنامه، سیستم‌عامل و متن خطا را ارسال کنید.
- Credential کامل یا QR را در گروه عمومی نفرستید.
