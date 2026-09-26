# Remote Support Security — Makia

Remote Support در v0.16 برای حذف نیاز به Master Password طراحی شده است.

## مدل دسترسی

مدیر محلی VPS از License & Support یک Grant می‌سازد:

- 15، 30، 60 یا 120 دقیقه
- Read-only یا Operator
- یک Code با Prefix `SUP-`
- فقط یک بار برای Login قابل مصرف

پس از Login، Session تا زمان Expiry معتبر است. ساخت Grant جدید، Grant قبلی را لغو می‌کند.

## محدودیت‌های Remote Support

حتی Scope Operator اجازه این عملیات حساس را ندارد:

- مشاهده/ایجاد API Token
- تغییر Password مدیر
- Setup/Disable کردن 2FA
- حذف License
- ساخت/لغو Remote Support Grant
- Export کردن Native Credential
- Share Link/QR Credential
- Protected ZIP
- Portable Backup
- ساخت Backup حساس

این محدودیت‌ها Backend هستند و فقط UI نیستند.

## Audit

ورود موفق/ناموفق، ساخت Grant، لغو Grant، Logout و تمام Actionهای عادی Support با Actor شبیه زیر ثبت می‌شوند:

```text
support:<grant-id>:operator
```

## Admin CIDR

اگر پنل به CIDR خاص محدود شده باشد، یک Remote Support Session معتبر می‌تواند فقط در بازه Grant از این محدودیت عبور کند. بدون Grant معتبر، CIDR Policy همچنان اعمال می‌شود.

## توصیه

برای کار عادی از Read-only شروع کنید و فقط زمانی Operator بسازید که تغییر Runtime واقعاً لازم است.
