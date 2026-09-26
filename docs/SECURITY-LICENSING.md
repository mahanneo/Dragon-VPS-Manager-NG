# Makia Security, Licensing & Source-Protection Model

## Threat model

Makia v0.15 separates three concerns:

1. **Server security** — protect the running admin panel, credentials and management actions.
2. **Feature entitlement** — Community installations are SSH-only; premium capabilities require an owner-signed license bound to one installation.
3. **Source distribution** — reduce casual copying and support a private release channel without pretending that software running on a customer-controlled root account can be made cryptographically unreadable.

## Signed entitlement

Makia uses Ed25519 signatures. The application contains only the public verification key. The private signing key must remain offline with the publisher.

A Full code is bound to the installation ID derived from the host machine identity. Copying the code to another VPS does not activate that VPS.

The server validates the license locally; a permanent online licensing dependency is not required.

## Community and Full

Community capabilities include SSH management, security, domain/HTTPS, updates and support.

Premium features include Xray, WireGuard, OpenVPN, Protected ZIP delivery, subscriptions, portable migration, nodes and advanced service operations. Backend enforcement is authoritative; UI locks are only presentation.

## What source protection can and cannot do

Root-only file permissions prevent ordinary local users from reading Makia application files. A private repository prevents casual cloning from the public GitHub page. Neither prevents a customer who controls root on the server from copying bytes that must execute on that server.

For materially stronger commercial IP protection, premium logic should eventually be split into one of these architectures:

- a private compiled premium agent with a narrow local RPC interface; or
- an owner-hosted premium control service where sensitive implementation never reaches the customer host.

Python obfuscation or bytecode-only distribution raises effort but is not a security boundary.

The current repository declares GPL-3.0-or-later. Do not remove license obligations or relicense third-party/copyleft code without a provenance and copyright audit.

## Private update channel

The updater accepts an HTTPS release archive URL and optional bearer token from root-only `/etc/makia-vps-manager/makia.env`.

Do not put a broad GitHub owner PAT on a customer VPS. If the customer controls root, that token can be read. Prefer a dedicated release proxy, scoped single-purpose credential or short-lived signed download URL.

## Signing-key custody

The Ed25519 private key:
- must never be committed;
- must never be copied to customer VPSes;
- should be stored offline/encrypted with at least one secure backup;
- should only be used to issue installation-bound activation codes.

If the private key is lost, existing valid licenses continue to verify but new codes cannot be issued. If it is exposed, rotate the public/private key pair in a controlled release.

## Admin hardening

Makia combines:
- signed HttpOnly SameSite cookies;
- optional TOTP 2FA;
- login rate limiting;
- mutation header + same-origin checks;
- CSP and anti-framing headers;
- no-store admin/API responses;
- Fail2ban baseline;
- optional CIDR allowlist;
- root-owned source/data permissions;
- audit logging.

The web process still runs as root in v0.15 because it performs validated Linux account and service mutations. A future privileged-helper split would materially reduce blast radius and remains a worthwhile Stable-hardening direction.
