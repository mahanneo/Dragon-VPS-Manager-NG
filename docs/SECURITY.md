# Security model

The web application intentionally does not expose a generic command execution API. Privileged actions are represented as typed operations with validation and allowlists.

Current controls: signed HttpOnly SameSite sessions, scrypt password storage, audit logging, systemd service allowlist, subprocess execution without `shell=True`, strict usernames, minimum password length, bounded audit queries, localhost-only application listener, Nginx security headers.

Before Internet exposure: enable TLS, set the session cookie `secure=True`, add CSRF tokens to state-changing browser requests, add login throttling/rate limits, configure firewall policy, and consider an administrative VPN or IP allowlist.
