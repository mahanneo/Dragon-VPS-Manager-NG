# Initial upstream audit notes — 2026-09-25

Upstream: januda-ui/DRAGON-VPS-MANAGER

Observed public repository characteristics:
- Legacy structure is centered on Install/, Modulos/ and Sistema/.
- Repository advertises Shell/Python/Linux/SSH tunnel/Telegram bot functionality.
- Upstream README installs by downloading a file named `hehe`, setting mode 777 and executing it.
- Public repository activity shown by GitHub indicates the upstream was last updated in February 2024.
- An open issue requests support for Ubuntu 24/25.
- README states the script was not originally authored by the repository owner.

Migration decision:
- Do not expose legacy shell modules directly over HTTP.
- Build a new web/service boundary, then port verified capabilities behind typed adapters.
- Target Ubuntu 22.04 and 24.04 first; validate 25.xx separately rather than claiming support without host tests.
