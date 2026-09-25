# v0.1.0 build/test report

Build date: 2026-09-25

## Static gates
- Python bytecode compilation: PASS
- Bash installer syntax: PASS
- JavaScript syntax (`node --check` when Node is available): PASS/see build output
- No `shell=True` in privileged Python operations: PASS
- Service action allowlist: PASS by inspection
- Username validation: PASS by inspection
- Installer does not use chmod 777: PASS

## Host UAT still required
- Fresh Ubuntu 22.04 install
- Fresh Ubuntu 24.04 install
- Create/lock/unlock/delete a disposable SSH account
- Restart each installed allowlisted service
- Verify Nginx reverse proxy and login persistence
- Enable HTTPS and set Secure cookie before public exposure
- Validate rollback/uninstall procedure before production rollout
