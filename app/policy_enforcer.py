import time
from collections import defaultdict
from .db import all_profiles, audit
from .system_ops import online_sessions, disconnect_session, OperationError

POLL_SECONDS=12

def enforce_once():
    profiles=all_profiles()
    grouped=defaultdict(list)
    for s in online_sessions():
        grouped[s.get("username","")].append(s)
    for username,sessions in grouped.items():
        p=profiles.get(username)
        if not p or not int(p.get("enabled",1)): continue
        limit=max(1,int(p.get("connection_limit",1) or 1))
        if len(sessions)<=limit: continue
        extras=sessions[limit:]
        for s in extras:
            tty=s.get("tty")
            if not tty: continue
            try:
                disconnect_session(tty)
                audit("system","policy_disconnect",username,f"tty={tty}; limit={limit}")
            except OperationError as exc:
                audit("system","policy_disconnect_failed",username,str(exc)[:240])

def main():
    while True:
        try:
            enforce_once()
        except Exception as exc:
            audit("system","policy_enforcer_error",detail=str(exc)[:240])
        time.sleep(POLL_SECONDS)

if __name__=="__main__":
    main()
