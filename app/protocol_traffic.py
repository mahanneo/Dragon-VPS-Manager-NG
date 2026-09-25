import time
from .db import list_protocol_clients, add_protocol_traffic, set_protocol_client_enabled, audit
from . import protocol_ops

POLL_SECONDS=30

def collect_once():
    now=int(time.time())
    for client in list_protocol_clients():
        if not int(client.get("enabled",1)):
            continue
        if client.get("engine")!="xray" or client.get("protocol") not in {"vless","vmess","trojan"}:
            continue
        try:
            stats=protocol_ops.xray_client_traffic(client["name"],reset=True)
        except Exception as exc:
            audit("system","traffic_collect_failed",client.get("name"),str(exc)[:240])
            continue
        if stats.get("available"):
            add_protocol_traffic(client["id"],stats.get("uplink",0),stats.get("downlink",0))
            total=int(client.get("used_up_bytes") or 0)+int(client.get("used_down_bytes") or 0)+int(stats.get("total") or 0)
            quota=int(client.get("quota_bytes") or 0)
            expire_at=int(client.get("expire_at") or 0)
            reason=None
            if quota and total>=quota:
                reason=f"quota exhausted: {total}/{quota}"
            elif expire_at and now>=expire_at:
                reason=f"expired at {expire_at}"
            if reason:
                try:
                    result=protocol_ops.disable_xray_client(client["inbound_tag"],client["name"])
                    set_protocol_client_enabled(client["id"],False)
                    audit("system","protocol_client_auto_disable",client["name"],reason+"; "+str(result)[:180])
                except Exception as exc:
                    audit("system","protocol_client_auto_disable_failed",client["name"],str(exc)[:240])

def main():
    while True:
        try:
            collect_once()
        except Exception as exc:
            audit("system","traffic_collector_error",detail=str(exc)[:240])
        time.sleep(POLL_SECONDS)

if __name__=="__main__":
    main()
