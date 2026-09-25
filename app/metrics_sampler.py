import time
from .db import add_metric, audit
from .system_ops import metrics

POLL_SECONDS=60

def sample_once():
    m=metrics()
    add_metric(
        int(time.time()),
        m["cpu"],m["memory"],m["disk"],
        (m.get("load") or [0])[0],
        m["network"]["recv"],m["network"]["sent"]
    )

def main():
    while True:
        try:
            sample_once()
        except Exception as exc:
            audit("system","metrics_sampler_error",detail=str(exc)[:240])
        time.sleep(POLL_SECONDS)

if __name__=="__main__":
    main()
