import json
import time


def log(event: str, **fields):
    payload = {"ts": int(time.time()), "event": event, **fields}
    print(json.dumps(payload, ensure_ascii=False))
