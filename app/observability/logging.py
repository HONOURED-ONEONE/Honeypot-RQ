import json
import time
from app.settings import settings

# Simple redaction patterns for logs (if PII redaction enabled)
SENSITIVE_KEYS = {"text", "message", "reply", "payload", "content"}

def _redact_value(v):
    if isinstance(v, str) and len(v) > 0:
        return f"[REDACTED:{len(v)}chars]"
    if isinstance(v, dict):
        return {k: _redact_value(val) for k, val in v.items()}
    return v

def log(event: str, **fields):
    payload = {"ts": int(time.time()), "event": event}
    
    if settings.ENABLE_PII_REDACTION:
        # Redact sensitive fields
        clean_fields = {}
        for k, v in fields.items():
            if k in SENSITIVE_KEYS:
                clean_fields[k] = _redact_value(v)
            elif isinstance(v, dict):
                # Recursive redaction for nested objects like 'payload'
                # If key is sensitive, redact whole value; else redact nested sensitive keys
                if k in SENSITIVE_KEYS:
                    clean_fields[k] = _redact_value(v)
                else:
                    clean_fields[k] = {sk: (_redact_value(sv) if sk in SENSITIVE_KEYS else sv) for sk, sv in v.items()}
            else:
                clean_fields[k] = v
        payload.update(clean_fields)
    else:
        payload.update(fields)

    print(json.dumps(payload, ensure_ascii=False))
