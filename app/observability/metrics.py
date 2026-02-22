import json
from typing import List, Optional
from app.store.redis_conn import get_redis
from app.settings import settings

# Keys
KEY_FINALIZE_SUCCESS = "metrics:finalize:success"
KEY_FINALIZE_ATTEMPTS = "metrics:finalize:attempts"
KEY_FINALIZE_LATENCY = "metrics:finalize:latency:samples"

KEY_CALLBACK_DELIVERED = "metrics:callback:delivered"
KEY_CALLBACK_ATTEMPTS = "metrics:callback:attempts"
KEY_CALLBACK_LATENCY = "metrics:callback:latency:samples"

KEY_RECENT_FAILED_CALLBACKS = "metrics:callback:failed:recent"

MAX_SAMPLES = 1000
MAX_RECENT_FAILURES = 50

def _r():
    return get_redis()

def increment_finalize_success():
    try:
        _r().incr(KEY_FINALIZE_SUCCESS)
    except Exception:
        pass

def increment_finalize_attempt():
    try:
        _r().incr(KEY_FINALIZE_ATTEMPTS)
    except Exception:
        pass

def record_finalize_latency(ms: int):
    try:
        r = _r()
        r.lpush(KEY_FINALIZE_LATENCY, ms)
        r.ltrim(KEY_FINALIZE_LATENCY, 0, MAX_SAMPLES - 1)
    except Exception:
        pass

def increment_callback_delivered():
    try:
        _r().incr(KEY_CALLBACK_DELIVERED)
    except Exception:
        pass

def increment_callback_attempt():
    try:
        _r().incr(KEY_CALLBACK_ATTEMPTS)
    except Exception:
        pass

def record_callback_latency(ms: int):
    try:
        r = _r()
        r.lpush(KEY_CALLBACK_LATENCY, ms)
        r.ltrim(KEY_CALLBACK_LATENCY, 0, MAX_SAMPLES - 1)
    except Exception:
        pass

def record_failed_callback(session_id: str):
    try:
        r = _r()
        r.lpush(KEY_RECENT_FAILED_CALLBACKS, session_id)
        r.ltrim(KEY_RECENT_FAILED_CALLBACKS, 0, MAX_RECENT_FAILURES - 1)
    except Exception:
        pass

def get_slo_snapshot() -> dict:
    r = _r()
    
    def _get_int(k):
        v = r.get(k)
        return int(v) if v else 0

    def _get_samples(k):
        # Redis returns list of strings
        vals = r.lrange(k, 0, -1)
        return [int(v) for v in vals if v]

    def _percentile(vals: List[int], p: float) -> int:
        if not vals:
            return 0
        vals.sort()
        idx = int(len(vals) * p)
        return vals[min(idx, len(vals) - 1)]

    fin_succ = _get_int(KEY_FINALIZE_SUCCESS)
    fin_att = _get_int(KEY_FINALIZE_ATTEMPTS)
    fin_rate = (fin_succ / fin_att) if fin_att > 0 else 0.0

    fin_samples = _get_samples(KEY_FINALIZE_LATENCY)
    p50_fin = _percentile(fin_samples, 0.50)
    p95_fin = _percentile(fin_samples, 0.95)

    cb_del = _get_int(KEY_CALLBACK_DELIVERED)
    cb_att = _get_int(KEY_CALLBACK_ATTEMPTS)
    cb_rate = (cb_del / cb_att) if cb_att > 0 else 0.0

    cb_samples = _get_samples(KEY_CALLBACK_LATENCY)
    p95_cb = _percentile(cb_samples, 0.95)

    recent_failures = r.lrange(KEY_RECENT_FAILED_CALLBACKS, 0, -1) or []

    return {
        "finalize_success_rate": round(fin_rate, 2),
        "finalize_count": fin_succ, # Extra useful info
        "p50_finalize_latency": p50_fin,
        "p95_finalize_latency": p95_fin,
        "target_finalize_latency": settings.FINALIZE_MIN_TURNS * 10, # arbitrary baseline or from config
        "callback_delivery_success_rate": round(cb_rate, 2),
        "p95_callback_delivery_latency": p95_cb,
        "target_callback_latency": settings.CALLBACK_TIMEOUT_SEC * 1000,
        "recent_failed_callbacks": recent_failures,
        "sessions_waiting_for_report": [] # Expensive to compute, returning empty as permitted
    }
