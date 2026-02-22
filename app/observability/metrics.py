"""
Observability Metrics & SLO Snapshot
------------------------------------
This module provides lightweight counters/timers and a single SLO snapshot
function consumed by /admin/slo. It is intentionally defensive: if certain
keys are missing in Redis (first boot), it returns sane defaults while still
exposing the required fields for dashboards/guards.
"""
from __future__ import annotations
import json
import time
from typing import List, Tuple
from statistics import median
from app.store.redis_conn import get_redis
from app.settings import settings

# Keys (best-effort, stable across restarts)
K_FIN_LAT = "metrics:finalize:latencies"          # LPUSH ms
K_FIN_SUCC = "metrics:finalize:success"           # INCR
K_FIN_ATT  = "metrics:finalize:attempt"           # INCR (optional if you count attempts)

K_CB_LAT   = "metrics:callback:latencies"         # LPUSH ms
K_CB_ATT   = "metrics:callback:attempts"          # INCR
K_CB_OK    = "metrics:callback:delivered"         # INCR
K_CB_FAIL_RECENT = "metrics:callback:failed_recent"  # LPUSH sessionId (trim window)

# Optional: sessions waiting (producer can maintain this; if absent we return [])
K_SESS_WAIT = "metrics:sessions:waiting_for_report"   # SMEMBERS

_DEFAULT_WINDOW_SECONDS = 15 * 60
_MAX_SAMPLES = 500  # cap to bound percentile computation cost

def _clip_list(vals: List[int], n: int = _MAX_SAMPLES) -> List[int]:
    return vals[:n] if len(vals) > n else vals

def _percentile(data: List[float], p: float) -> float:
    """Deterministic percentile (nearest-rank on sorted data)."""
    if not data:
        return 0.0
    d = sorted(data)
    k = max(1, int(round(p * len(d))))
    return float(d[k - 1])

def _now_s() -> int:
    return int(time.time())

# Public counters/timers (already referenced by the app; re-define idempotently)
def increment_finalize_success() -> None:
    r = get_redis()
    r.incr(K_FIN_SUCC, 1)

def increment_finalize_attempt() -> None:
    r = get_redis()
    r.incr(K_FIN_ATT, 1)

def record_finalize_latency(ms: int) -> None:
    try:
        ms = int(ms)
    except Exception:
        return
    r = get_redis()
    r.lpush(K_FIN_LAT, ms)
    r.ltrim(K_FIN_LAT, 0, _MAX_SAMPLES - 1)

def increment_callback_attempt() -> None:
    r = get_redis()
    r.incr(K_CB_ATT, 1)

def increment_callback_delivered() -> None:
    r = get_redis()
    r.incr(K_CB_OK, 1)

def record_callback_latency(ms: int) -> None:
    try:
        ms = int(ms)
    except Exception:
        return
    r = get_redis()
    r.lpush(K_CB_LAT, ms)
    r.ltrim(K_CB_LAT, 0, _MAX_SAMPLES - 1)

def record_failed_callback(session_id: str) -> None:
    """Track recent failures for incident attachments."""
    if not session_id:
        return
    r = get_redis()
    r.lpush(K_CB_FAIL_RECENT, session_id)
    r.ltrim(K_CB_FAIL_RECENT, 0, 49)  # keep last 50

def _read_latency_list(key: str) -> List[float]:
    r = get_redis()
    raw = r.lrange(key, 0, _MAX_SAMPLES - 1) or []
    out: List[float] = []
    for x in raw:
        try:
            v = float(x if isinstance(x, (int, float)) else (x.decode("utf-8") if isinstance(x, (bytes, bytearray)) else str(x)))
            out.append(v / 1000.0)  # seconds
        except Exception:
            continue
    return out

def _p50_p95(latencies_s: List[float]) -> Tuple[float, float]:
    if not latencies_s:
        return 0.0, 0.0
    return _percentile(latencies_s, 0.50), _percentile(latencies_s, 0.95)

def _safe_float_env(name: str, default: float) -> float:
    try:
        return float(getattr(settings, name, default) or default)
    except Exception:
        return float(default)

def _safe_int_env(name: str, default: int) -> int:
    try:
        return int(getattr(settings, name, default) or default)
    except Exception:
        return int(default)

def get_slo_snapshot() -> dict:
    """
    Return a dict shaped for /admin/slo consumers (SRE/Turbotic guards).
    Rolling window is approximated by most recent samples (LPUSH+LTRIM).
    Fields:
      - finalize_success_rate, p50_finalize_latency, p95_finalize_latency, target_finalize_latency
      - callback_delivery_success_rate, p95_callback_delivery_latency, target_callback_latency
      - sessions_waiting_for_report (optional)
      - recent_failed_callbacks (optional)
    """
    r = get_redis()

    # Finalize latency percentiles (seconds)
    fin_lat_s = _read_latency_list(K_FIN_LAT)
    p50_fin, p95_fin = _p50_p95(fin_lat_s)

    # Finalize success rate: successes / attempts (fallback to successes / max(1, successes))
    fin_succ = int(r.get(K_FIN_SUCC) or 0)
    fin_att  = int(r.get(K_FIN_ATT) or 0)
    fin_denom = fin_att if fin_att > 0 else max(1, fin_succ)
    finalize_success_rate = (fin_succ / fin_denom) * 100.0 if fin_denom else 0.0

    # Callback success rate: delivered / attempts
    cb_ok  = int(r.get(K_CB_OK) or 0)
    cb_att = int(r.get(K_CB_ATT) or 0)
    cb_rate = (cb_ok / cb_att) * 100.0 if cb_att > 0 else (100.0 if cb_ok > 0 else 0.0)

    # Callback latency p95 (seconds)
    cb_lat_s = _read_latency_list(K_CB_LAT)
    _, p95_cb = _p50_p95(cb_lat_s)

    # Targets
    target_fin = _safe_float_env("TARGET_FINALIZE_P95_SEC", 5.0)
    target_cb  = _safe_float_env("TARGET_CALLBACK_P95_SEC", 3.0)

    # Optional lists
    try:
        waiting = list(set([x.decode("utf-8") if isinstance(x, (bytes, bytearray)) else str(x)
                            for x in (r.smembers(K_SESS_WAIT) or [])]))
    except Exception:
        waiting = []

    try:
        recent_failed = [x.decode("utf-8") if isinstance(x, (bytes, bytearray)) else str(x)
                         for x in (r.lrange(K_CB_FAIL_RECENT, 0, 19) or [])]
    except Exception:
        recent_failed = []

    return {
        "finalize_success_rate": round(finalize_success_rate, 3),
        "p50_finalize_latency": round(p50_fin, 3),
        "p95_finalize_latency": round(p95_fin, 3),
        "target_finalize_latency": float(target_fin),
        "callback_delivery_success_rate": round(cb_rate, 3),
        "p95_callback_delivery_latency": round(p95_cb, 3),
        "target_callback_latency": float(target_cb),
        "sessions_waiting_for_report": waiting,
        "recent_failed_callbacks": recent_failed,
        "window_seconds": _safe_int_env("SLO_WINDOW_SECONDS", _DEFAULT_WINDOW_SECONDS),
        "snapshot_at": _now_s(),
    }
