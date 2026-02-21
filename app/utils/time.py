import time
from datetime import datetime, timezone

def now_ms() -> int:
    return int(time.time() * 1000)

def parse_timestamp_ms(ts) -> int:
    """
    Normalize timestamps to epoch milliseconds (int).
    Accepts:
    - int/float: treated as epoch ms (or seconds if suspiciously small)
    - ISO-8601 string: parsed via datetime.fromisoformat (supports trailing 'Z')
    Fallback: current time in ms.
    """
    try:
        if ts is None:
            return now_ms()
        if isinstance(ts, (int, float)):
            v = int(ts)
            # Heuristic: if looks like seconds (< 10^12), convert to ms.
            return v * 1000 if v > 0 and v < 10**12 else v
        if isinstance(ts, str):
            s = ts.strip()
            if not s:
                return now_ms()
            # Support Zulu time
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
    except Exception:
        pass
    return now_ms()

def compute_engagement_seconds(conversation: list[dict], first_seen_ms: int = 0, last_seen_ms: int = 0) -> int:
    """
    Compute engagement window from the first 'scammer' message timestamp
    to the last 'agent' message timestamp in the *persisted* session.conversation.
    Prefer wall-clock (first_seen_ms -> last_seen_ms) when available for robust scoring.
    Falls back to last-any-message if no agent message exists yet.
    Returns whole seconds (int), clamped to >= 0.
    """
    # 0) Prefer wall-clock if valid and increasing
    try:
        fs = int(first_seen_ms or 0)
        ls = int(last_seen_ms or 0)
        if fs > 0 and ls >= fs:
            dur_ms = max(0, ls - fs)
            sec = dur_ms // 1000
            # Ensure >0 when an interaction existed but ms delta rounds down to 0
            if sec == 0 and ls > fs:
                sec = 1
            return int(sec)
    except Exception:
        pass

    if not conversation:
        return 0
    # Defensive extraction
    scammer_ts = None
    last_agent_ts = None
    last_any_ts = None
    for item in conversation:
        ts = parse_timestamp_ms(item.get("timestamp"))
        sender = (item.get("sender") or "").lower()
        if sender == "scammer" and scammer_ts is None and ts > 0:
            scammer_ts = ts
        if sender == "agent" and ts > 0:
            # keep walking; we want the last agent timestamp
            last_agent_ts = ts
        if ts > 0:
            last_any_ts = ts
    if scammer_ts is None:
        return 0
    end_ts = last_agent_ts or last_any_ts or scammer_ts
    duration_ms = max(0, end_ts - scammer_ts)
    sec = duration_ms // 1000
    # If we have messages but timestamps collapse to same ms, ensure minimal non-zero engagement.
    if sec == 0 and len(conversation) > 1:
        sec = 1
    return int(sec)
