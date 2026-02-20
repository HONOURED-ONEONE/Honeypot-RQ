import time

def now_ms() -> int:
    return int(time.time() * 1000)

def compute_engagement_seconds(conversation: list[dict]) -> int:
    """
    Compute engagement window from the first 'scammer' message timestamp
    to the last 'agent' message timestamp in the *persisted* session.conversation.
    Falls back to last-any-message if no agent message exists yet.
    Returns whole seconds (int), clamped to >= 0.
    """
    if not conversation:
        return 0
    # Defensive extraction
    scammer_ts = None
    last_agent_ts = None
    last_any_ts = None
    for item in conversation:
        ts = int(item.get("timestamp") or 0)
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
    return duration_ms // 1000
