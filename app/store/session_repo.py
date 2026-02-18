import json
import time
import inspect
from dataclasses import fields as dc_fields
from app.store.redis_conn import get_redis
from app.store.models import SessionState, Intelligence
from app.observability.logging import log  # ✅ P1.2d: migration observability

PREFIX = "session:"

def _migrate_session_data(data: dict) -> dict:
    """
    Backward-compat migration for stored sessions.
    Ensures `turnIndex` exists and is an int, and keeps `totalMessagesExchanged` synced.
    """
    # ✅ P1.2d: Accumulators for structured migration logging
    did_backfill_scam_type = False
    did_drop_legacy_scam_type = False
    removed_top_fields = 0
    removed_intel_fields = 0

    # ✅ P1.2: Harmonize scam type fields from legacy records
    # - Canonical field is 'scamType' (persisted in SessionState)
    # - Older sessions may have stored only 'scam_type' (alias used by controller)
    #   In that case, backfill 'scamType' so downstream logic has a consistent value.
    if "scamType" not in data or data.get("scamType") is None:
        alias_val = data.get("scam_type")
        if alias_val is not None:
            data["scamType"] = alias_val
            did_backfill_scam_type = True

    # ✅ P1.2b: Drop legacy alias fields after backfill to keep schema clean.
    # Only remove keys that are not part of SessionState to avoid leaking unknowns.
    # ('scam_type' is not a declared dataclass field in SessionState.)
    if "scam_type" in data:
        try:
            del data["scam_type"]
            did_drop_legacy_scam_type = True
        except Exception:
            # Defensive: ignore if deletion fails for any reason
            pass

    # ✅ P1.2c: Purge any other undeclared legacy fields (top-level and nested intelligence)
    # 1) Top-level allowlist: only keep fields that are defined on SessionState
    try:
        allowed_top = {f.name for f in dc_fields(SessionState)}
        for k in list(data.keys()):
            if k not in allowed_top:
                # Keep only canonical fields to avoid persisting stale debug/legacy keys
                try:
                    del data[k]
                    removed_top_fields += 1
                except Exception:
                    pass
    except Exception:
        # Do not fail migration if dataclass inspection fails
        pass

    # 2) Nested allowlist for extractedIntelligence (dict form prior to rehydration)
    try:
        ei = data.get("extractedIntelligence")
        if isinstance(ei, dict):
            allowed_ei = {f.name for f in dc_fields(Intelligence)}
            for k in list(ei.keys()):
                if k not in allowed_ei:
                    try:
                        del ei[k]
                        removed_intel_fields += 1
                    except Exception:
                        pass
    except Exception:
        pass
    # If stored sessions used only totalMessagesExchanged, backfill turnIndex
    if "turnIndex" not in data or data.get("turnIndex") is None:
        legacy = data.get("totalMessagesExchanged") or 0
        convo = data.get("conversation") or []
        inferred = len(convo) if isinstance(convo, list) else 0
        data["turnIndex"] = int(legacy or inferred or 0)

    # Sync legacy field too
    data["totalMessagesExchanged"] = int(data.get("turnIndex") or 0)

    # ✅ P1.2d: Emit a compact migration log line for observability
    # (Non-influential: wrapped in try to avoid impacting load path)
    try:
        log(
            event="session_migrated",
            scamType=data.get("scamType") or "",
            backfilledScamType=bool(did_backfill_scam_type),
            droppedLegacyScamType=bool(did_drop_legacy_scam_type),
            removedTopFields=int(removed_top_fields),
            removedIntelFields=int(removed_intel_fields),
            turnIndex=int(data.get("turnIndex") or 0),
            totalMessagesExchanged=int(data.get("totalMessagesExchanged") or 0),
        )
    except Exception:
        pass
    return data

def _key(session_id: str) -> str:
    return f"{PREFIX}{session_id}"


def _json_safe(obj):
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    return obj


def _rehydrate_sets(data: dict) -> dict:
    """
    Rehydrate known set-backed state machine fields
    """
    SET_FIELDS = {
        "bf_satisfied_intents",
        "bf_seen_intents",
        "bf_seen_states",
    }

    for field in SET_FIELDS:
        if field in data and isinstance(data[field], list):
            data[field] = set(data[field])

    return data


def _filter_session_kwargs(data: dict) -> dict:
    """
    Drop unknown fields so SessionState(**kwargs) never explodes
    """
    sig = inspect.signature(SessionState)
    allowed = set(sig.parameters.keys())
    return {k: v for k, v in data.items() if k in allowed}


def load_session(session_id: str) -> SessionState:
    r = get_redis()
    raw = r.get(_key(session_id))
    if not raw:
        s = SessionState(sessionId=session_id)
        s.lastUpdatedAtEpoch = int(time.time())
        return s

    data = json.loads(raw)

    # ✅ Migration step (permanent fix for old sessions)
    data = _migrate_session_data(data)

    # Rehydrate intelligence
    intel = Intelligence(**data.get("extractedIntelligence", {}))
    data["extractedIntelligence"] = intel

    # Rehydrate sets
    data = _rehydrate_sets(data)

    # Drop unknown fields
    data = _filter_session_kwargs(data)

    return SessionState(**data)

def save_session(session: SessionState) -> None:
    r = get_redis()
    session.lastUpdatedAtEpoch = int(time.time())

    # ✅ keep legacy field synced for older readers/tools
    session.totalMessagesExchanged = int(getattr(session, "turnIndex", 0) or 0)

    data = session.__dict__.copy()
    data["extractedIntelligence"] = session.extractedIntelligence.__dict__
    safe_data = _json_safe(data)
    r.set(_key(session.sessionId), json.dumps(safe_data))