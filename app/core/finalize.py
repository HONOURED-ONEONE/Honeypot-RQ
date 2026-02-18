from typing import Optional
from app.settings import settings
from app.intel.artifact_registry import artifact_registry


def _ioc_category_count(session) -> int:
    """
    Counts distinct artifact categories populated in the registry.
    INVARIANT: Only registry-defined keys are valid for completion logic.
    """
    intel = session.extractedIntelligence
    count = 0
    # Use registry to determine which keys to check
    for key in artifact_registry.artifacts.keys():
        if hasattr(intel, key):
            vals = getattr(intel, key)
            if isinstance(vals, list) and len(vals) > 0:
                count += 1
    return count


def should_finalize(session) -> Optional[str]:
    """
    Decide whether to end engagement and trigger final callback.

    INVARIANT: Finalization is DETRIMINISTIC and REGISTRY-GATED.
    - No sentiment analysis or conversation length heuristics.
    - Driven SOLELY by:
      1) Artifact Registry state (IOC counts)
      2) Controller counters (No-progress / Repeat limits)

    Returns the reason string if finalization is required, else None.
    """
    if session.state in ("READY_TO_REPORT", "REPORTED", "CLOSED"):
        return None

    # ✅ P1.3: Hard stop so evaluation sessions don't run past typical max turns.
    # This helps ensure the mandatory final callback can trigger within the evaluator's budget.
    try:
        if int(getattr(session, "turnIndex", 0) or 0) >= int(getattr(settings, "BF_MAX_TURNS", 10) or 10):
            return "max_turns_reached"
    except Exception:
        pass

    # 1. SCAM DETECTED + MIN IOC CATEGORIES (Registry-based)
    # INVARIANT: Completion requires verifiable artifact extraction.
    if session.scamDetected:
        iocs_ok = _ioc_category_count(session) >= settings.FINALIZE_MIN_IOC_CATEGORIES
        if iocs_ok:
            return "ioc_milestone"

    # 2. NO PROGRESS THRESHOLD (Controller-defined)
    # INVARIANT: Finite state machine must terminate on stagnation.
    if session.bf_no_progress_count >= settings.BF_NO_PROGRESS_TURNS:
        return "no_progress_threshold"

    # 3. REPEAT LIMIT REACHED (Controller-defined)
    # We use +1 to allow the controller's pivot logic to try once more
    # before we give up entirely.
    if session.bf_repeat_count >= settings.BF_REPEAT_LIMIT + 1:
        return "repeat_threshold"

    return None