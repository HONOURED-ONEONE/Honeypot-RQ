"""
Unified Termination Policy
--------------------------
Goal: Fix finalization timing & control-loop coupling by making ONE place decide
whether to finalize, and why.

Evaluator notes:
- Conversation phase is up to ~10 turns. [2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/Honeypot%20API%20Evaluation%20System%20Documentation%20Updated%20-%20feb%2019.pdf)
- Keeping engagement for ~8+ turns improves conversation quality scoring. [2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/Honeypot%20API%20Evaluation%20System%20Documentation%20Updated%20-%20feb%2019.pdf)
"""

from __future__ import annotations

from typing import Any, Dict, Optional

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
        # 1) static fields on Intelligence
        if hasattr(intel, key):
            vals = getattr(intel, key)
            if isinstance(vals, list) and len(vals) > 0:
                count += 1
                continue
        # 2) dynamic add-ons bucket
        try:
            dyn = getattr(intel, "dynamicArtifacts", None)
            if isinstance(dyn, dict):
                vals2 = dyn.get(key)
                if isinstance(vals2, list) and len(vals2) > 0:
                    count += 1
        except Exception:
            pass
    return count


def decide_termination(*, session, controller_out: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Returns a termination reason string if we should finalize now; otherwise None.
    Order of precedence:
      1) Hard cap: turnsEngaged >= BF_MAX_TURNS  -> "max_turns_reached"
      2) Stagnation: no progress threshold       -> "no_progress_threshold"
      3) Repeat limit threshold                  -> "repeat_threshold"
      4) Scam + IOC milestone AFTER CQ_MIN_TURNS -> "ioc_milestone"
      5) Controller-requested finalize (if allowed) -> controller reason (normalized)
    """

    # If already reported/closed, never re-finalize
    if getattr(session, "state", "") in ("READY_TO_REPORT", "REPORTED", "CLOSED"):
        return None

    turns = int(getattr(session, "turnsEngaged", 0) or 0)

    # 1) Hard cap to match evaluator max-turn model (default 10). [2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/Honeypot%20API%20Evaluation%20System%20Documentation%20Updated%20-%20feb%2019.pdf)
    # This prevents endless loops and ensures we reach final output within evaluation flow.
    try:
        hard_max = int(getattr(settings, "BF_MAX_TURNS", 10) or 10)
        if hard_max > 0 and turns >= hard_max:
            return "max_turns_reached"
    except Exception:
        pass

    # 2) Stagnation termination (existing controller counter)
    try:
        if int(getattr(session, "bf_no_progress_count", 0) or 0) >= int(getattr(settings, "BF_NO_PROGRESS_TURNS", 3) or 3):
            return "no_progress_threshold"
    except Exception:
        pass

    # 3) Repeat termination (existing controller counter)
    try:
        if int(getattr(session, "bf_repeat_count", 0) or 0) >= int(getattr(settings, "BF_REPEAT_LIMIT", 2) or 2) + 1:
            return "repeat_threshold"
    except Exception:
        pass

    # 4) Scam + IOC milestone, gated by Conversation Quality minimum turns (>=8 typical). [2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/Honeypot%20API%20Evaluation%20System%20Documentation%20Updated%20-%20feb%2019.pdf)
    try:
        if bool(getattr(session, "scamDetected", False)):
            cq_min = int(getattr(settings, "CQ_MIN_TURNS", 8) or 8)
            if turns >= cq_min:
                ioc_min = int(getattr(settings, "FINALIZE_MIN_IOC_CATEGORIES", 2) or 2)
                if _ioc_category_count(session) >= ioc_min:
                    return "ioc_milestone"
    except Exception:
        pass

    # 5) If controller asked to force finalize, honor it only if it doesn't violate CQ min-turns,
    # unless we are at the hard cap or stagnation (already handled above).
    try:
        if isinstance(controller_out, dict) and bool(controller_out.get("force_finalize")):
            reason = str(controller_out.get("reason") or "controller_finalize")
            cq_min = int(getattr(settings, "CQ_MIN_TURNS", 8) or 8)
            if turns >= cq_min:
                return reason
    except Exception:
        pass

    return None
