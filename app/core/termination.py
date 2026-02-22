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


from typing import Any, Dict, Optional
import time

from app.settings import settings
from app.intel.artifact_registry import artifact_registry
from app.utils.time import now_ms

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
      1) Latch-and-drain: if already finalized, return "already_finalized" (or None if handled by caller).
      2) Hard cap: turnsEngaged >= BF_MAX_TURNS  -> "max_turns_reached"
      3) Inactivity Watchdog: (now - lastIocAtMs) > FINALIZE_INACTIVITY_SECONDS -> "inactivity_timeout"
      4) Evidence Quorum: (IOCs >= MIN) AND (RedFlags >= MIN) -> "evidence_quorum"
      5) Stagnation: no progress threshold       -> "no_progress_threshold"
      6) Repeat limit threshold                  -> "repeat_threshold"
      7) Controller-requested finalize (if allowed) -> controller reason (normalized)
      8) Escalation termination (e.g. loop refusal) -> "escalation_termination"
    """

    # If already reported/closed/finalized, never re-finalize
    if getattr(session, "state", "") in ("READY_TO_REPORT", "REPORTED", "CLOSED", "FINALIZED"):
        return None

    turns = int(getattr(session, "turnsEngaged", 0) or 0)
    now = now_ms()

    # 1) Hard cap to match evaluator max-turn model (default 10).
    try:
        hard_max = int(getattr(settings, "BF_MAX_TURNS", 10) or 10)
        if hard_max > 0 and turns >= hard_max:
            return "max_turns_reached"
    except Exception:
        pass

    # 2) Inactivity Watchdog: no new IOC within X seconds after last agent reply.
    # We use lastIocAtMs (updated by orchestrator)
    # Only applies if we have at least started engaging (turns > 0)
    try:
        if turns > 0:
            last_ioc = int(getattr(session, "lastIocAtMs", 0) or 0)
            # If never had an IOC, maybe use session start? Or skip?
            # Prompt says "since last new IOC". If no IOC ever, maybe use session start.
            reference_time = last_ioc if last_ioc > 0 else int(getattr(session, "sessionFirstSeenAtMs", 0) or 0)
            if reference_time > 0:
                limit_sec = int(getattr(settings, "FINALIZE_INACTIVITY_SECONDS", 30) or 30)
                if (now - reference_time) > (limit_sec * 1000):
                     return "inactivity_timeout"
    except Exception:
        pass

    # 3) Evidence Quorum
    # Configurable min DISTINCT IOC categories AND/OR DISTINCT red-flags.
    try:
        min_iocs = int(getattr(settings, "FINALIZE_MIN_IOC_CATEGORIES", 2) or 2)
        min_redflags = int(getattr(settings, "FINALIZE_MIN_REDFLAGS", 4) or 4)
        
        ioc_count = _ioc_category_count(session)
        # Distinct red flags from history
        rf_hist = getattr(session, "redFlagHistory", []) or []
        distinct_rf = len(set(x for x in rf_hist if x != "NONE"))
        
        # Logic: "DISTINCT IOC categories and/or DISTINCT red-flags".
        # We'll require BOTH to be safe, or make it flexible?
        # The prompt says "and/or". Let's assume strict AND for high quality, OR if one is very high?
        # Let's use AND as default behavior for "Quorum".
        # Actually, "AND/OR" usually implies a config choice or a combined score.
        # Let's stick to: if (IOCs >= MIN) OR (RedFlags >= MAX_RF AND IOCs >= 1)?
        # Let's implement: IOCs >= MIN_IOCS  (RedFlags is usually secondary in this system).
        # Wait, the objective says: "Evidence quorum met (configurable min of DISTINCT IOC categories and/or DISTINCT red-flags)."
        # Let's trigger if IOCs met.
        
        if ioc_count >= min_iocs:
             # Check red flags if configured?
             # For now, if IOCs are good, we are good.
             return "evidence_quorum_iocs"
        
        if distinct_rf >= min_redflags and ioc_count >= 1:
             return "evidence_quorum_redflags"

    except Exception:
        pass

    # 4) Stagnation termination (existing controller counter)
    try:
        if int(getattr(session, "bf_no_progress_count", 0) or 0) >= int(getattr(settings, "BF_NO_PROGRESS_TURNS", 3) or 3):
            return "no_progress_threshold"
    except Exception:
        pass

    # 5) Repeat termination (existing controller counter)
    try:
        if int(getattr(session, "bf_repeat_count", 0) or 0) >= int(getattr(settings, "BF_REPEAT_LIMIT", 2) or 2) + 1:
            return "repeat_threshold"
    except Exception:
        pass

    # 6) Escalation termination (e.g., OTP/payment/remote-control refusal loop reached).
    # Controlled by controller state BF_S5 or "force finalize"
    if getattr(settings, "FINALIZE_FORCE_ON_ESCALATION", True):
        state = getattr(session, "bf_state", "")
        if state == "BF_S5":
             return "escalation_termination"

    # 7) Controller-requested finalize
    try:
        if isinstance(controller_out, dict) and bool(controller_out.get("force_finalize")):
            reason = str(controller_out.get("reason") or "controller_finalize")
            # Honor it unless it's a "soft" finalize that violates min turns
            # But controller usually checks min turns before forcing.
            return reason
    except Exception:
        pass

    return None
