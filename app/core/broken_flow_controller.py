import hashlib
import json
import re
from typing import Dict, Any
from app.core.broken_flow_constants import *
from app.store.models import SessionState
from app.core.finalize import should_finalize


# ============================================================
# Utilities
# ============================================================

def compute_ioc_signature(intel_dict: Dict[str, Any]) -> str:
    """
    Stable signature of extracted IOCs to detect progress.
    """
    data = {
        "bankAccounts": sorted(intel_dict.get("bankAccounts", [])),
        "upiIds": sorted(intel_dict.get("upiIds", [])),
        "phishingLinks": sorted(intel_dict.get("phishingLinks", [])),
        "phoneNumbers": sorted(intel_dict.get("phoneNumbers", [])),
    }
    encoded = json.dumps(data, sort_keys=True).encode()
    return hashlib.md5(encoded).hexdigest()


def _pick_missing_intel_intent(intel_dict: Dict[str, Any]) -> str:
    """
    Implicit alternative-seeking priority.
    Never explicitly asks for sensitive data.
    """
    if not intel_dict.get("phoneNumbers"):
        return INT_ASK_OFFICIAL_HELPLINE

    if not intel_dict.get("phishingLinks"):
        return INT_ASK_OFFICIAL_WEBSITE

    kws = intel_dict.get("suspiciousKeywords", [])
    has_ticket = any(k in kws for k in ["ticket", "reference", "complaint"])
    has_branch = any(k in kws for k in ["branch", "department", "employee id"])

    if not has_ticket:
        return INT_ASK_TICKET_REF

    if not has_branch:
        return INT_ASK_DEPARTMENT_BRANCH

    return INT_ASK_TICKET_REF


def _pivot_intent(current_intent: str) -> str:
    """
    Forced pivot chain to break repetition loops.
    """
    pivots = {
        INT_ACK_CONCERN: INT_ASK_OFFICIAL_HELPLINE,
        INT_ASK_OFFICIAL_HELPLINE: INT_ASK_TICKET_REF,
        INT_ASK_OFFICIAL_WEBSITE: INT_ASK_DEPARTMENT_BRANCH,
        INT_ASK_TICKET_REF: INT_ASK_DEPARTMENT_BRANCH,
        INT_ASK_DEPARTMENT_BRANCH: INT_CLOSE_AND_VERIFY_SELF,
        INT_REFUSE_SENSITIVE_ONCE: INT_ASK_TICKET_REF,
        INT_ASK_ALT_VERIFICATION: INT_ASK_DEPARTMENT_BRANCH,
        INT_SECONDARY_FAIL: INT_CLOSE_AND_VERIFY_SELF,
    }
    return pivots.get(current_intent, INT_CLOSE_AND_VERIFY_SELF)


# ============================================================
# Controller
# ============================================================

def choose_next_action(
    session: SessionState,
    latest_text: str,
    intel_dict: Dict[str, Any],
    detection_dict: Dict[str, Any],
    settings: Any,
) -> Dict[str, Any]:
    """
    Deterministic broken-flow controller.
    - Controller owns ALL state transitions
    - Responder is intent-only
    """

    # --------------------------------------------------------
    # Session defaults (backward compatible)
    # --------------------------------------------------------
    session.bf_state = getattr(session, "bf_state", BF_S0)
    session.bf_last_intent = getattr(session, "bf_last_intent", None)
    session.bf_repeat_count = getattr(session, "bf_repeat_count", 0)
    session.bf_no_progress_count = getattr(session, "bf_no_progress_count", 0)
    session.bf_secondary_bounce_count = getattr(session, "bf_secondary_bounce_count", 0)
    session.bf_policy_refused_once = getattr(session, "bf_policy_refused_once", False)
    session.bf_recent_intents = getattr(session, "bf_recent_intents", [])
    session.bf_last_ioc_signature = getattr(session, "bf_last_ioc_signature", None)

    # --------------------------------------------------------
    # Progress detection (IOC-based)
    # --------------------------------------------------------
    new_signature = compute_ioc_signature(intel_dict)
    new_intel_received = False

    if session.bf_last_ioc_signature is None:
        session.bf_last_ioc_signature = new_signature
        if any(intel_dict.get(k) for k in ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers"]):
            new_intel_received = True
    elif new_signature != session.bf_last_ioc_signature:
        new_intel_received = True
        session.bf_no_progress_count = 0
        session.bf_last_ioc_signature = new_signature
    else:
        session.bf_no_progress_count += 1

    # --------------------------------------------------------
    # Sensitive request detection
    # --------------------------------------------------------
    sensitive_pattern = re.compile(r"\b(otp|pin|password|cvv|code)\b", re.I)
    asked_sensitive = bool(sensitive_pattern.search(latest_text))

    intent = None
    force_finalize = False
    reason = "normal_flow"

    # --------------------------------------------------------
    # Explicit policy refusal path (only once)
    # --------------------------------------------------------
    if asked_sensitive and not session.bf_policy_refused_once:
        session.bf_policy_refused_once = True
        session.bf_state = BF_S3
        intent = INT_REFUSE_SENSITIVE_ONCE
        reason = "policy_refusal"

    # --------------------------------------------------------
    # State progression driven by intelligence surfaces
    # --------------------------------------------------------
    if not intent and new_intel_received:
        if intel_dict.get("phishingLinks") and session.bf_state in (BF_S0, BF_S1):
            session.bf_state = BF_S2
        elif intel_dict.get("phoneNumbers") and session.bf_state in (BF_S0, BF_S1, BF_S2):
            session.bf_state = BF_S3
        elif (intel_dict.get("upiIds") or intel_dict.get("bankAccounts")):
            session.bf_state = BF_S4

    # --------------------------------------------------------
    # Progress-based advancement (broken loops)
    # --------------------------------------------------------
    if not intent:
        if session.bf_state == BF_S1:
            session.bf_state = BF_S2
        elif session.bf_state == BF_S2 and session.bf_no_progress_count >= settings.BF_NO_PROGRESS_TURNS:
            session.bf_state = BF_S3
        elif session.bf_state == BF_S3 and session.bf_no_progress_count >= settings.BF_NO_PROGRESS_TURNS:
            if session.bf_secondary_bounce_count < settings.BF_SECONDARY_BOUNCE_LIMIT:
                session.bf_state = BF_S4
                session.bf_secondary_bounce_count += 1
            else:
                session.bf_state = BF_S5
        elif session.bf_state == BF_S4 and session.bf_no_progress_count >= settings.BF_NO_PROGRESS_TURNS:
            session.bf_state = BF_S5

    # --------------------------------------------------------
    # Intent selection (FINAL state only)
    # --------------------------------------------------------
    if not intent:
        if session.bf_state == BF_S0:
            session.bf_state = BF_S1
            intent = INT_ACK_CONCERN
        elif session.bf_state == BF_S1:
            intent = INT_ACK_CONCERN
        elif session.bf_state == BF_S2:
            intent = _pick_missing_intel_intent(intel_dict)
        elif session.bf_state == BF_S3:
            intent = INT_ASK_ALT_VERIFICATION
        elif session.bf_state == BF_S4:
            intent = _pick_missing_intel_intent(intel_dict)
        elif session.bf_state == BF_S5:
            intent = INT_CLOSE_AND_VERIFY_SELF
            force_finalize = True
        else:
            intent = INT_CLOSE_AND_VERIFY_SELF
            force_finalize = True

    # --------------------------------------------------------
    # Close gating (never close without sufficient intel)
    # --------------------------------------------------------
    if intent == INT_CLOSE_AND_VERIFY_SELF:
        if not should_finalize(session):
            intent = _pick_missing_intel_intent(intel_dict)
            force_finalize = False
            reason = "close_gated_pivot"

    # --------------------------------------------------------
    # Repetition breaker
    # --------------------------------------------------------
    if intent == session.bf_last_intent:
        session.bf_repeat_count += 1
    else:
        session.bf_repeat_count = 0

    if session.bf_repeat_count >= settings.BF_REPEAT_LIMIT:
        intent = _pivot_intent(intent)
        session.bf_repeat_count = 0
        reason = "repetition_pivot"

    session.bf_last_intent = intent
    session.bf_recent_intents.append(intent)
    if len(session.bf_recent_intents) > 10:
        session.bf_recent_intents.pop(0)

    return {
        "bf_state": session.bf_state,
        "intent": intent,
        "reason": reason,
        "force_finalize": force_finalize,
    }