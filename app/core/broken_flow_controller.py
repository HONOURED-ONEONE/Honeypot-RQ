import hashlib
import json
import re
from typing import Dict, Any, List, Optional
from app.core.broken_flow_constants import *
from app.store.models import SessionState

def compute_ioc_signature(intel_dict: Dict[str, Any]) -> str:
    """Compute a signature for the current intelligence to detect changes."""
    data = {
        "bankAccounts": sorted(intel_dict.get("bankAccounts", [])),
        "upiIds": sorted(intel_dict.get("upiIds", [])),
        "phishingLinks": sorted(intel_dict.get("phishingLinks", [])),
        "phoneNumbers": sorted(intel_dict.get("phoneNumbers", [])),
    }
    encoded = json.dumps(data, sort_keys=True).encode()
    return hashlib.md5(encoded).hexdigest()

def choose_next_action(session: SessionState, latest_text: str, intel_dict: Dict[str, Any], detection_dict: Dict[str, Any], settings: Any) -> Dict[str, Any]:
    """
    Deterministic Broken-Flow Controller.
    Decides the next intent and state based on session history and current intelligence.
    """
    # Fix 2: Detect new intel
    new_signature = compute_ioc_signature(intel_dict)
    new_intel_received = False
    if not session.bf_last_ioc_signature:
        session.bf_last_ioc_signature = new_signature
    elif new_signature != session.bf_last_ioc_signature:
        new_intel_received = True
        session.bf_no_progress_count = 0
        session.bf_last_ioc_signature = new_signature
    else:
        session.bf_no_progress_count += 1

    # Detect sensitive requests from scammer (OTP/PIN/etc.)
    sensitive_pattern = re.compile(r"\b(otp|pin|password|cvv|code)\b", re.IGNORECASE)
    asked_sensitive = bool(sensitive_pattern.search(latest_text))

    force_finalize = False
    reason = "normal_flow"
    intent = None
    
    # --- State Progression Logic ---
    
    if asked_sensitive:
        if not session.bf_policy_refused_once:
            session.bf_policy_refused_once = True
            session.bf_state = BF_S3
            intent = INT_REFUSE_SENSITIVE_ONCE
            reason = "policy_refusal"
        else:
            # Already refused once. Advance to NEXT broken-flow surface.
            if session.bf_state in (BF_S0, BF_S1, BF_S2, BF_S3):
                session.bf_state = BF_S4
            reason = "otp_loop_exit"

    elif new_intel_received:
        # Advance state on new intel
        if session.bf_state == BF_S1:
            session.bf_state = BF_S2
        elif session.bf_state == BF_S2:
            session.bf_state = BF_S3
        elif session.bf_state == BF_S3:
            session.bf_state = BF_S4
    
    # Progress-based advancement
    if not intent:
        if session.bf_state == BF_S1:
            session.bf_state = BF_S2
        elif session.bf_state == BF_S2 and session.bf_no_progress_count >= getattr(settings, "BF_NO_PROGRESS_TURNS", 2):
            session.bf_state = BF_S3
        elif session.bf_state == BF_S3 and session.bf_no_progress_count >= getattr(settings, "BF_NO_PROGRESS_TURNS", 2):
            if session.bf_secondary_bounce_count < getattr(settings, "BF_SECONDARY_BOUNCE_LIMIT", 1):
                session.bf_state = BF_S4
                session.bf_secondary_bounce_count += 1
            else:
                session.bf_state = BF_S5
        elif session.bf_state == BF_S4 and session.bf_no_progress_count >= getattr(settings, "BF_NO_PROGRESS_TURNS", 2):
            session.bf_state = BF_S5

    # --- Intent Selection Logic (based on FINAL state for this turn) ---
    
    if not intent:
        # Important: check state in order of progression
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
            if new_intel_received:
                intent = INT_SECONDARY_FAIL
            else:
                intent = _pick_missing_intel_intent(intel_dict)
        elif session.bf_state == BF_S5:
            intent = INT_CLOSE_AND_VERIFY_SELF
            force_finalize = True
        else:
            intent = INT_CLOSE_AND_VERIFY_SELF
            force_finalize = True

    # Refinement 1: Intent repetition breaker
    if intent == session.bf_last_intent:
        session.bf_repeat_count += 1
    else:
        session.bf_repeat_count = 0
    
    if session.bf_repeat_count >= getattr(settings, "BF_REPEAT_LIMIT", 1):
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
        "force_finalize": force_finalize
    }

def _pick_missing_intel_intent(intel_dict: Dict[str, Any]) -> str:
    """Prioritize intent based on missing IOC categories."""
    # Priority: phone -> website -> ticket -> branch
    if not intel_dict.get("phoneNumbers"):
        return INT_ASK_OFFICIAL_HELPLINE
    if not intel_dict.get("phishingLinks"):
        return INT_ASK_OFFICIAL_WEBSITE
    
    # Check suspiciousKeywords for ticket/branch mentions
    kws = intel_dict.get("suspiciousKeywords", [])
    has_ticket = any(k in kws for k in ["ticket", "reference", "complaint"])
    has_branch = any(k in kws for k in ["branch", "department", "employee id"])

    if not has_ticket:
        return INT_ASK_TICKET_REF
    if not has_branch:
        return INT_ASK_DEPARTMENT_BRANCH
        
    return INT_ASK_TICKET_REF

def _pivot_intent(current_intent: str) -> str:
    """Forced pivot chain to avoid repetition loops."""
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
