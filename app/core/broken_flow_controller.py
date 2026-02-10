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
    # Refinement 4: No-progress forcing (using signature)
    new_signature = compute_ioc_signature(intel_dict)
    if new_signature == session.bf_last_ioc_signature:
        session.bf_no_progress_count += 1
    else:
        session.bf_no_progress_count = 0
        session.bf_last_ioc_signature = new_signature

    # Detect sensitive requests from scammer (OTP/PIN/etc.)
    sensitive_pattern = re.compile(r"\b(otp|pin|password|cvv|code)\b", re.IGNORECASE)
    asked_sensitive = bool(sensitive_pattern.search(latest_text))

    force_finalize = False
    reason = "normal_flow"
    intent = None
    
    # Refinement 2: Single-use refusal
    if asked_sensitive and not session.bf_policy_refused_once:
        intent = INT_REFUSE_SENSITIVE_ONCE
        session.bf_policy_refused_once = True
        session.bf_state = BF_S3
        reason = "policy_refusal"
    
    # State-based intent selection
    if not intent:
        if session.bf_state == BF_S0:
            session.bf_state = BF_S1
            intent = INT_ACK_CONCERN
        
        elif session.bf_state == BF_S1:
            session.bf_state = BF_S2
            intent = _pick_missing_intel_intent(intel_dict)
            
        elif session.bf_state == BF_S2:
            if session.bf_no_progress_count >= getattr(settings, "BF_NO_PROGRESS_TURNS", 2):
                session.bf_state = BF_S3
                intent = INT_ASK_ALT_VERIFICATION
            else:
                intent = _pick_missing_intel_intent(intel_dict)
                
        elif session.bf_state == BF_S3:
            if session.bf_no_progress_count >= getattr(settings, "BF_NO_PROGRESS_TURNS", 2):
                # Refinement 3: Limited secondary-failure bounce
                if session.bf_secondary_bounce_count < getattr(settings, "BF_SECONDARY_BOUNCE_LIMIT", 1):
                    session.bf_state = BF_S4
                    session.bf_secondary_bounce_count += 1
                    intent = INT_SECONDARY_FAIL
                else:
                    session.bf_state = BF_S5
                    intent = INT_CLOSE_AND_VERIFY_SELF
            else:
                intent = INT_ASK_TICKET_REF
                
        elif session.bf_state == BF_S4:
            # Bounce back to S3 after failure
            session.bf_state = BF_S3
            intent = INT_ASK_DEPARTMENT_BRANCH
            
        elif session.bf_state == BF_S5:
            intent = INT_CLOSE_AND_VERIFY_SELF
            force_finalize = True
        else:
            # Fallback
            intent = INT_CLOSE_AND_VERIFY_SELF

    # Refinement 1: Intent repetition breaker
    if intent == session.bf_last_intent:
        session.bf_repeat_count += 1
    else:
        session.bf_repeat_count = 0
    
    if session.bf_repeat_count >= getattr(settings, "BF_REPEAT_LIMIT", 2):
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
    if not intel_dict.get("phoneNumbers"):
        return INT_ASK_OFFICIAL_HELPLINE
    if not intel_dict.get("phishingLinks"):
        return INT_ASK_OFFICIAL_WEBSITE
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
