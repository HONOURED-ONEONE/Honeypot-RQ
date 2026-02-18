import hashlib
import json
from typing import Dict, Any, List
from app.core.broken_flow_constants import *
from app.core.state_machine import *
from app.store.models import SessionState
from app.core.finalize import should_finalize
from app.intel.artifact_registry import artifact_registry
from app.settings import settings as default_settings


# ---------------------------------------------------------------------------
# OTP/PIN boundary trigger (lightweight, controller-local)
# We avoid importing detector internals; simple keyword check on latest_text.
# ---------------------------------------------------------------------------
_BOUNDARY_TERMS = ("otp", "pin", "password")


# ============================================================
# Registry-Driven Logic
# ============================================================

ARTIFACT_INTENT_MAP = {
    "phoneNumbers": INT_ASK_OFFICIAL_HELPLINE,
    "phishingLinks": INT_ASK_OFFICIAL_WEBSITE,
    "upiIds": INT_ASK_ALT_VERIFICATION,
    "bankAccounts": INT_CHANNEL_FAIL,
}


def compute_ioc_signature(intel_dict: Dict[str, Any]) -> str:
    data = {}
    for key in artifact_registry.artifacts.keys():
        if key in intel_dict:
            data[key] = sorted(intel_dict[key])
    encoded = json.dumps(data, sort_keys=True).encode()
    return hashlib.md5(encoded).hexdigest()


# ------------------------------------------------------------
# Scam-Aware Priority Boost
# ------------------------------------------------------------

def _scam_priority_boost(spec, scam_type: str) -> int:
    if scam_type == "UPI_FRAUD" and spec.key in ("upiIds", "bankAccounts"):
        return 10
    if scam_type == "PHISHING" and spec.key == "phishingLinks":
        return 10
    if scam_type == "BANK_IMPERSONATION" and spec.key == "phoneNumbers":
        return 8
    if scam_type == "JOB_SCAM" and spec.key in ("phoneNumbers", "bankAccounts"):
        return 6
    return 0


def _pick_missing_intel_intent(
    intel_dict: Dict[str, Any],
    recent_intents: List[str],
    scam_type: str = "UNKNOWN",
) -> str:

    specs = sorted(
        artifact_registry.artifacts.values(),
        key=lambda x: (
            x.priority + _scam_priority_boost(x, scam_type),
            not x.passive_only,
        ),
        reverse=True,
    )

    recent_window = set(recent_intents[-3:])

    # Strict cooldown pass
    for spec in specs:
        if not spec.ask_enabled or spec.passive_only:
            continue

        intent = ARTIFACT_INTENT_MAP.get(spec.key)
        if not intent:
            continue

        if intel_dict.get(spec.key):
            continue

        if intent in recent_window:
            continue

        return intent

    # Relax cooldown pass
    for spec in specs:
        if not spec.ask_enabled or spec.passive_only:
            continue

        intent = ARTIFACT_INTENT_MAP.get(spec.key)
        if not intent:
            continue

        if not intel_dict.get(spec.key):
            return intent

    return INT_ACK_CONCERN


def _pivot_intent(
    intel_dict: Dict[str, Any],
    recent_intents: List[str],
    avoid_intent: str,
    scam_type: str = "UNKNOWN",
) -> str:
    return _pick_missing_intel_intent(
        intel_dict,
        recent_intents + [avoid_intent],
        scam_type,
    )


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

    if settings is None or isinstance(settings, dict):
        settings = default_settings

    # ------------------------------------------------------------
    # Session defaults
    # ------------------------------------------------------------

    session.bf_state = getattr(session, "bf_state", BF_S0)
    session.bf_last_intent = getattr(session, "bf_last_intent", None)
    session.bf_repeat_count = getattr(session, "bf_repeat_count", 0)
    session.bf_no_progress_count = getattr(session, "bf_no_progress_count", 0)
    session.bf_secondary_bounce_count = getattr(session, "bf_secondary_bounce_count", 0)
    session.bf_policy_refused_once = getattr(session, "bf_policy_refused_once", False)
    session.bf_recent_intents = getattr(session, "bf_recent_intents", [])
    session.bf_last_ioc_signature = getattr(session, "bf_last_ioc_signature", None)
    session.scam_type = getattr(session, "scam_type", "UNKNOWN")

    # ------------------------------------------------------------
    # PIVOT 0: Early boundary refusal if OTP/PIN appears and we haven't refused once.
    # This improves realism and safety without revealing detection logic.
    # ------------------------------------------------------------
    latest_lc = (latest_text or "").lower()
    otp_in_latest = any(t in latest_lc for t in _BOUNDARY_TERMS)
    if otp_in_latest and not session.bf_policy_refused_once:
        intent = INT_REFUSE_SENSITIVE_ONCE
        session.bf_policy_refused_once = True
        session.bf_last_intent = intent
        session.bf_recent_intents.append(intent)
        if len(session.bf_recent_intents) > 10:
            session.bf_recent_intents.pop(0)
        return {
            "bf_state": session.bf_state,
            "intent": intent,
            "reason": "boundary_refusal",
            "force_finalize": False,
            "scam_type": session.scam_type,
        }

    # ------------------------------------------------------------
    # IOC Progress Detection
    # ------------------------------------------------------------

    new_signature = compute_ioc_signature(intel_dict)
    new_intel_received = False

    if session.bf_last_ioc_signature is None:
        session.bf_last_ioc_signature = new_signature
        if any(intel_dict.get(k) for k in artifact_registry.artifacts.keys()):
            new_intel_received = True
    elif new_signature != session.bf_last_ioc_signature:
        new_intel_received = True
        session.bf_no_progress_count = 0
        session.bf_last_ioc_signature = new_signature
    else:
        session.bf_no_progress_count += 1

    intent = None
    force_finalize = False
    reason = "normal_flow"

    # ------------------------------------------------------------
    # State Advancement via Intel
    # ------------------------------------------------------------

    if new_intel_received:
        if intel_dict.get("upiIds") or intel_dict.get("bankAccounts"):
            if session.bf_state in (BF_S0, BF_S1, BF_S2, BF_S3):
                session.bf_state = BF_S4
        elif intel_dict.get("phoneNumbers"):
            if session.bf_state in (BF_S0, BF_S1, BF_S2):
                session.bf_state = BF_S3
        elif intel_dict.get("phishingLinks"):
            if session.bf_state in (BF_S0, BF_S1):
                session.bf_state = BF_S2

    # ------------------------------------------------------------
    # Loop Breaking
    # ------------------------------------------------------------

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

    # ------------------------------------------------------------
    # Intent Selection (Scam-aware)
    # ------------------------------------------------------------

    if session.bf_state == BF_S0:
        session.bf_state = BF_S1
        intent = INT_ACK_CONCERN
    elif session.bf_state == BF_S1:
        intent = INT_ACK_CONCERN
    elif session.bf_state in (BF_S2, BF_S3, BF_S4):
        intent = _pick_missing_intel_intent(
            intel_dict,
            session.bf_recent_intents,
            session.scam_type,
        )

        # PIVOT 1: When OTP terms are present and we still don't have a phone number,
        # prefer asking for an official helpline (yields phoneNumbers) instead of looping ALT_VERIFICATION.
        if otp_in_latest and not intel_dict.get("phoneNumbers"):
            intent = INT_ASK_OFFICIAL_HELPLINE
            reason = "otp_bias_helpline"
    elif session.bf_state == BF_S5:
        intent = INT_CLOSE_AND_VERIFY_SELF
        force_finalize = True
    else:
        intent = INT_CLOSE_AND_VERIFY_SELF
        force_finalize = True

    # ------------------------------------------------------------
    # Close Gating
    # ------------------------------------------------------------

    if intent == INT_CLOSE_AND_VERIFY_SELF:
        if should_finalize(session) is None:
            intent = _pick_missing_intel_intent(
                intel_dict,
                session.bf_recent_intents,
                session.scam_type,
            )
            force_finalize = False
            reason = "close_gated_pivot"

    # ------------------------------------------------------------
    # Repetition Breaker + Escalation
    # ------------------------------------------------------------

    if intent == session.bf_last_intent:
        session.bf_repeat_count += 1
    else:
        session.bf_repeat_count = 0

    if session.bf_repeat_count >= settings.BF_REPEAT_LIMIT:

        if session.bf_state in (BF_S2, BF_S3):
            session.bf_state = BF_S4
        elif session.bf_state == BF_S4:
            session.bf_state = BF_S5

        intent = _pivot_intent(
            intel_dict,
            session.bf_recent_intents,
            intent,
            session.scam_type,
        )

        session.bf_repeat_count = 0
        reason = "repetition_escalation"

    # ------------------------------------------------------------
    # PIVOT 2: Cooldown for ALT_VERIFICATION to avoid repeated loops
    # If ALT_VERIFICATION was chosen very recently (last 2 intents), pivot once.
    # ------------------------------------------------------------
    if intent == INT_ASK_ALT_VERIFICATION and intent in session.bf_recent_intents[-2:]:
        intent = _pivot_intent(
            intel_dict,
            session.bf_recent_intents,
            intent,
            session.scam_type,
        )
        reason = "alt_verification_cooldown"

    # ------------------------------------------------------------

    session.bf_last_intent = intent
    session.bf_recent_intents.append(intent)
    if len(session.bf_recent_intents) > 10:
        session.bf_recent_intents.pop(0)

    return {
        "bf_state": session.bf_state,
        "intent": intent,
        "reason": reason,
        "force_finalize": force_finalize,
        "scam_type": session.scam_type,
    }