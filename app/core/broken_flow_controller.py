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

# Default mapping (fallback if dynamic intent_map not provided for a key)
DEFAULT_ARTIFACT_INTENT_MAP = {
    "phoneNumbers": INT_ASK_OFFICIAL_HELPLINE,
    "phishingLinks": INT_ASK_OFFICIAL_WEBSITE,
    "upiIds": INT_ASK_ALT_VERIFICATION,
    "bankAccounts": INT_CHANNEL_FAIL,
}

# Repetition control / progression helpers
# Allowed intents that directly support artifact progress or safe control surfaces
_ALLOWED_INTENTS = {
    INT_REFUSE_SENSITIVE_ONCE,        # one-time boundary
    INT_ASK_OFFICIAL_HELPLINE,        # phoneNumbers
    INT_ASK_OFFICIAL_WEBSITE,         # phishingLinks
    INT_ASK_ALT_VERIFICATION,         # can bait upiIds/links; use with cooldowns
    INT_CHANNEL_FAIL,                 # controlled failure; often baits links/alternatives
    INT_SECONDARY_FAIL,               # non-terminal stuck surface
    INT_CLOSE_AND_VERIFY_SELF,        # finalization
    INT_ACK_CONCERN,                  # minimal filler (guarded by anti-loop)
    INT_ASK_TICKET_REF,               # progression
    INT_ASK_DEPARTMENT_BRANCH,        # progression
}

_ACK_SET = {INT_ACK_CONCERN}
_RECENT_WINDOW = 3
_ALT_COOLDOWN_WINDOW = 2

# Broad instruction phrases per intent (fallbacks)
INSTRUCTION_TEXTS: Dict[str, str] = {
    INT_ACK_CONCERN: "acknowledge concern briefly without adding steps",
    INT_REFUSE_SENSITIVE_ONCE: "refuse sharing OTP, PIN, or passwords and steer to official channels",
    INT_CHANNEL_FAIL: "state the link or page is not loading and ask for an official source to check",
    INT_ASK_OFFICIAL_WEBSITE: "ask for the official website or domain to verify independently",
    INT_ASK_OFFICIAL_HELPLINE: "ask for the official helpline number to call and verify",
    INT_ASK_TICKET_REF: "ask for a reference or complaint number for this case",
    INT_ASK_DEPARTMENT_BRANCH: "ask which department or branch is handling this case",
    INT_ASK_ALT_VERIFICATION: "ask for an alternative official verification method",
    INT_SECONDARY_FAIL: "say it still is not working on your side and ask for another official option",
    INT_CLOSE_AND_VERIFY_SELF: "politely close and state you will verify through official channels yourself",
}

def _intent_for_key(ioc_key: str) -> str:
    """
    Resolve intent for a registry IOC key, using dynamic registry.intent_map if present,
    else fallback to DEFAULT_ARTIFACT_INTENT_MAP.
    """
    dyn = artifact_registry.intent_map.get(ioc_key) if hasattr(artifact_registry, "intent_map") else None
    if isinstance(dyn, dict) and dyn.get("intent"):
        return str(dyn["intent"])
    return DEFAULT_ARTIFACT_INTENT_MAP.get(ioc_key, INT_ACK_CONCERN)

def _instruction_for(intent: str, ioc_key: str = None) -> str:
    dyn = artifact_registry.intent_map.get(ioc_key or "", {}) if hasattr(artifact_registry, "intent_map") else {}
    return str(dyn.get("instruction") or INSTRUCTION_TEXTS.get(intent, "acknowledge briefly"))

def _ioc_category_count_from_dict(intel_dict: Dict[str, Any]) -> int:
    count = 0
    for k in artifact_registry.artifacts.keys():
        if intel_dict.get(k):
            if isinstance(intel_dict.get(k), list) and len(intel_dict.get(k)) > 0:
                count += 1
    return count

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


def _pick_missing_intel_target(
    intel_dict: Dict[str, Any],
    recent_intents: List[str],
    scam_type: str = "UNKNOWN",
) -> (str, str):

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
        if not spec.enabled or not spec.ask_enabled or spec.passive_only:
            continue

        intent = _intent_for_key(spec.key)
        if not intent:
            continue

        if intel_dict.get(spec.key):
            continue

        if intent in recent_window:
            continue

        return intent, spec.key

    # Relax cooldown pass
    for spec in specs:
        if not spec.enabled or not spec.ask_enabled or spec.passive_only:
            continue

        intent = _intent_for_key(spec.key)
        if not intent:
            continue

        if not intel_dict.get(spec.key):
            return intent, spec.key

    if len(recent_intents) >= 3 and all(x in _ACK_SET for x in recent_intents[-3:]):
        return INT_ASK_ALT_VERIFICATION, None
    return INT_ACK_CONCERN, None

def _pick_missing_intel_intent(
    intel_dict: Dict[str, Any],
    recent_intents: List[str],
    scam_type: str = "UNKNOWN",
) -> str:
    """Compatibility wrapper returning only the intent string for tests/imports."""
    intent, _ = _pick_missing_intel_target(intel_dict, recent_intents, scam_type)
    return intent


def _pivot_intent(
    intel_dict: Dict[str, Any],
    recent_intents: List[str],
    avoid_intent: str,
    scam_type: str = "UNKNOWN",
) -> (str, str):
    return _pick_missing_intel_target(
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

    def _constrain(intent: str) -> str:
        # If a non-allowed intent is produced, pivot to a productive one
        if intent not in _ALLOWED_INTENTS:
            # choose a missing-intel intent based on registry
            return _pick_missing_intel_intent(intel_dict, session.bf_recent_intents, session.scam_type)
        return intent

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
    recent = session.bf_recent_intents[-_RECENT_WINDOW:]

    # ------------------------------------------------------------
    # PIVOT 0: Early boundary refusal if OTP/PIN appears and we haven't refused once.
    # This improves realism and safety without revealing detection logic.
    # ------------------------------------------------------------
    latest_lc = (latest_text or "").lower()
    otp_in_latest = any(t in latest_lc for t in _BOUNDARY_TERMS)
    if otp_in_latest and not session.bf_policy_refused_once:
        intent = INT_REFUSE_SENSITIVE_ONCE
        session.bf_policy_refused_once = True
        intent = _constrain(intent)
        session.bf_last_intent = intent
        session.bf_recent_intents.append(intent)
        if len(session.bf_recent_intents) > 10:
            session.bf_recent_intents.pop(0)
        # Early return to enforce boundary once
        return {
            "bf_state": session.bf_state,
            "intent": intent,
            "reason": "boundary_refusal",
            "force_finalize": False,
            "scam_type": session.scam_type,
            "instruction": _instruction_for(intent, None),
        }

    # ------------------------------------------------------------
    # IOC Progress Detection
    # ------------------------------------------------------------
    # Stronger escalation when there is sustained no-progress
    # If we've exceeded 2x the no-progress threshold, step up to SECONDARY_FAIL (non-terminal).
    try:
        if session.bf_no_progress_count >= (settings.BF_NO_PROGRESS_TURNS * 2):
            session.bf_state = BF_S4  # controlled failure surface
    except Exception:
        pass

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
    target_key = None
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
        intent, target_key = _pick_missing_intel_target(
            intel_dict,
            session.bf_recent_intents,
            session.scam_type,
        )

        # Progression once some intel exists
        got_phone = bool(intel_dict.get("phoneNumbers"))
        got_link  = bool(intel_dict.get("phishingLinks"))
        asked_ticket_recently = INT_ASK_TICKET_REF in recent
        asked_dept_recently   = INT_ASK_DEPARTMENT_BRANCH in recent

        # Prefer ticket after phone/link; then department after ticket
        if (got_phone or got_link):
            if not asked_ticket_recently and intent in (INT_ASK_ALT_VERIFICATION, INT_ACK_CONCERN, INT_ASK_OFFICIAL_WEBSITE):
                intent = INT_ASK_TICKET_REF
                target_key = None
                reason = "progress_ticket_ref"
            elif asked_ticket_recently and not asked_dept_recently and intent in (INT_ASK_ALT_VERIFICATION, INT_ACK_CONCERN):
                intent = INT_ASK_DEPARTMENT_BRANCH
                target_key = None
                reason = "progress_department"

        # Milestone finalize: if IOC categories meet threshold and scamDetected is true, request close now.
        try:
            ioc_cnt = _ioc_category_count_from_dict(intel_dict)
            if ioc_cnt >= settings.FINALIZE_MIN_IOC_CATEGORIES and getattr(session, "scamDetected", False):
                intent = INT_CLOSE_AND_VERIFY_SELF
                target_key = None
                force_finalize = True
                reason = "ioc_milestone_ready"
        except Exception:
            pass

        intent = _constrain(intent)

        # Keep existing OTP → HELPLINE bias when phone missing
        if otp_in_latest and not got_phone:
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
            intent, target_key = _pick_missing_intel_target(
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

        intent, target_key = _pivot_intent(
            intel_dict,
            session.bf_recent_intents,
            intent,
            session.scam_type,
        )

        session.bf_repeat_count = 0
        reason = "repetition_escalation"

    # ------------------------------------------------------------
    # PIVOT 2a: Cooldown for ALT_VERIFICATION to avoid repeated loops
    # If ALT_VERIFICATION was chosen very recently (last 2 intents), pivot once.
    # ------------------------------------------------------------
    if intent == INT_ASK_ALT_VERIFICATION and intent in session.bf_recent_intents[-_ALT_COOLDOWN_WINDOW:]:
        intent, target_key = _pivot_intent(
            intel_dict,
            session.bf_recent_intents,
            intent,
            session.scam_type,
        )
        reason = "alt_verification_cooldown"
        intent = _constrain(intent)

    # PIVOT 2b: ACK repetition guard — if ACK dominates recent window, pivot away
    if intent in _ACK_SET and sum(1 for x in recent if x in _ACK_SET) >= 2:
        intent, target_key = _pivot_intent(
            intel_dict,
            session.bf_recent_intents,
            intent,
            session.scam_type,
        )
        reason = "ack_repetition_breaker"
        intent = _constrain(intent)

    # ------------------------------------------------------------

    session.bf_last_intent = intent
    session.bf_recent_intents.append(intent)
    if len(session.bf_recent_intents) > 10:
        session.bf_recent_intents.pop(0)

    # Resolve a broad instruction for the responder
    instruction = _instruction_for(intent, target_key)

    return {
        "bf_state": session.bf_state,
        "intent": intent,
        "reason": reason,
        "force_finalize": force_finalize,
        "scam_type": session.scam_type,
        # NEW: hand instruction to responder for LLM phrasing
        "instruction": instruction,
    }