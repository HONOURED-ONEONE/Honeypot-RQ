import hashlib
import json
from typing import Dict, Any, List
from app.core.broken_flow_constants import *
from app.core.state_machine import *
from app.store.models import SessionState
from app.core.finalize import should_finalize
from app.intel.artifact_registry import artifact_registry
from app.settings import settings as default_settings


# ============================================================
# Registry-Driven Logic
# ============================================================

ARTIFACT_INTENT_MAP = {
    "phoneNumbers": INT_ASK_OFFICIAL_HELPLINE,
    "phishingLinks": INT_ASK_OFFICIAL_WEBSITE,
}


def compute_ioc_signature(intel_dict: Dict[str, Any]) -> str:
    data = {}
    for key in artifact_registry.artifacts.keys():
        if key in intel_dict:
            data[key] = sorted(intel_dict[key])
    encoded = json.dumps(data, sort_keys=True).encode()
    return hashlib.md5(encoded).hexdigest()


def _pick_missing_intel_intent(
    intel_dict: Dict[str, Any],
    recent_intents: List[str],
) -> str:
    """
    Improved registry-driven intent selection:
    - Strict priority ordering
    - Strong cooldown (last 3 intents)
    - Deterministic
    - No structural changes
    """

    specs = sorted(
        artifact_registry.artifacts.values(),
        key=lambda x: (x.priority, not x.passive_only),
        reverse=True,
    )

    recent_window = set(recent_intents[-3:])

    # First pass: respect cooldown strictly
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

    # Second pass: relax cooldown once to avoid deadlock
    for spec in specs:
        if not spec.ask_enabled or spec.passive_only:
            continue

        intent = ARTIFACT_INTENT_MAP.get(spec.key)
        if not intent:
            continue

        if not intel_dict.get(spec.key):
            return intent

    return INT_ACK_CONCERN


def _pivot_intent(intel_dict: Dict[str, Any], recent_intents: List[str], avoid_intent: str) -> str:
    return _pick_missing_intel_intent(intel_dict, recent_intents + [avoid_intent])


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
    # Progress-based loop breaking
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
    # Intent Selection
    # ------------------------------------------------------------

    if session.bf_state == BF_S0:
        session.bf_state = BF_S1
        intent = INT_ACK_CONCERN
    elif session.bf_state == BF_S1:
        intent = INT_ACK_CONCERN
    elif session.bf_state in (BF_S2, BF_S3, BF_S4):
        intent = _pick_missing_intel_intent(intel_dict, session.bf_recent_intents)
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
            intent = _pick_missing_intel_intent(intel_dict, session.bf_recent_intents)
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

        # Escalate state before pivoting
        if session.bf_state in (BF_S2, BF_S3):
            session.bf_state = BF_S4
        elif session.bf_state == BF_S4:
            session.bf_state = BF_S5

        intent = _pivot_intent(intel_dict, session.bf_recent_intents, intent)
        session.bf_repeat_count = 0
        reason = "repetition_escalation"

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
    }