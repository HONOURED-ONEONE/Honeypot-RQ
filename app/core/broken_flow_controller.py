from typing import Dict, Any, List

from app.core.broken_flow_constants import *
from app.core.broken_flow_constants import (
    _ALT_COOLDOWN_WINDOW,
    _ALT_SEMANTIC_WINDOW,
    _ALT_MAX_USES_IN_WINDOW,
    _OTP_PRESSURE_WINDOW,
    _OTP_PRESSURE_THRESHOLD,
)
from app.core.state_machine import *
from app.store.models import SessionState
from app.core.finalize import should_finalize
from app.intel.artifact_registry import artifact_registry
from app.settings import settings as default_settings
from app.core.investigative_ladder import choose_ladder_target
import hashlib
import json


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

# --------------------------------------------
# Scam-aware "expected IOC" sets (heuristic)
# --------------------------------------------
# Used for prioritization and to avoid early finalize.
# This is NOT a hard requirement; we still terminate on
# no-progress/repeat/max-turns to ensure completion.
EXPECTED_IOCS_BY_SCAMTYPE = {
    "BANK_IMPERSONATION": ["phoneNumbers", "bankAccounts", "caseIds"],
    "UPI_FRAUD":          ["upiIds", "phoneNumbers", "caseIds"],
    "PHISHING":           ["phishingLinks", "emailAddresses", "orderNumbers"],
    "JOB_SCAM":           ["phoneNumbers", "upiIds", "policyNumbers"],
}

def _expected_iocs_covered(intel_dict: Dict[str, Any], scam_type: str) -> bool:
    exp = EXPECTED_IOCS_BY_SCAMTYPE.get((scam_type or "UNKNOWN").upper(), [])
    if not exp:
        return False
    for k in exp:
        vals = intel_dict.get(k) or []
        if not (isinstance(vals, list) and len(vals) > 0):
            return False
    return True

# Controller-owned reasons so we never fall back to generic strings when we know better
CTRL_REASON_EXPECTED_IOCS = "expected_iocs_covered"
CTRL_REASON_MIN_TURNS_AND_IOCS = "ioc_min_count_and_turns"
CTRL_REASON_NO_PROGRESS = "no_progress_window"
CTRL_REASON_SECONDARY_BOUNCE = "secondary_bounce_limit"

def finalize(reason: str) -> Dict[str, str]:
    """Standard shape consumed by orchestrator."""
    return {"force_finalize": True, "reason": reason}

def keep_going() -> Dict[str, str]:
    return {"force_finalize": False, "reason": ""}

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


# ----------------------------
# Group B helpers
# ----------------------------
def _count_intent_in_window(recent: List[str], name: str, window: int) -> int:
    if window <= 0:
        return recent.count(name)
    return sum(1 for x in recent[-window:] if x == name)

def _otp_pressure_count(session, window_msgs: int) -> int:
    try:
        convo = getattr(session, "conversation", []) or []
        # Scan last N scammer messages for boundary terms
        c = 0
        for m in reversed(convo):
            if window_msgs <= 0:
                break
            if (m.get("sender") or "").lower() == "scammer":
                txt = (m.get("text") or "").lower()
                if any(t in txt for t in _BOUNDARY_TERMS):
                    c += 1
                window_msgs -= 1
        return c
    except Exception:
        return 0

def _alt_satisfied(intel_dict: Dict[str, Any]) -> bool:
    """
    ALT_VERIFICATION typically seeks alternate official verification paths,
    which often yield phoneNumbers or phishingLinks. If either is already present,
    prefer not to ask ALT again.
    """
    try:
        has_phone = bool(intel_dict.get("phoneNumbers"))
        has_link = bool(intel_dict.get("phishingLinks"))
        return has_phone or has_link
    except Exception:
        return False


# ============================================================
# Controller
# ============================================================

def choose_next_action(
    session: SessionState,
    latest_text: str,
    intel_dict: Dict[str, Any],
    detection_dict: Dict[str, Any],
    settings: Any,
    red_flag: str = "NONE",
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
    session.bf_ack_used_count = int(getattr(session, "bf_ack_used_count", 0) or 0)
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
    # Correct definition: "new intel" iff signature changed since last turn.
    # Do NOT treat "any existing intel" as new every turn, or no-progress never triggers.
    prev_sig = getattr(session, "bf_last_ioc_signature", None)
    
    if not prev_sig:
        # First turn or previously empty: treat as new to initialize state/counters
        session.bf_last_ioc_signature = new_signature
        new_intel_received = True
    else:
        new_intel_received = (new_signature != prev_sig)
        if new_intel_received:
            session.bf_last_ioc_signature = new_signature

    if new_intel_received:
        session.bf_no_progress_count = 0
    else:
        session.bf_no_progress_count += 1

    intent = None
    target_key = None
    force_finalize = False
    reason = "normal_flow"

    # ------------------------------------------------------------
    # Anti-redundancy helpers (category cooldown + satisfied guard)
    # ------------------------------------------------------------
    def _has_vals(key: str) -> bool:
        try:
            vals = intel_dict.get(key) or []
            return isinstance(vals, list) and len(vals) > 0
        except Exception:
            return False

    def _asked_map() -> Dict[str, int]:
        try:
            return getattr(session, "askedArtifactLastTurn", {}) or {}
        except Exception:
            return {}

    def _avoid_keys() -> List[str]:
        try:
            return list(getattr(session, "lastNewIocKeys", []) or [])
        except Exception:
            return []

    def _cooldown_block(key: str, window_turns: int = 4) -> bool:
        """
        Prevent repeatedly asking the same category too soon.
        window_turns counts in session.turnIndex units (which includes both sides).
        """
        try:
            last_map = getattr(session, "askedArtifactLastTurn", {}) or {}
            last = int(last_map.get(key, -10**9))
            now = int(getattr(session, "turnIndex", 0) or 0)
            return (now - last) < int(window_turns)
        except Exception:
            return False

    def _mark_asked(key: str) -> None:
        try:
            m = dict(getattr(session, "askedArtifactLastTurn", {}) or {})
            m[key] = int(getattr(session, "turnIndex", 0) or 0)
            session.askedArtifactLastTurn = m
        except Exception:
            pass

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
        # Start with an investigative move anchored to the most obvious red-flag
        session.bf_state = BF_S1
        if (red_flag or "").upper() == "OTP_REQUEST":
            intent = INT_REFUSE_SENSITIVE_ONCE
        elif (red_flag or "").upper() == "SUSPICIOUS_LINK":
            intent = INT_ASK_OFFICIAL_WEBSITE
        elif (red_flag or "").upper() == "THREAT_PRESSURE":
            intent = INT_ASK_TICKET_REF
        elif (red_flag or "").upper() == "IMPERSONATION_CLAIM":
            intent = INT_ASK_DEPARTMENT_BRANCH
        elif (red_flag or "").upper() == "PAYMENT_REQUEST":
            intent = INT_ASK_ALT_VERIFICATION
        else:
            # Default: ask for official helpline to verify identity
            intent = INT_ASK_OFFICIAL_HELPLINE
    elif session.bf_state == BF_S1:
        # Scoring-optimized: use investigative ladder for variety + relevance. [1](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.txt)[2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.1771597261347.log)
        ladder_key = choose_ladder_target(
            intel_dict=intel_dict,
            scam_type=session.scam_type,
            asked_last_turn=_asked_map(),
            turn_index=int(getattr(session, "turnIndex", 0) or 0),
            cooldown_turns=4,
            avoid_keys=_avoid_keys(),
        )
        session.lastLadderTarget = ladder_key
        if ladder_key == "department":
            intent, target_key = INT_ASK_DEPARTMENT_BRANCH, None
        elif ladder_key == "phoneNumbers":
            intent, target_key = INT_ASK_OFFICIAL_HELPLINE, "phoneNumbers"
        elif ladder_key == "phishingLinks":
            intent, target_key = INT_ASK_OFFICIAL_WEBSITE, "phishingLinks"
        elif ladder_key == "upiIds":
            intent, target_key = INT_ASK_ALT_VERIFICATION, "upiIds"
        elif ladder_key == "emailAddresses":
            # No dedicated intent exists; domain/site verification is the closest safe surface.
            intent, target_key = INT_ASK_OFFICIAL_WEBSITE, "emailAddresses"
        elif ladder_key == "caseIds":
            intent, target_key = INT_ASK_TICKET_REF, "caseIds"
        elif ladder_key == "policyNumbers":
            intent, target_key = INT_ASK_TICKET_REF, "policyNumbers"
        elif ladder_key == "orderNumbers":
            intent, target_key = INT_ASK_TICKET_REF, "orderNumbers"
        else:
            # Fallback to existing missing-intel selector
            intent, target_key = _pick_missing_intel_target(
                intel_dict,
                session.bf_recent_intents,
                session.scam_type,
            )
    elif session.bf_state in (BF_S2, BF_S3, BF_S4):
        # Use ladder in deeper states too, to avoid repetitive cycles and keep engagement varied. [1](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.txt)[2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.1771597261347.log)
        ladder_key = choose_ladder_target(
            intel_dict=intel_dict,
            scam_type=session.scam_type,
            asked_last_turn=_asked_map(),
            turn_index=int(getattr(session, "turnIndex", 0) or 0),
            cooldown_turns=4,
            avoid_keys=_avoid_keys(),
        )
        session.lastLadderTarget = ladder_key
        if ladder_key == "department":
            intent, target_key = INT_ASK_DEPARTMENT_BRANCH, None
        elif ladder_key == "phoneNumbers":
            intent, target_key = INT_ASK_OFFICIAL_HELPLINE, "phoneNumbers"
        elif ladder_key == "phishingLinks":
            intent, target_key = INT_ASK_OFFICIAL_WEBSITE, "phishingLinks"
        elif ladder_key == "upiIds":
            intent, target_key = INT_ASK_ALT_VERIFICATION, "upiIds"
        elif ladder_key == "emailAddresses":
            intent, target_key = INT_ASK_OFFICIAL_WEBSITE, "emailAddresses"
        elif ladder_key == "caseIds":
            intent, target_key = INT_ASK_TICKET_REF, "caseIds"
        elif ladder_key == "policyNumbers":
            intent, target_key = INT_ASK_TICKET_REF, "policyNumbers"
        elif ladder_key == "orderNumbers":
            intent, target_key = INT_ASK_TICKET_REF, "orderNumbers"
        else:
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
            scam_ok = bool(getattr(session, "scamDetected", False))
            turns  = int(getattr(session, "turnIndex", 0) or 0)
            # New gating: prefer closing only after expected IOC coverage AND min turns,
            # while still allowing deterministic termination (no-progress/repeat/max-turns elsewhere).
            if scam_ok:
                exp_cov = _expected_iocs_covered(intel_dict, session.scam_type)
                if exp_cov and turns >= 8:
                    intent = INT_CLOSE_AND_VERIFY_SELF
                    target_key = None
                    force_finalize = True
                    reason = CTRL_REASON_EXPECTED_IOCS
                elif ioc_cnt >= settings.FINALIZE_MIN_IOC_CATEGORIES and turns >= 8:
                    intent = INT_CLOSE_AND_VERIFY_SELF
                    target_key = None
                    force_finalize = True
                    reason = CTRL_REASON_MIN_TURNS_AND_IOCS
        except Exception:
            pass

        intent = _constrain(intent)

        # ------------------------------------------------------------
        # Fix B: ACK gating (allow INT_ACK_CONCERN at most once per session)
        # ------------------------------------------------------------
        if intent == INT_ACK_CONCERN:
            if int(getattr(session, "bf_ack_used_count", 0) or 0) >= 1:
                # Pivot away from ACK to a productive, IOC-eliciting intent
                intent, target_key = _pick_missing_intel_target(
                    intel_dict,
                    session.bf_recent_intents,
                    session.scam_type,
                )
                reason = "ack_gated_pivot"
            else:
                session.bf_ack_used_count = int(getattr(session, "bf_ack_used_count", 0) or 0) + 1
                reason = reason or "ack_allowed_once"

        # ----------------------------
        # Group B: OTP pressure (even if phone exists)
        # ----------------------------
        otp_recent = _otp_pressure_count(session, _OTP_PRESSURE_WINDOW)
        got_phone = bool(intel_dict.get("phoneNumbers"))
        if otp_recent >= _OTP_PRESSURE_THRESHOLD:
            # First assert boundary once; if already asserted, steer to helpline (non-procedural) again
            if not session.bf_policy_refused_once:
                intent = INT_REFUSE_SENSITIVE_ONCE
                session.bf_policy_refused_once = True
                reason = "otp_pressure_refusal"
            else:
                intent = INT_ASK_OFFICIAL_HELPLINE
                reason = "otp_pressure_helpline"

        # ----------------------------
        # Group B: ALT satisfaction & semantic cooldown
        # ----------------------------
        recent_full: List[str] = list(getattr(session, "bf_recent_intents", []) or [])
        if intent == INT_ASK_ALT_VERIFICATION:
            # 1) Satisfied suppression: if phone or link already present, avoid ALT
            if _alt_satisfied(intel_dict):
                asked_ticket_recently = INT_ASK_TICKET_REF in recent
                asked_dept_recently = INT_ASK_DEPARTMENT_BRANCH in recent
                if not asked_ticket_recently:
                    intent = INT_ASK_TICKET_REF
                    reason = "alt_satisfied_to_ticket"
                elif not asked_dept_recently:
                    intent = INT_ASK_DEPARTMENT_BRANCH
                    reason = "alt_satisfied_to_department"
                else:
                    intent = INT_ACK_CONCERN
                    reason = "alt_satisfied_to_ack"
            else:
                # 2) Semantic cooldown: limit total ALT uses in lookback window
                alt_uses = _count_intent_in_window(recent_full, INT_ASK_ALT_VERIFICATION, _ALT_SEMANTIC_WINDOW)
                if alt_uses >= _ALT_MAX_USES_IN_WINDOW:
                    # Pivot to another productive target using registry-based chooser
                    intent, _ = _pivot_intent(intel_dict, session.bf_recent_intents, INT_ASK_ALT_VERIFICATION, session.scam_type)
                    reason = "alt_semantic_cooldown_pivot"

    # Final guard: terminal state
    if session.bf_state == BF_S5 and intent != INT_CLOSE_AND_VERIFY_SELF:
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
    # Anti-redundancy: satisfied-category guard (pivot away)
    # ------------------------------------------------------------
    if intent == INT_ASK_OFFICIAL_HELPLINE and _has_vals("phoneNumbers"):
        intent, target_key = _pivot_intent(intel_dict, session.bf_recent_intents, intent, session.scam_type)
        reason = "satisfied_guard_pivot_phone"
    if intent == INT_ASK_OFFICIAL_WEBSITE and _has_vals("phishingLinks"):
        intent, target_key = _pivot_intent(intel_dict, session.bf_recent_intents, intent, session.scam_type)
        reason = "satisfied_guard_pivot_link"
    if intent == INT_ASK_TICKET_REF and _has_vals("caseIds"):
        intent, target_key = _pivot_intent(intel_dict, session.bf_recent_intents, intent, session.scam_type)
        reason = "satisfied_guard_pivot_case"

    # ------------------------------------------------------------
    # Anti-redundancy: category cooldown (avoid asking same target_key too soon)
    # ------------------------------------------------------------
    if target_key and _cooldown_block(target_key, window_turns=4):
        intent, target_key = _pivot_intent(intel_dict, session.bf_recent_intents, intent, session.scam_type)
        reason = "category_cooldown_pivot"

    # Record the asked category for future cooldown checks
    if target_key:
        _mark_asked(target_key)
    elif intent == INT_ASK_DEPARTMENT_BRANCH:
        _mark_asked("department")

    # ------------------------------------------------------------

    # Resolve a broad instruction for the responder
    instruction = _instruction_for(intent, target_key)
    
    # NEW: choose a responder_key; by default we mirror the intent
    responder_key = intent

    return {
        "bf_state": session.bf_state,
        "intent": intent,
        "responder_key": responder_key,
        "reason": reason,
        "force_finalize": force_finalize,
        "scam_type": session.scam_type,
        "instruction": instruction,
        "target_key": target_key,
    }
