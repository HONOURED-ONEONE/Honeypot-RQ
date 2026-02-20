import types
from app.store.models import SessionState
from app.core.broken_flow_controller import (
    choose_next_action,
    INT_REFUSE_SENSITIVE_ONCE,
    INT_ASK_OFFICIAL_HELPLINE,
    INT_ASK_ALT_VERIFICATION,
)

def _new_session():
    s = SessionState(sessionId="t-session")
    # Ensure defaults are present (mirrors runtime defaults)
    s.bf_state = "BF_S0"
    s.bf_recent_intents = []
    s.bf_policy_refused_once = False
    s.bf_repeat_count = 0
    s.bf_no_progress_count = 0
    return s

def test_boundary_refusal_on_otp_first():
    session = _new_session()
    # No intel yet
    intel = {"phoneNumbers": [], "upiIds": [], "bankAccounts": [], "phishingLinks": []}
    out = choose_next_action(
        session=session,
        latest_text="Please share OTP now",
        intel_dict=intel,
        detection_dict={},
        settings=None,
    )
    assert out["intent"] == INT_REFUSE_SENSITIVE_ONCE
    assert session.bf_policy_refused_once is True

def test_bias_helpline_after_boundary_when_otp_present_and_no_phone():
    session = _new_session()
    # Simulate we already refused once
    session.bf_policy_refused_once = True
    # Pivot 1 is active in BF_S2, BF_S3, or BF_S4
    session.bf_state = "BF_S2"
    intel = {"phoneNumbers": [], "upiIds": [], "bankAccounts": [], "phishingLinks": []}
    out = choose_next_action(
        session=session,
        latest_text="Send OTP now",
        intel_dict=intel,
        detection_dict={},
        settings=None,
    )
    # We should bias to helpline when otp terms present and phoneNumbers missing
    assert out["intent"] == INT_ASK_OFFICIAL_HELPLINE

def test_cooldown_for_alt_verification_repetition():
    session = _new_session()
    session.bf_state = "BF_S3"
    session.bf_recent_intents = [INT_ASK_ALT_VERIFICATION, INT_ASK_ALT_VERIFICATION]
    intel = {"phoneNumbers": [], "upiIds": [], "bankAccounts": [], "phishingLinks": []}
    out = choose_next_action(
        session=session,
        latest_text="(no otp here)",
        intel_dict=intel,
        detection_dict={},
        settings=None,
    )
    # Should pivot away from ALT_VERIFICATION if it was used very recently
    assert out["intent"] != INT_ASK_ALT_VERIFICATION
