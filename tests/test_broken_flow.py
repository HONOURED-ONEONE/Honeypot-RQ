import pytest
from dataclasses import asdict
from app.store.models import SessionState, Intelligence
from app.core.broken_flow_constants import *
from app.core.broken_flow_controller import choose_next_action, compute_ioc_signature, _pick_missing_intel_intent
from app.llm.responder import _safety_filter
from app.core.finalize import should_finalize

class MockSettings:
    BF_ENABLED = True
    BF_MAX_TURNS = 15
    BF_NO_PROGRESS_TURNS = 10 
    BF_REPEAT_LIMIT = 2
    BF_SECONDARY_BOUNCE_LIMIT = 1
    BF_MIN_IOC_CATEGORIES = 2
    BF_LLM_REPHRASE = False
    FINALIZE_MIN_IOC_CATEGORIES = 2
    FINALIZE_MIN_TURNS = 5
    INACTIVITY_TIMEOUT_SEC = 180

@pytest.fixture
def session():
    s = SessionState(sessionId="test_session")
    s.bf_last_ioc_signature = compute_ioc_signature(asdict(s.extractedIntelligence))
    return s

@pytest.fixture
def settings():
    return MockSettings()

def test_otp_refusal_once_and_exit(session, settings):
    intel_dict = asdict(session.extractedIntelligence)
    action = choose_next_action(session, "send me the otp", intel_dict, {}, settings)
    assert action["intent"] == INT_REFUSE_SENSITIVE_ONCE
    assert session.bf_policy_refused_once is True
    assert session.bf_state == BF_S3
    
    action = choose_next_action(session, "i need the otp now", intel_dict, {}, settings)
    assert action["intent"] != INT_REFUSE_SENSITIVE_ONCE
    assert session.bf_state == BF_S4
    assert action["reason"] == "otp_loop_exit"

def test_deterministic_progression_on_intel(session, settings):
    intel_dict = asdict(session.extractedIntelligence)
    session.bf_state = BF_S1
    
    intel_dict["phoneNumbers"] = ["9999999999"]
    action = choose_next_action(session, "my phone is 9999999999", intel_dict, {}, settings)
    assert session.bf_state == BF_S2
    
    # We need to re-add S2->S3 transition in the controller for this to pass
    intel_dict["phishingLinks"] = ["http://scam.link"]
    action = choose_next_action(session, "visit http://scam.link", intel_dict, {}, settings)
    assert session.bf_state == BF_S3

def test_intent_repetition_pivot(session, settings):
    intel_dict = asdict(session.extractedIntelligence)
    session.bf_state = BF_S2
    session.bf_last_intent = INT_ASK_OFFICIAL_HELPLINE
    session.bf_repeat_count = 0 
    
    action = choose_next_action(session, "hello", intel_dict, {}, settings)
    assert action["intent"] == INT_ASK_OFFICIAL_HELPLINE
    assert session.bf_repeat_count == 1
    
    action = choose_next_action(session, "hello again", intel_dict, {}, settings)
    assert action["reason"] == "repetition_pivot"
    assert session.bf_repeat_count == 0

def test_safety_filter_updated(session):
    assert _safety_filter("please open sms") is True
    assert _safety_filter("enter otp") is True
    assert _safety_filter("tap confirm") is True
    assert _safety_filter("6-digit code") is True
    assert _safety_filter("i am fine, how are you?") is False

def test_finalize_triggers(session, settings):
    session.scamDetected = True
    session.extractedIntelligence.phoneNumbers = ["1234567890"]
    session.extractedIntelligence.phishingLinks = ["http://scam.com"]
    assert should_finalize(session) is True
    
    session.extractedIntelligence = Intelligence()
    session.bf_no_progress_count = settings.BF_NO_PROGRESS_TURNS
    assert should_finalize(session) is True

def test_pick_missing_intel_logic():
    # Test the pure function directly
    intel = {
        "phoneNumbers": [],
        "phishingLinks": [],
        "suspiciousKeywords": []
    }
    assert _pick_missing_intel_intent(intel) == INT_ASK_OFFICIAL_HELPLINE
    
    intel["phoneNumbers"] = ["123"]
    assert _pick_missing_intel_intent(intel) == INT_ASK_OFFICIAL_WEBSITE
    
    intel["phishingLinks"] = ["http"]
    assert _pick_missing_intel_intent(intel) == INT_ASK_TICKET_REF
    
    intel["suspiciousKeywords"] = ["ticket"]
    assert _pick_missing_intel_intent(intel) == INT_ASK_DEPARTMENT_BRANCH
