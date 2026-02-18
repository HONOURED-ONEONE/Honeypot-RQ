import pytest
from dataclasses import asdict
from app.store.models import SessionState, Intelligence
from app.core.broken_flow_constants import *
from app.core.broken_flow_controller import choose_next_action, compute_ioc_signature, _pick_missing_intel_intent
from app.llm.responder import _contains_forbidden as _safety_filter
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

def test_registry_driven_intent_selection(session, settings):
    intel_dict = asdict(session.extractedIntelligence)
    session.bf_state = BF_S2
    
    # Priority: Link (20) > Phone (10)
    action = choose_next_action(session, "hello", intel_dict, {}, settings)
    assert action["intent"] == INT_ASK_OFFICIAL_WEBSITE
    
    # Now add Link, should pick UPI (prio 15)
    intel_dict["phishingLinks"] = ["http://scam.com"]
    action = choose_next_action(session, "hello", intel_dict, {}, settings)
    assert action["intent"] == INT_ASK_ALT_VERIFICATION

    # Now add UPI, should pick Phone (prio 10)
    intel_dict["upiIds"] = ["scam@upi"]
    action = choose_next_action(session, "hello", intel_dict, {}, settings)
    assert action["intent"] == INT_ASK_OFFICIAL_HELPLINE

def test_deterministic_progression_on_intel(session, settings):
    intel_dict = asdict(session.extractedIntelligence)
    session.bf_state = BF_S1
    
    # Adding phone numbers advances state to BF_S3
    intel_dict["phoneNumbers"] = ["9999999999"]
    action = choose_next_action(session, "my phone is 9999999999", intel_dict, {}, settings)
    assert session.bf_state == BF_S3
    
    # Adding phishing link advances to S2 (if S0/S1) but we are in S3, so it stays in S3
    intel_dict["phishingLinks"] = ["http://scam.link"]
    action = choose_next_action(session, "visit http://scam.link", intel_dict, {}, settings)
    assert session.bf_state == BF_S3

def test_intent_repetition_pivot(session, settings):
    intel_dict = asdict(session.extractedIntelligence)
    session.bf_state = BF_S2
    # Website is highest priority
    session.bf_last_intent = INT_ASK_OFFICIAL_WEBSITE
    session.bf_repeat_count = 1 
    
    action = choose_next_action(session, "hello", intel_dict, {}, settings)
    # Trigger repetition pivot
    assert action["reason"] == "repetition_escalation"
    # Pivot should pick the next best missing intel (UPI, prio 15)
    assert action["intent"] == INT_ASK_ALT_VERIFICATION

def test_safety_filter_updated(session):
    assert _safety_filter("please open sms") is True
    assert _safety_filter("enter otp") is True
    assert _safety_filter("tap confirm") is True
    assert _safety_filter("6-digit code") is True
    assert _safety_filter("i am fine, how are you?") is False

def test_finalize_triggers(session, settings):
    from unittest.mock import patch
    with patch("app.core.finalize.settings", settings):
        session.scamDetected = True
        session.extractedIntelligence.phoneNumbers = ["1234567890"]
        session.extractedIntelligence.phishingLinks = ["http://scam.com"]
        # settings.py default is 3 categories (WAIT, it's 4 now)
        # MockSettings has FINALIZE_MIN_IOC_CATEGORIES = 2
        assert should_finalize(session) is not None
        
        session.extractedIntelligence = Intelligence()
        session.bf_no_progress_count = settings.BF_NO_PROGRESS_TURNS
        assert should_finalize(session) == "no_progress_threshold"

def test_pick_missing_intel_logic():
    # Test the pure function directly
    intel = {
        "phoneNumbers": [],
        "phishingLinks": [],
        "upiIds": [],
        "bankAccounts": [],
    }
    # Link (20) > UPI (15) > Phone (10)
    assert _pick_missing_intel_intent(intel, []) == INT_ASK_OFFICIAL_WEBSITE
    
    intel["phishingLinks"] = ["http"]
    assert _pick_missing_intel_intent(intel, []) == INT_ASK_ALT_VERIFICATION
    
    intel["upiIds"] = ["scam@upi"]
    assert _pick_missing_intel_intent(intel, []) == INT_ASK_OFFICIAL_HELPLINE
    
    intel["phoneNumbers"] = ["123"]
    assert _pick_missing_intel_intent(intel, []) == INT_CHANNEL_FAIL

    intel["bankAccounts"] = ["123456789012"]
    # All asked artifacts collected -> ACK_CONCERN
    assert _pick_missing_intel_intent(intel, []) == INT_ACK_CONCERN

def test_guardrail_controller_never_asks_passive_only(session, settings):
    from app.intel.artifact_registry import artifact_registry
    intel_dict = asdict(session.extractedIntelligence)
    session.bf_state = BF_S2
    
    # Normally picks Website (prio 20)
    # Let's set phishingLinks to passive_only
    artifact_registry.artifacts["phishingLinks"].passive_only = True
    try:
        action = choose_next_action(session, "hello", intel_dict, {}, settings)
        # Should NOT pick Website now, should pick UPI (prio 15)
        assert action["intent"] == INT_ASK_ALT_VERIFICATION
    finally:
        # Reset
        artifact_registry.artifacts["phishingLinks"].passive_only = False

def test_guardrail_finalization_ignores_non_registry_data(session, settings):
    from unittest.mock import patch
    with patch("app.core.finalize.settings", settings):
        session.scamDetected = True
        # Add data to Intelligence that IS in the registry
        session.extractedIntelligence.phoneNumbers = ["1234567890"]
        
        # Add something that is NOT in the registry
        setattr(session.extractedIntelligence, "fake_intel", ["some_data"])
        
        # Should NOT finalize because MockSettings has FINALIZE_MIN_IOC_CATEGORIES = 2
        assert should_finalize(session) is None
        
        # Add 2nd registered category
        session.extractedIntelligence.phishingLinks = ["http://scam.com"]
        assert should_finalize(session) == "ioc_milestone"
