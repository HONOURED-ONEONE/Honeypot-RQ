import pytest
from app.store.models import SessionState, Intelligence
from app.intel.extractor import update_intelligence_from_text
from app.core.broken_flow_controller import choose_next_action
from app.core.finalize import should_finalize
from app.core.broken_flow_constants import *
from app.settings import settings

def test_extractor_missing_ioc():
    session = SessionState(sessionId="test_ext")
    # Test text with various IOCs
    text = "Call me at +91-9876543210 or 1800-123-4567. Visit https://sbi-verify.com/login?ref=secure. Pay to scammer.fraud@fakebank. Account: 1234-5678-9012-3456."
    
    update_intelligence_from_text(session, text)
    intel = session.extractedIntelligence
    
    assert "+919876543210" in intel.phoneNumbers
    assert "1800-123-456" in intel.phoneNumbers
    assert "https://sbi-verify.com/login?ref=secure" in intel.phishingLinks
    assert "scammer.fraud@fakebank" in intel.upiIds
    assert "1234567890123456" in intel.bankAccounts

def test_extractor_normalization():
    session = SessionState(sessionId="test_norm")
    # Unicode dashes and zero-width spaces
    text = "Acc\u200bount\u20131234567890123456"
    update_intelligence_from_text(session, text)
    assert "1234567890123456" in session.extractedIntelligence.bankAccounts

# def test_keywords_extraction():
#     session = SessionState(sessionId="test_kw")
#     text = "Here is your ticket REF987654321. Visit our branch."
#     update_intelligence_from_text(session, text)
#     kws = session.extractedIntelligence.suspiciousKeywords
#     assert "ticket" in kws
#     assert "ref" in kws
#     assert "branch" in kws

def test_controller_gating_and_priority():
    session = SessionState(sessionId="test_gate")
    session.scamDetected = True
    intel_dict = {
        "phoneNumbers": [],
        "phishingLinks": ["https://scam.link"],
        "upiIds": [],
        "bankAccounts": [],
    }
    session.extractedIntelligence.phishingLinks = intel_dict["phishingLinks"]
    session.bf_state = BF_S5 # Try to close
    
    # Should be gated because only 1 IOC category (link) is present, and settings.FINALIZE_MIN_IOC_CATEGORIES=2
    action = choose_next_action(session, "hello", intel_dict, {}, settings)
    
    assert action["intent"] != INT_CLOSE_AND_VERIFY_SELF
    assert action["reason"] == "close_gated_pivot"
    # Registry priority: UPI (15) is missing. Link (20) is present.
    assert action["intent"] == INT_ASK_ALT_VERIFICATION

def test_controller_repetition_pivot():
    session = SessionState(sessionId="test_rep")
    # Set state to S2 so it naturally picks INT_ASK_OFFICIAL_WEBSITE (highest prio)
    session.bf_state = BF_S2
    session.bf_last_intent = INT_ASK_OFFICIAL_WEBSITE
    session.bf_repeat_count = 1 # Already repeated once
    # No intel so it stays in S2 area and picks the same intent
    intel_dict = {"phoneNumbers": [], "phishingLinks": [], "upiIds": [], "bankAccounts": []}
    
    action = choose_next_action(session, "hello", intel_dict, {}, settings)
    assert action["intent"] != INT_ASK_OFFICIAL_WEBSITE
    assert action["reason"] == "repetition_escalation"
    # Should pivot to UPI (next best)
    assert action["intent"] == INT_ASK_ALT_VERIFICATION

def test_finalization_logic():
    session = SessionState(sessionId="test_fin")
    session.scamDetected = True
    
    # 0 categories
    assert should_finalize(session) is None
    
    # 1 category
    session.extractedIntelligence.phoneNumbers = ["+919876543210"]
    assert should_finalize(session) is None
    
    # 2 categories
    session.extractedIntelligence.phishingLinks = ["https://scam.link"]
    # ✅ P1.3: settings.FINALIZE_MIN_IOC_CATEGORIES is now 2 by default
    assert should_finalize(session) == "ioc_milestone"

def test_finalization_max_turns():
    session = SessionState(sessionId="test_max_turns")
    # ✅ P1.3: Default BF_MAX_TURNS is 10
    session.turnIndex = 10
    assert should_finalize(session) == "max_turns_reached"
    
    session.turnIndex = 5
    assert should_finalize(session) is None

def test_guardrail_non_registered_dropped():
    from app.intel.artifact_registry import artifact_registry
    session = SessionState(sessionId="test_guard_drop")
    # Some random text that shouldn't match any registered regex
    # and something that looks like an email but shouldn't match if we are strict (though UPI_RE is broad)
    # Actually, let's just use random noise.
    text = "Random noise 12345. My name is Junie. Visit https://scam.link"
    update_intelligence_from_text(session, text)
    
    # phishingLinks should be there
    assert "https://scam.link" in session.extractedIntelligence.phishingLinks
    # No other fields should have data
    assert len(session.extractedIntelligence.phoneNumbers) == 0
    assert len(session.extractedIntelligence.upiIds) == 0
    assert len(session.extractedIntelligence.bankAccounts) == 0

def test_guardrail_conflicts_phone_vs_bank():
    from app.intel.artifact_registry import artifact_registry
    session = SessionState(sessionId="test_guard_conflict")
    
    # We want to test that a value doesn't end up in both.
    # Since existing regexes don't overlap much, we can verify the 'conflicts_with' logic 
    # by checking that we don't have duplicates across categories if we were to force it.
    # But more importantly, the requirement is "Phone numbers never appear in bankAccounts".
    
    text = "My number is 9876543210. My account is 1234567890123456."
    update_intelligence_from_text(session, text)
    
    # Phone number should be in phoneNumbers, NOT in bankAccounts
    assert "9876543210" in session.extractedIntelligence.phoneNumbers
    assert "9876543210" not in session.extractedIntelligence.bankAccounts
    
    # Bank account should be in bankAccounts
    assert "1234567890123456" in session.extractedIntelligence.bankAccounts

def test_surface_driven_progression():
    session = SessionState(sessionId="test_prog")
    # Initial state S0
    intel_dict = {"phoneNumbers": [], "phishingLinks": ["https://link"], "upiIds": [], "bankAccounts": []}
    session.extractedIntelligence.phishingLinks = intel_dict["phishingLinks"]
    
    # First turn: detections etc.
    action = choose_next_action(session, "here is link", intel_dict, {}, settings)
    # Since phishingLinks is present, should advance to S2
    assert session.bf_state == BF_S2
    
    # Now add phone
    intel_dict["phoneNumbers"] = ["9876543210"]
    session.extractedIntelligence.phoneNumbers = intel_dict["phoneNumbers"]
    # We need to simulate the signature change detection
    # choose_next_action compares with session.bf_last_ioc_signature
    
    action = choose_next_action(session, "call me", intel_dict, {}, settings)
    assert session.bf_state == BF_S3
    
    # Now add UPI
    intel_dict["upiIds"] = ["scam@upi"]
    session.extractedIntelligence.upiIds = intel_dict["upiIds"]
    action = choose_next_action(session, "pay here", intel_dict, {}, settings)
    assert session.bf_state == BF_S4

@pytest.mark.parametrize("toggle", [True, False])
def test_guardrail_runtime_toggle_behavior(toggle):
    from unittest.mock import patch, MagicMock
    import json
    from app.intel.artifact_registry import artifact_registry
    
    # We test that toggling 'enabled' in Redis actually stops extraction
    with patch("app.store.redis_conn.get_redis") as mock_get_redis:
        mock_redis = MagicMock()
        mock_get_redis.return_value = mock_redis
        
        # Mock settings for TTL=0 to force refresh
        with patch("app.settings.settings") as mock_settings:
            mock_settings.REGISTRY_TTL = 0
            mock_settings.REGISTRY_OVERRIDES_KEY = "registry:overrides"
            
            # Set toggle state
            overrides = {"phoneNumbers": {"enabled": toggle}}
            mock_redis.get.return_value = json.dumps(overrides)
            
            session = SessionState(sessionId="test_toggle")
            text = "Call me at 9876543210"
            
            update_intelligence_from_text(session, text)
            
            if toggle:
                assert "9876543210" in session.extractedIntelligence.phoneNumbers
            else:
                assert "9876543210" not in session.extractedIntelligence.phoneNumbers
            
            # Cleanup for other tests
            mock_redis.get.return_value = None
            artifact_registry.extract_all("dummy")
