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
    assert "18001234567" in intel.phoneNumbers
    assert "https://sbi-verify.com/login?ref=secure" in intel.phishingLinks
    assert "scammer.fraud@fakebank" in intel.upiIds
    assert "1234567890123456" in intel.bankAccounts

def test_extractor_normalization():
    session = SessionState(sessionId="test_norm")
    # Unicode dashes and zero-width spaces
    text = "Acc\u200bount\u20131234567890123456"
    update_intelligence_from_text(session, text)
    assert "1234567890123456" in session.extractedIntelligence.bankAccounts

def test_keywords_extraction():
    session = SessionState(sessionId="test_kw")
    text = "Here is your ticket REF987654321. Visit our branch."
    update_intelligence_from_text(session, text)
    kws = session.extractedIntelligence.suspiciousKeywords
    assert "ticket" in kws
    assert "ref" in kws
    assert "branch" in kws

def test_controller_gating_and_priority():
    session = SessionState(sessionId="test_gate")
    session.scamDetected = True
    intel_dict = {
        "phoneNumbers": [],
        "phishingLinks": ["https://scam.link"],
        "upiIds": [],
        "bankAccounts": [],
        "suspiciousKeywords": []
    }
    session.extractedIntelligence.phishingLinks = intel_dict["phishingLinks"]
    session.bf_state = BF_S5 # Try to close
    
    # Should be gated because only 1 IOC category (link) is present, and default MIN_IOC is 2
    action = choose_next_action(session, "hello", intel_dict, {}, settings)
    
    assert action["intent"] != INT_CLOSE_AND_VERIFY_SELF
    assert action["reason"] == "close_gated_pivot"
    # Priority: phone -> website -> ticket -> branch. Phone is missing.
    assert action["intent"] == INT_ASK_OFFICIAL_HELPLINE

def test_controller_repetition_pivot():
    session = SessionState(sessionId="test_rep")
    # Set state to S2 so it naturally picks INT_ASK_OFFICIAL_HELPLINE
    session.bf_state = BF_S2
    session.bf_last_intent = INT_ASK_OFFICIAL_HELPLINE
    session.bf_repeat_count = 1 # Already repeated once
    # No intel so it stays in S2 area and picks the same intent
    intel_dict = {"phoneNumbers": [], "phishingLinks": [], "upiIds": [], "bankAccounts": []}
    
    action = choose_next_action(session, "hello", intel_dict, {}, settings)
    assert action["intent"] != INT_ASK_OFFICIAL_HELPLINE
    assert action["reason"] == "repetition_pivot"

def test_finalization_logic():
    session = SessionState(sessionId="test_fin")
    session.scamDetected = True
    
    # 0 categories
    assert should_finalize(session) is False
    
    # 1 category
    session.extractedIntelligence.phoneNumbers = ["+919876543210"]
    assert should_finalize(session) is False
    
    # 2 categories
    session.extractedIntelligence.phishingLinks = ["https://scam.link"]
    assert should_finalize(session) is True

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
