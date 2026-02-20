import pytest
from app.store.models import SessionState
from app.intel.extractor import update_intelligence_from_text

def test_update_intelligence_dedupe():
    session = SessionState(sessionId="test_dedupe")
    text = "Call 9876543210"
    update_intelligence_from_text(session, text)
    # Merged extraction might produce normalized (+91...) and raw variants.
    # Just ensure we have at least one valid extraction.
    assert any("9876543210" in p for p in session.extractedIntelligence.phoneNumbers)
    initial_count = len(session.extractedIntelligence.phoneNumbers)
    assert initial_count >= 1
    
    # Same text again -> should not increase count
    update_intelligence_from_text(session, text)
    assert len(session.extractedIntelligence.phoneNumbers) == initial_count
    
    # New phone number
    update_intelligence_from_text(session, "Another: 9999999999")
    assert any("9999999999" in p for p in session.extractedIntelligence.phoneNumbers)
    assert len(session.extractedIntelligence.phoneNumbers) > initial_count

def test_update_intelligence_mixed():
    session = SessionState(sessionId="test_mixed")
    text = "Call 9876543210 and visit http://scam.link"
    update_intelligence_from_text(session, text)
    assert "9876543210" in session.extractedIntelligence.phoneNumbers
    assert "http://scam.link" in session.extractedIntelligence.phishingLinks

def test_suspicious_keywords_extraction():
    session = SessionState(sessionId="test_kw")
    text = "Your account blocked. Please share OTP and PIN for verify."
    update_intelligence_from_text(session, text)
    kws = session.extractedIntelligence.suspiciousKeywords
    assert "account blocked" in kws
    assert "otp" in kws
    assert "pin" in kws
    assert "verify" in kws
