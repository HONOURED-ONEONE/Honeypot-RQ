import pytest
from app.store.models import SessionState, Intelligence
from app.intel.extractor import update_intelligence_from_text
from app.intel.core_extraction import extract_all

def test_url_normalization_in_core_extraction():
    # Verify core_extraction.extract_all uses normalize_url
    text = "Visit https://scam-site.com/."
    res = extract_all(text)
    # Trailing /. should be stripped by normalize_url
    assert "https://scam-site.com/" in res["phishingLinks"]

def test_account_fallback_excludes_mobiles():
    # 10-digit number that looks like a mobile should be excluded from ACCT_RE_FALLBACK
    # if it's not explicitly prefixed with account keywords.
    text = "Please check this number 9876543210" 
    res = extract_all(text)
    # 9876543210 matches ACCT_RE_FALLBACK (\b(?:\d[ -]?){12,19}\b is for ACCT_PATTERN in artifact_registry, 
    # but core_extraction uses [0-9]{9,18})
    # Wait, let me check core_extraction patterns again.
    # ACCT_RE_FALLBACK = re.compile(rf'(?:(?:{ACCT_CTX}).{{0,20}})?\b([0-9]{{9,18}})\b', re.I)
    # 9876543210 is 10 digits, so it matches \b([0-9]{9,18})\b.
    # But it also matches PHONE_RE.
    assert "9876543210" not in res["bankAccounts"]
    # It should be in phoneNumbers (normalized)
    assert any("9876543210" in p for p in res["phoneNumbers"])

def test_post_merge_sanitize_urls():
    session = SessionState(sessionId="test_sanitize_urls")
    # Manually add some unnormalized URLs to intelligence
    session.extractedIntelligence.phishingLinks = ["http://scam.com/.", "www.another-scam.com"]
    
    # Trigger update_intelligence_from_text with empty text just to run post_merge_sanitize
    update_intelligence_from_text(session, "")
    
    links = session.extractedIntelligence.phishingLinks
    assert "http://scam.com/" in links
    assert "https://www.another-scam.com" in links
    assert "http://scam.com/." not in links
    assert "www.another-scam.com" not in links

def test_post_merge_sanitize_phone_vs_bank():
    session = SessionState(sessionId="test_phone_vs_bank")
    # 9876543210 is both a phone and a bank account (if incorrectly extracted)
    session.extractedIntelligence.phoneNumbers = ["+919876543210"]
    session.extractedIntelligence.bankAccounts = ["9876543210", "123456789012"]
    
    update_intelligence_from_text(session, "")
    
    # 9876543210 should be removed from bankAccounts because it's in phoneNumbers
    assert "9876543210" not in session.extractedIntelligence.bankAccounts
    assert "123456789012" in session.extractedIntelligence.bankAccounts

def test_post_merge_sanitize_mobile_as_bank_removal():
    session = SessionState(sessionId="test_mobile_as_bank")
    # Even if it's NOT in phoneNumbers, if it IS a valid phone, remove from bank accounts
    session.extractedIntelligence.bankAccounts = ["9123456789"] # valid 10-digit mobile
    
    update_intelligence_from_text(session, "")
    
    assert "9123456789" not in session.extractedIntelligence.bankAccounts

def test_phone_deduplication_and_sorting():
    session = SessionState(sessionId="test_phone_dedup")
    session.extractedIntelligence.phoneNumbers = ["+919876543210", "9876543210", "+919876543210"]
    
    update_intelligence_from_text(session, "")
    
    # Should be sorted and unique
    # Note: currently _post_merge_sanitize does sorted(set(...))
    # Artifact registry might have produced both +91 and raw. 
    # Sanitizer just de-dups whatever is there.
    assert len(session.extractedIntelligence.phoneNumbers) == 2
    assert session.extractedIntelligence.phoneNumbers == sorted(["+919876543210", "9876543210"])
