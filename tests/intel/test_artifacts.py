import pytest
from app.intel.artifact_registry import artifact_registry
from app.intel.keywords import extract_keywords

def test_phone_extraction():
    text = "Call me at +91-9876543210 or 1800-123-4567"
    res = artifact_registry.extract_all(text)
    assert "+919876543210" in res["phoneNumbers"]
    assert "1800-123-456" in res["phoneNumbers"]

def test_upi_extraction():
    text = "Pay to scammer.fraud@fakebank"
    res = artifact_registry.extract_all(text)
    assert "scammer.fraud@fakebank" in res["upiIds"]

def test_bank_extraction():
    text = "Account: 1234-5678-9012-3456"
    res = artifact_registry.extract_all(text)
    assert "1234567890123456" in res["bankAccounts"]

def test_url_extraction():
    text = "Visit https://sbi-verify.com/login?ref=secure"
    res = artifact_registry.extract_all(text)
    assert "https://sbi-verify.com/login?ref=secure" in res["phishingLinks"]

def test_keyword_extraction():
    text = "Your account will be blocked, please do kyc immediately"
    hits = extract_keywords(text)
    assert "account will be blocked" in hits
    assert "kyc" in hits
    assert "immediately" in hits

def test_normalization_dashes():
    # Unicode dashes
    text = "Account\u20131234567890123456"
    res = artifact_registry.extract_all(text)
    assert "1234567890123456" in res["bankAccounts"]

def test_url_extraction_robustness():
    # Test P1.2e robust URL extractor
    text = "Visit https://sbi-verify.com/login?ref=secure and also check www.google.com"
    res = artifact_registry.extract_all(text)
    assert "https://sbi-verify.com/login?ref=secure" in res["phishingLinks"]
    assert "https://www.google.com" in res["phishingLinks"] # Normalized by normalize_url

def test_upi_id_with_underscores():
    # Test P1.2e UPI regex fix
    text = "Pay to scammer_fraud.123@fakebank"
    res = artifact_registry.extract_all(text)
    assert "scammer_fraud.123@fakebank" in res["upiIds"]
