import pytest
from app.llm.detector import _high_signal_flags, _keyword_fallback

def test_high_signal_flags_otp():
    high, reasons, scam_hint = _high_signal_flags("Please share your OTP")
    assert high is True
    assert "otp/pin/password request" in reasons
    assert scam_hint == "BANK_IMPERSONATION"

def test_high_signal_flags_upi():
    high, reasons, scam_hint = _high_signal_flags("Send money via UPI")
    assert high is True
    assert "payment/upi request" in reasons
    assert scam_hint == "UPI_FRAUD"

def test_high_signal_flags_phishing():
    high, reasons, scam_hint = _high_signal_flags("Visit https://bit.ly/123 to verify account")
    assert high is True
    assert "link + verify/kyc/login" in reasons
    assert scam_hint == "PHISHING"

def test_keyword_fallback():
    res = _keyword_fallback("Please share your OTP")
    assert res["scamDetected"] is True
    assert res["confidence"] == 0.80
    assert res["scamType"] == "BANK_IMPERSONATION"

def test_keyword_fallback_no_scam():
    res = _keyword_fallback("How are you?")
    assert res["scamDetected"] is False
    assert res["confidence"] == 0.25

def test_detector_regexes_robustness():
    # Test LINK_TERMS with various formats
    texts = [
        "visit https://example.com/verify",
        "check www.scam.in",
        "open bit.ly/123-abc",
        "click tinyurl.com/xyz",
        "go to t.co/abc123"
    ]
    for text in texts:
        high, _, _ = _high_signal_flags(text + " to kyc")
        assert high is True, f"Failed on: {text}"

    # Test IMPERSONATION_TERMS with combinations
    high, reasons, _ = _high_signal_flags("This is HDFC bank. Please share your OTP.")
    assert high is True
    assert "impersonation + high-signal request" in reasons

    high, _, _ = _high_signal_flags("Contact customer care for UPI payment")
    assert high is True

    # Test word boundaries
    high, _, _ = _high_signal_flags("Not an otp-like string") # otp is matched but not word-boundary?
    # Actually "otp-like" might match \b if - is treated as non-word.
    # Let's test non-matching
    high, _, _ = _high_signal_flags("not_an_otp_string")
    assert high is False

    high, _, _ = _high_signal_flags("my_upi_id")
    assert high is False
