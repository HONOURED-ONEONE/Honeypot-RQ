import pytest
from app.llm.detector import _keyword_fallback
from app.llm.signals import score_message

def test_high_signal_flags_otp():
    s, reasons, scam_hint = score_message("Please share your OTP")
    assert s >= 0.45
    assert "credential request (otp/pin/password)" in reasons
    assert scam_hint == "BANK_IMPERSONATION"

def test_high_signal_flags_upi():
    s, reasons, scam_hint = score_message("Send money via UPI")
    assert s >= 0.45
    assert "payment/transfer request" in reasons
    assert scam_hint == "UPI_FRAUD"

def test_high_signal_flags_phishing():
    s, reasons, scam_hint = score_message("Visit https://bit.ly/123 to verify account")
    assert s >= 0.45
    assert "link combined with verify/login/kyc" in reasons
    assert scam_hint == "PHISHING"

def test_keyword_fallback():
    # _keyword_fallback requires score >= 0.75 for scamDetected=True
    res = _keyword_fallback("Please share your OTP and payment details immediately to avoid block")
    assert res["scamDetected"] is True
    assert res["confidence"] == 0.82

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
        s, _, _ = score_message(text + " to kyc")
        assert s >= 0.45, f"Failed on: {text}"

    # Test IMPERSONATION_TERMS with combinations
    s, reasons, _ = score_message("This is HDFC bank. Please share your OTP.")
    assert s >= 0.5
    assert "impersonation/authority claim" in reasons

    s, _, _ = score_message("Contact customer care for UPI payment")
    assert s >= 0.5

    # Test word boundaries
    s, _, _ = score_message("not_an_otp_string")
    assert s < 0.45

    s, _, _ = score_message("my_upi_id")
    assert s < 0.45
