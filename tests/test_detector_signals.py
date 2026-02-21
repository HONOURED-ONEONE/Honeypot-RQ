from app.llm.signals import score_message, score_conversation


def test_high_signal_otp():
    s, reasons, th = score_message("Share OTP now to unblock your account")
    assert s >= 0.45
    assert th in ("BANK_IMPERSONATION", "UNKNOWN")


def test_link_plus_verify():
    s, reasons, th = score_message("Verify KYC at bit.ly/abc now")
    assert s >= 0.45
    assert th == "PHISHING"


def test_cumulative_evidence():
    msgs = [
        "This is customer care, your account will be blocked today",
        "We need your account number to verify",
        "Also share OTP to complete verification",
    ]
    agg = score_conversation(msgs)
    assert agg["high_signal_seen"] is True
    assert float(agg["cumulative_score"]) > 0.5
