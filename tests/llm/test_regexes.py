import re
from app.intel.artifact_registry import URL_RE
from app.llm.signals import (
    OTP_TERMS, PAYMENT_TERMS, LINK_TERMS, VERIFY_TERMS, THREAT_TERMS, IMPERSONATION_TERMS
)

def test_url_re_matches_http_and_www():
    assert URL_RE.search("see http://foo.bar/x") is not None
    assert URL_RE.search("go to www.foo.bar/login") is not None

def test_detector_high_signal_terms_no_newlines():
    # Must match and be single line patterns
    assert OTP_TERMS.search("share OTP now") is not None
    assert PAYMENT_TERMS.search("pay transfer fee now") is not None
    assert LINK_TERMS.search("open https://x.co/a or tinyurl.com/y") is not None
    assert VERIFY_TERMS.search("please verify kyc") is not None
    assert THREAT_TERMS.search("account will be blocked") is not None
    assert IMPERSONATION_TERMS.search("bank customer care") is not None

    # None of these patterns should contain literal newlines
    for pat in [OTP_TERMS, PAYMENT_TERMS, LINK_TERMS, VERIFY_TERMS, THREAT_TERMS, IMPERSONATION_TERMS]:
        assert "\n" not in pat.pattern
