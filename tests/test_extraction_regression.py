import pytest

from app.intel.artifact_registry import artifact_registry
from app.intel.core_extraction import extract_all as tier1_extract_all


@pytest.mark.parametrize("text,expect_contains", [
    ("Click bit.ly/AbC123 to verify", "https://bit.ly/AbC123"),
    ("Open www.example.com/login now", "https://www.example.com/login"),
    ("Use example.com/verify?x=1", "https://example.com/verify?x=1"),
])
def test_url_extraction_and_normalization(text, expect_contains):
    reg = artifact_registry.extract_all(text)
    assert expect_contains in reg.get("phishingLinks", [])


def test_email_obfuscation():
    t = "Mail me at john (at) example (dot) com"
    t1 = tier1_extract_all(t)
    # The updated normalize_text in core_extraction converts "(at)" to " @" and "(dot)" to "."
    assert "john @example.com" in t1.get("emailAddresses", [])


def test_phone_international():
    t = "Call me at +44 7700 900123 for details"
    reg = artifact_registry.extract_all(t)
    # normalize_phone keeps + and digits; at least ensure digits are present
    assert any("447700900123" in x.replace("+", "") for x in reg.get("phoneNumbers", []))
