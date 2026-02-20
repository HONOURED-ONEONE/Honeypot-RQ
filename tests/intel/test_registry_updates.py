import pytest
from app.intel.artifact_registry import artifact_registry, normalize_url

def test_id_like_extraction():
    text = """
    Your CASE-AB12 is pending.
    Refer to REF-987654 for details.
    Check your policy POL-12345678.
    Order ORD-123456 has been shipped.
    PO-998877 is also ready.
    """
    res = artifact_registry.extract_all(text)
    
    assert "CASE-AB12" in res["caseIds"]
    assert "REF-987654" in res["caseIds"]
    assert "POL-12345678" in res["policyNumbers"]
    assert "ORD-123456" in res["orderNumbers"]
    assert "PO-998877" in res["orderNumbers"]

def test_normalize_url_improved():
    # Test handling of None
    assert normalize_url(None) == ""
    
    # Test stripping of various punctuation
    assert normalize_url("https://example.com/.") == "https://example.com/"
    assert normalize_url("https://example.com/!") == "https://example.com/"
    assert normalize_url("https://example.com/?") == "https://example.com/"
    assert normalize_url("https://example.com/;") == "https://example.com/"
    assert normalize_url("https://example.com/)") == "https://example.com/"
    assert normalize_url("https://example.com/]") == "https://example.com/"
    assert normalize_url("https://example.com/}") == "https://example.com/"
    
    # Test www promotion
    assert normalize_url("www.example.com") == "https://www.example.com"
    assert normalize_url("WWW.EXAMPLE.COM") == "https://WWW.EXAMPLE.COM"

def test_case_insensitive_ids():
    text = "ref-123456, pol-88776655, ord-abc123"
    res = artifact_registry.extract_all(text)
    
    # Extraction functions like _extract_case_ids use _norm_upper_hyphen
    assert "REF-123456" in res["caseIds"]
    assert "POL-88776655" in res["policyNumbers"]
    assert "ORD-ABC123" in res["orderNumbers"]
