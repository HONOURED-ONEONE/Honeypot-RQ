import pytest
from app.intel.artifact_registry import artifact_registry, _valid_http_url, _canonicalize_urls
from app.settings import settings
from app.core import broken_flow_constants

def test_valid_http_url():
    assert _valid_http_url("http://example.com") is True
    assert _valid_http_url("https://example.com") is True
    assert _valid_http_url("ftp://example.com") is False
    assert _valid_http_url("http://localhost") is False
    assert _valid_http_url("http://127.0.0.1") is False
    assert _valid_http_url("http://mysite.local") is False
    assert _valid_http_url("not a url") is False

def test_canonicalize_urls():
    urls = [
        "www.example.com",
        "https://example.com/.",
        "http://example.com",
        "https://example.com",
        "http://localhost",
        "www.example.com" # duplicate
    ]
    canonical = _canonicalize_urls(urls)
    # 1. www.example.com -> https://www.example.com
    # 2. https://example.com/. -> https://example.com/
    # 3. http://example.com -> http://example.com
    # 4. https://example.com -> https://example.com
    # 5. http://localhost -> filtered
    assert "https://www.example.com" in canonical
    assert "https://example.com/" in canonical
    assert "http://example.com" in canonical
    assert "https://example.com" in canonical
    assert len(canonical) == 4

def test_registry_extract_all_canonicalizes_urls():
    text = "Check www.scam.com and https://fake.in/login! and http://localhost"
    res = artifact_registry.extract_all(text)
    links = res.get("phishingLinks", [])
    assert "https://www.scam.com" in links
    assert "https://fake.in/login" in links
    assert "http://localhost" not in links

def test_new_settings_presence():
    assert hasattr(settings, "ALT_SEMANTIC_WINDOW")
    assert hasattr(settings, "ALT_MAX_USES_IN_WINDOW")
    assert hasattr(settings, "OTP_PRESSURE_WINDOW")
    assert hasattr(settings, "OTP_PRESSURE_THRESHOLD")

def test_new_constants_presence():
    assert broken_flow_constants._ALT_SEMANTIC_WINDOW == settings.ALT_SEMANTIC_WINDOW
    assert broken_flow_constants._ALT_MAX_USES_IN_WINDOW == settings.ALT_MAX_USES_IN_WINDOW
    assert broken_flow_constants._OTP_PRESSURE_WINDOW == settings.OTP_PRESSURE_WINDOW
    assert broken_flow_constants._OTP_PRESSURE_THRESHOLD == settings.OTP_PRESSURE_THRESHOLD
