from app.intel.core_extraction import extract_all, normalize_text

def test_normalization():
    # Devanagari digits + zero width space + weird hyphen
    text = "Call \u0967\u0968\u0969\u200B456\u20137890"
    norm = normalize_text(text)
    assert "Call 123456-7890" in norm or "Call 1234567890" in norm.replace("-", "")

def test_extract_phone_simple():
    text = "Call +91-9876543210 or 8888888888"
    res = extract_all(text)
    assert "+919876543210" in res["phoneNumbers"]
    assert "+918888888888" in res["phoneNumbers"]

def test_extract_phone_indic():
    # "9876543210" in Devanagari is "९८७६५४३२१०"
    text = "Mera number \u096F\u096E\u096D\u096C\u096B\u096A\u0969\u0968\u0967\u0966 hai"
    res = extract_all(text)
    assert "+919876543210" in res["phoneNumbers"]

def test_extract_email():
    text = "Contact support@fakebank.com or admin.fraud@scam.co.in"
    res = extract_all(text)
    assert "support@fakebank.com" in res["emailAddresses"]
    assert "admin.fraud@scam.co.in" in res["emailAddresses"]

def test_extract_url():
    text = "Visit https://secure-login.com or http://phish.site/login."
    res = extract_all(text)
    assert "https://secure-login.com" in res["phishingLinks"]
    assert "http://phish.site/login" in res["phishingLinks"]

def test_extract_upi():
    text = "Pay to merchant@sbi or my.name@okicici"
    res = extract_all(text)
    assert "merchant@sbi" in res["upiIds"]
    assert "my.name@okicici" in res["upiIds"]

def test_extract_upi_obfuscated():
    text = "Pay to scammer @ paytm"
    res = extract_all(text)
    assert "scammer@paytm" in res["upiIds"]

def test_extract_bank_account_context():
    text = "Account No: 123456789012"
    res = extract_all(text)
    assert "123456789012" in res["bankAccounts"]

def test_extract_bank_account_fallback():
    # Only digits, no immediate context but maybe nearby?
    # The regex allows 20 chars distance.
    text = "My A/C details are below. 987654321098"
    res = extract_all(text)
    assert "987654321098" in res["bankAccounts"]

def test_invalid_stuff():
    text = "Call 12345. Visit ftp://file.server. invalid@email"
    res = extract_all(text)
    assert len(res["phoneNumbers"]) == 0
    assert len(res["phishingLinks"]) == 0
    # "invalid@email" might match EMAIL_RE if the regex allows simple domains, checking:
    # Regex: [a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}
    # "invalid@email" lacks dot in domain part? "email" is tld? No, "invalid@email" has no dot.
    # But wait, "invalid@email" -> domain is "email". Regex expects dot.
    assert len(res["emailAddresses"]) == 0
