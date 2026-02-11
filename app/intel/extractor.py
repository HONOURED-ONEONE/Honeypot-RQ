import re
from urllib.parse import urlparse
from app.intel.keywords import extract_keywords

# Regexes (defensive extraction of scammer-shared IOCs)
UPI_RE = re.compile(r"\b[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\b")
URL_RE = re.compile(r"\bhttps?://[^\s]+\b|\bwww\.[^\s]+\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?:(?:\+?91)[\s-]?)?[6-9]\d{9}\b")
TOLL_FREE_RE = re.compile(r"\b1800[\s-]?\d{3}[\s-]?\d{4}\b")
# Bank account/card numbers: 12-19 digits, allowing spaces/hyphens
BANK_RE = re.compile(r"\b(?:\d[\s-]?){11,18}\d\b")


def _dedupe_extend(target_list, items):
    existing = set(target_list)
    for it in items:
        if it not in existing:
            target_list.append(it)
            existing.add(it)


def _normalize_text(text: str) -> str:
    # normalize unicode dashes to ASCII "-"
    text = re.sub(r'[\u2010-\u2015]', '-', text)
    # remove zero-width characters
    text = re.sub(r'[\u200b-\u200d\ufeff]', '', text)
    # collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def _normalize_url(u: str) -> str:
    u = u.strip().rstrip(').,]')
    if u.lower().startswith('www.'):
        u = 'https://' + u
    # Preserve full URL including query string
    return u


def update_intelligence_from_text(session, text: str):
    # Update ledger from scammer text.
    text = _normalize_text(text)
    
    upis = [x.lower() for x in UPI_RE.findall(text)]
    urls = [_normalize_url(x) for x in URL_RE.findall(text)]
    
    # Phone numbers including +91 and 1800
    phones = [x.replace(' ', '').replace('-', '') for x in PHONE_RE.findall(text)]
    toll_frees = [x.replace(' ', '').replace('-', '') for x in TOLL_FREE_RE.findall(text)]
    _dedupe_extend(phones, toll_frees)
    
    # Bank accounts: capture 12-19 digits
    accts = [x.replace(' ', '').replace('-', '') for x in BANK_RE.findall(text)]
    
    kws = extract_keywords(text)

    _dedupe_extend(session.extractedIntelligence.upiIds, upis)
    _dedupe_extend(session.extractedIntelligence.phishingLinks, urls)
    _dedupe_extend(session.extractedIntelligence.phoneNumbers, phones)
    _dedupe_extend(session.extractedIntelligence.bankAccounts, accts)
    _dedupe_extend(session.extractedIntelligence.suspiciousKeywords, kws)


# --- PATCH: normalized IOC extraction ---

# NOTE: This block is appended by the patch script to improve IOC extraction.
# It is safe and defensive: it does not request OTP/PIN and does not invent identifiers.

import re

_UNICODE_DASHES = ["\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2212"]
_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\uFEFF]")
_WS_RE = re.compile(r"\s+")


def normalize_text(s: str) -> str:
    """Normalize unicode dashes, remove zero-width chars, collapse whitespace."""
    if not s:
        return ""
    for d in _UNICODE_DASHES:
        s = s.replace(d, "-")
    s = _ZERO_WIDTH_RE.sub("", s)
    s = _WS_RE.sub(" ", s).strip()
    return s


# Phone patterns: +91 mobile, 10-digit mobiles, and India toll-free 1800 formats.
_PHONE_PATTERNS = [
    re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}"),
    re.compile(r"1800[-\s]?\d{3}[-\s]?\d{3}"),
    re.compile(r"1800\d{6}"),
]

# UPI handle pattern (tolerant): allows dots/dashes/underscores in username.
_UPI_PATTERN = re.compile(r"\b[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32}\b")

# Account/card-like numbers: 12-19 digits with optional spaces/hyphens.
# We ignore short OTP-like values by enforcing length >= 12.
_ACCT_PATTERN = re.compile(r"\b(?:\d[ -]?){12,19}\b")


def _dedupe_keep_order(items):
    seen = set()
    out = []
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def extract_phone_numbers(text: str):
    t = normalize_text(text)
    found = []
    for pat in _PHONE_PATTERNS:
        for m in pat.findall(t):
            digits = re.sub(r"\D", "", m)
            if digits.startswith("1800") and len(digits) == 10:
                found.append(f"{digits[:4]}-{digits[4:7]}-{digits[7:]}")
            else:
                found.append(digits)
    return _dedupe_keep_order(found)


def extract_upi_ids(text: str):
    t = normalize_text(text)
    upis = [u.lower() for u in _UPI_PATTERN.findall(t)]
    return _dedupe_keep_order(upis)


def extract_bank_accounts(text: str):
    t = normalize_text(text)
    out = []
    for h in _ACCT_PATTERN.findall(t):
        digits = re.sub(r"\D", "", h)
        if 12 <= len(digits) <= 19:
            out.append(digits)
    return _dedupe_keep_order(out)


def _apply_ioc_patch_to_intel_dict(intel_dict: dict, text: str) -> dict:
    """Merge patched IOC extraction results into an existing intel dict."""
    if intel_dict is None:
        intel_dict = {}

    phones = extract_phone_numbers(text)
    upis = extract_upi_ids(text)
    accts = extract_bank_accounts(text)

    intel_dict.setdefault("phoneNumbers", [])
    intel_dict.setdefault("upiIds", [])
    intel_dict.setdefault("bankAccounts", [])

    intel_dict["phoneNumbers"] = _dedupe_keep_order(intel_dict["phoneNumbers"] + phones)
    intel_dict["upiIds"] = _dedupe_keep_order(intel_dict["upiIds"] + upis)
    intel_dict["bankAccounts"] = _dedupe_keep_order(intel_dict["bankAccounts"] + accts)

    return intel_dict

