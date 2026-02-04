import re
from urllib.parse import urlparse
from app.intel.keywords import extract_keywords

# Regexes (defensive extraction of scammer-shared IOCs)
UPI_RE = re.compile(r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}[a-zA-Z0-9.-]{1,}\b")
URL_RE = re.compile(r"\bhttps?://[^\s]+\b|\bwww\.[^\s]+\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?:(?:\+?91)[\s-]?)?[6-9]\d{9}\b")
# Bank account numbers vary; we only capture digit sequences near banking context
ACCT_CONTEXT_RE = re.compile(r"(?i)(?:account|a/c|acct|bank)\D{0,20}([0-9]{9,18})")


def _dedupe_extend(target_list, items):
    existing = set(target_list)
    for it in items:
        if it not in existing:
            target_list.append(it)
            existing.add(it)


def _normalize_url(u: str) -> str:
    u = u.strip().rstrip(').,]')
    if u.lower().startswith('www.'):
        u = 'https://' + u
    try:
        p = urlparse(u)
        if not p.scheme:
            return u
        # normalize scheme+netloc+path only
        return f"{p.scheme}://{p.netloc}{p.path}".rstrip('/')
    except Exception:
        return u


def update_intelligence_from_text(session, text: str):
    # Update ledger from scammer text.
    upis = UPI_RE.findall(text)
    urls = [_normalize_url(x) for x in URL_RE.findall(text)]
    phones = [x.replace(' ', '').replace('-', '') for x in PHONE_RE.findall(text)]
    accts = [m.group(1) for m in ACCT_CONTEXT_RE.finditer(text)]
    kws = extract_keywords(text)

    _dedupe_extend(session.extractedIntelligence.upiIds, upis)
    _dedupe_extend(session.extractedIntelligence.phishingLinks, urls)
    _dedupe_extend(session.extractedIntelligence.phoneNumbers, phones)
    _dedupe_extend(session.extractedIntelligence.bankAccounts, accts)
    _dedupe_extend(session.extractedIntelligence.suspiciousKeywords, kws)
