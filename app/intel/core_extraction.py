import re
import unicodedata
from urllib.parse import urlparse
from typing import List, Dict

# ---------------------------
# Normalization utilities
# ---------------------------

ZERO_WIDTH = dict.fromkeys(map(ord, [
    '\u200B', # ZERO WIDTH SPACE
    '\u200C', # ZERO WIDTH NON-JOINER
    '\u200D', # ZERO WIDTH JOINER
    '\u2060', # WORD JOINER
    '\uFEFF', # ZERO WIDTH NO-BREAK SPACE
]), None)

# Map common Indic digit ranges to ASCII 0-9
_INDIC_DIGIT_RANGES = [
    ('\u0966', '\u096F'),  # Devanagari 0-9
    ('\u0BE6', '\u0BEF'),  # Tamil 0-9
    ('\u0DE6', '\u0DEF'),  # Sinhala 0-9 (occasionally appears)
    ('\u0CE6', '\u0CEF'),  # Kannada 0-9
    ('\u0C66', '\u0C6F'),  # Telugu 0-9
    ('\u0D66', '\u0D6F'),  # Malayalam 0-9
    ('\u0AE6', '\u0AEF'),  # Gujarati 0-9
    ('\u0A66', '\u0A6F'),  # Gurmukhi 0-9
]

_digit_map = {}
for start, end in _INDIC_DIGIT_RANGES:
    for i, cp in enumerate(range(ord(start), ord(end) + 1)):
        _digit_map[cp] = ord('0') + i

def normalize_text(s: str) -> str:
    """
    - NFC normalize
    - strip zero width chars
    - convert Indic digits to ASCII
    - collapse repeated whitespace & separators
    """
    if not s:
        return s
    s = unicodedata.normalize('NFC', s)
    s = s.translate(ZERO_WIDTH)
    s = s.translate(_digit_map)
    # unify weird hyphens/dots that scammers insert between digits/handles
    s = s.replace('·', '.').replace('•', '.').replace('．', '.').replace('–', '-').replace('—', '-')
    # collapse spaces around typical separators to help regexes
    s = re.sub(r'\s+', ' ', s)
    return s

# ---------------------------
# Core patterns (hardened)
# ---------------------------

# Phone (India): allow optional +91 / 0 prefix, separators, and spacey obfuscations already normalized.
# Enforce leading digit 6-9 for 10-digit mobiles, avoid overmatching longer digit runs.
# Guard with numeric look-arounds so matches don't happen inside longer digit runs
PHONE_RE = re.compile(
    r'(?<!\d)(?:\+?91[\s-]?)?(?:0[\s-]?)?([6-9]\d[\s-]?\d{2}[\s-]?\d{3}[\s-]?\d{3})(?!\d)'
)

# Email: tolerant but case-insensitive; punycode/IDN not required for scoring, keep simple and fast.
EMAIL_RE = re.compile(
    r'\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b', re.I
)

# URL: basic http(s) with conservative terminators; avoid trailing punctuation and unmatched brackets.
URL_RE = re.compile(
    r'''\bhttps?://[^\s<>()\[\]{}"'|\\^`]+''', re.I
)

# UPI: <handle> @<psp>. Allow dots/underscores/dashes in handle, lowercase PSP alpha.
# Also catch spaced or dotted obfuscations we normalized (e.g., "id @ paytm").
UPI_RE = re.compile(
    r'\b([a-z0-9][a-z0-9._\-]{1,})\s*@\s*([a-z]{2,})\b', re.I
)

# Bank account: capture 9-18 contiguous digits with nearby context keywords.
# Two strategies:
#  1) Keyword-anchored capture (preferred)
#  2) Fallback: standalone 9-18 digits guarded by positive lookbehind for context within ~20 chars
ACCT_CTX = r'(?:a/?c|acct|account|a/c|ac no\.?|account no\.?|account number)'
ACCT_RE_CTX = re.compile(
    rf'\b(?:{ACCT_CTX})\s*(?:no\.?|number)?\s*[:\-]?\s*([0-9]{{9,18}})\b',
    re.I
)
ACCT_RE_FALLBACK = re.compile(
    rf'(?:(?:{ACCT_CTX}).{{0,20}})?\b([0-9]{{9,18}})\b',
    re.I
)

# ---------------------------
# Validators / post-filters
# ---------------------------

_PSP_SUFFIX_HINTS = {
    # Common PSP / bank handles (not exhaustive; used only as a soft hint)
    'okaxis', 'okhdfcbank', 'okicici', 'oksbi', 'okyesbank', 'paytm', 'apl',
    'ibl', 'axisbank', 'sbi', 'ybl', 'axl', 'idfcbank', 'kmbl', 'ubi', 'ubiupi',
    'barodampay', 'boi', 'fbl', 'jsb', 'aubank'
}

def _only_digits(s: str) -> str:
    return re.sub(r'\D+', '', s or '')

def _format_indian_mobile(s: str) -> str:
    d = _only_digits(s)
    # strip trunk 0 and country 91 if present
    if d.startswith('91') and len(d) >= 12:
        d = d[2:]
    if d.startswith('0') and len(d) >= 11:
        d = d[1:]
    return d

def is_valid_phone(candidate: str) -> bool:
    d = _format_indian_mobile(candidate)
    return len(d) == 10 and d[0] in '6789'

def is_valid_upi(candidate: str) -> bool:
    # Quick sanity: exactly one '@', handle+psp non-empty, PSP alpha.
    if '@' not in candidate:
        return False
    handle, sep, psp = candidate.lower().partition('@')
    if not handle or not psp.isalpha():
        return False
    # Ensure handle begins alnum, reasonably long
    if not re.match(r'^[a-z0-9][a-z0-9._\-]{1,}$', handle):
        return False
    # PSP hint: allow any alpha, but prefer common suffixes; do not reject unknown PSPs.
    return True

def is_plausible_account(candidate: str) -> bool:
    d = _only_digits(candidate)
    return 9 <= len(d) <= 18

def valid_url(u: str) -> bool:
    try:
        p = urlparse(u)
        if p.scheme not in ("http", "https") or not p.netloc:
            return False
        # Block obvious private/loopback hosts (avoid scoring issues / side effects)
        host = p.hostname or ""
        if host in {"localhost", "127.0.0.1"} or host.endswith(".local"):
            return False
        return True
    except Exception:
        return False

# ---------------------------
# Public API
# ---------------------------

def extract_all(text: str) -> Dict[str, List[str]]:
    """
    Deterministic, low-latency extraction for Honeypot scoring categories:
      - phoneNumbers, emailAddresses, phishingLinks, upiIds, bankAccounts
    Returns de-duplicated, normalized lists. Keep this fast (< few ms).
    """
    t = normalize_text(text or "")

    # Phones
    raw_phones = [m.group(1) for m in PHONE_RE.finditer(t)]
    phones = []
    for ph in raw_phones:
        d = _format_indian_mobile(ph)
        if is_valid_phone(d):
            phones.append("+91" + d if not ph.strip().startswith('+') else "+91" + d)
    phones = sorted(set(phones))

    # Emails
    emails = sorted(set(EMAIL_RE.findall(t)))

    # URLs
    urls = []
    for u in URL_RE.findall(t):
        # trim trailing punctuation commonly stuck to URLs
        u = u.rstrip(').,;!?\'"[]{}')
        if valid_url(u):
            urls.append(u)
    urls = sorted(set(urls))

    # UPI IDs
    upis = []
    for m in UPI_RE.finditer(t):
        cand = m.group(0)
        # normalize to handle@psp (remove all spaces)
        cand = cand.replace(' ', '')
        if is_valid_upi(cand):
            upis.append(cand.lower())
    upis = sorted(set(upis))

    # Bank accounts (context-first, then guarded fallback)
    accts = [m.group(1) for m in ACCT_RE_CTX.finditer(t)]
    # Fallback: only keep if surrounded by account-ish context within 20 chars (already in regex),
    # but also ensure we didn't already capture it.
    for m in ACCT_RE_FALLBACK.finditer(t):
        cand = m.group(1)
        if cand not in accts and is_plausible_account(cand):
            accts.append(cand)
    # Normalize to digit-only strings to avoid stray separators
    accts = sorted(set(_only_digits(a) for a in accts if is_plausible_account(a)))

    return {
        "phoneNumbers": phones,
        "emailAddresses": emails,
        "phishingLinks": urls,
        "upiIds": upis,
        "bankAccounts": accts
    }

def extract_phones_tier1(t: str) -> List[str]:
    return [m.group(1) for m in PHONE_RE.finditer(t)]
