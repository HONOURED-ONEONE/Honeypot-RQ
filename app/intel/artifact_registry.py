import re
import time
import json
from typing import Match
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Dict, Any, Iterable, Set, Tuple
from app.settings import settings
from app.store.redis_conn import get_redis
from urllib.parse import urlparse

@dataclass
class ArtifactSpec:
    key: str
    extract_fn: Callable[[str], List[str]]
    normalize_fn: Optional[Callable[[str], str]] = None
    validate_fn: Optional[Callable[[str], bool]] = None
    conflicts_with: List[str] = field(default_factory=list)
    priority: int = 0
    ask_enabled: bool = True
    passive_only: bool = False
    enabled: bool = True

# -----------------
# New ID-like Regex
# -----------------
# Conservative patterns with explicit prefixes to reduce false positives.
# Case IDs: REF/CASE/TICKET + 4–12 A-Z0-9
# Enhanced per Objective 5: ORG-YEAR-SEQUENCE, ORG-SEQUENCE, ALPHA{1,4}\d{6,12}
_CASE_ID_RE = re.compile(
    r'(?<![A-Z0-9])(?:'
    r'(?:REF|CASE|TKT|SR|ID|NO)[-\s]?[A-Z0-9]{4,12}'
    r'|'
    r'[A-Z]{2,5}-(?:19|20)\d{2}-\d{3,12}'  # ORG-YEAR-SEQUENCE (e.g. ITR-2024-789)
    r'|'
    r'[A-Z]{2,5}-\d{6,12}'                 # ORG-SEQUENCE (e.g. AMZ-00123)
    r'|'
    r'[A-Z]{1,4}\d{6,12}'                  # ALPHA+DIGITS (bounded length)
    r')(?![A-Z0-9])',
    re.I
)
# POLICY: e.g., POL-12345678 (typical insurer style)
_POLICY_NO_RE = re.compile(
    r'(?<![A-Z0-9])(?:POL|POLICY)[-\s]?[A-Z0-9]{6,16}(?![A-Z0-9])',
    re.I
)
# ORDER:
# - ORD / ORDER: allow alphanumerics 4–16 but REQUIRE at least one digit (prevents "PORTAL" type false positives)
# - PO: require 4–16 digits after PO (purchase order numbers are typically numeric in scams)
_ORDER_NO_RE = re.compile(
    r'(?<![A-Z0-9])(?:'
    r'(?:ORD|ORDER)[-\s]?(?=[A-Z0-9]{4,16}\b)(?=[A-Z0-9]*\d)[A-Z0-9]{4,16}'
    r'|'
    r'PO[-\s]?\d{4,16}'
    r')(?![A-Z0-9])',
    re.I
)

# Regexes from existing extractor.py
UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32}\b")
# ✅ URL extractor (expanded):
# - http(s)://...
# - www....
# - common shorteners without scheme: bit.ly/..., t.co/..., tinyurl.com/..., is.gd/...
# - bare domains WITH a path or query: example.com/path, example.com?x=1
#   (avoid matching plain domains without / or ? to reduce false positives)
URL_RE = re.compile(
    r"\b(?:"
    r"https?://[^\s<>()\[\]{}\"'\\^`]+"
    r"|www\.[^\s<>()\[\]{}\"'\\^`]+"
    r"|(?:bit\.ly|t\.co|tinyurl\.com|is\.gd|goo\.gl|cutt\.ly|rb\.gy)/[A-Za-z0-9_\-/?=&%#.]+"
    r"|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>()\[\]{}\"'\\^`]+|\?[^\s<>()\[\]{}\"'\\^`]+)"
    r")",
    re.IGNORECASE
)
_PHONE_PATTERNS = [
    # Mobile (optionally +91), guarded so it cannot be carved out of adjacent digits
    re.compile(r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)"),
    # Toll-free 1800 with separators
    re.compile(r"(?<!\d)1800[-\s]?\d{3}[-\s]?\d{3}(?!\d)"),
    # Toll-free 1800 contiguous digits (older style)
    re.compile(r"(?<!\d)1800\d{6,7}(?!\d)"),
]

# ✅ International / E.164-ish phone capture (conservative):
# - requires '+' OR parentheses/space separators
# - total digits 10..15 to avoid matching short numeric IDs
_PHONE_INTL_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\-\s().]{8,}\d)(?!\d)")
_ACCT_PATTERN = re.compile(r"\b(?:\d[ -]?){12,19}\b")

# Email extractor (tolerant). Keep simple + fast.
EMAIL_RE = re.compile(r"\b[a-z0-9._%+\-]+\s*@\s*[a-z0-9.\-]+\.[a-z]{2,}\b", re.I)

def normalize_email(e: str) -> str:
    # remove spaces around @ and lowercase
    return re.sub(r"\s+", "", (e or "")).lower()


# Normalization utilities
def normalize_phone(s: str) -> str:
    # Remove spaces and hyphens but keep + and digits
    clean = re.sub(r"[^\d+]", "", s)
    if clean.startswith("1800") and len(clean) == 10:
        return f"{clean[:4]}-{clean[4:7]}-{clean[7:]}"
    return clean


def _digits_only(s: str) -> str:
    return re.sub(r"\D", "", s or "")


def _valid_intl_phone(raw: str) -> bool:
    d = _digits_only(raw)
    # Avoid confusing long IDs with phones; require 10..15 digits
    return 10 <= len(d) <= 15

def normalize_upi(s: str) -> str:
    return s.lower()

def normalize_url(u: str) -> str:
    # Strip common trailing punctuation that frequently rides with URLs
    u = (u or "").strip().rstrip(').,;!?\'"[]{}')
    # Promote scheme-less forms:
    # - www.* -> https://www.*
    # - shorteners like bit.ly/... -> https://bit.ly/...
    # - bare domains with / or ? -> https://example.com/...
    ul = u.lower()
    if ul.startswith("www."):
        u = "https://" + u
    elif re.match(r"^(?:bit\.ly|t\.co|tinyurl\.com|is\.gd|goo\.gl|cutt\.ly|rb\.gy)/", ul):
        u = "https://" + u
    elif re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/|\?)", ul):
        u = "https://" + u
    return u

def _valid_http_url(u: str) -> bool:
    """
    Minimal, side‑effect‑free URL validation:
    - scheme is http/https
    - netloc present
    - reject obvious loopback/private hostnames (best‑effort)
    """
    try:
        p = urlparse(u)
        if p.scheme not in ("http", "https") or not p.netloc:
            return False
        host = (p.hostname or "").lower()
        if not host:
            return False
        if host in {"localhost", "127.0.0.1"} or host.endswith(".local"):
            return False
        return True
    except Exception:
        return False

def _canonicalize_urls(urls: List[str]) -> List[str]:
    """
    Apply shared normalization + minimal validation + de‑duplication.
    This function is intentionally lightweight and consistent with the
    canonicalization used elsewhere, so Registry and Tier‑1 paths converge.
    """
    out: List[str] = []
    seen: Set[str] = set()
    for u in urls or []:
        cu = normalize_url(u)
        if cu and _valid_http_url(cu) and cu not in seen:
            out.append(cu)
            seen.add(cu)
    return out

def normalize_bank(s: str) -> str:
    return re.sub(r"\D", "", s)

# ✅ NEW: Helpers for case/policy/order extraction
def _dedupe_preserve(seq: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for s in seq:
        if s not in seen:
            seen.add(s); out.append(s)
    return out

def _norm_upper_hyphen(s: str) -> str:
    # Normalize spaces to hyphen and upper-case for consistency
    s = re.sub(r'\s+', '-', s.strip())
    return s.upper()

def _extract_case_ids(text: str) -> List[str]:
    return _dedupe_preserve(_norm_upper_hyphen(m.group(0)) for m in _CASE_ID_RE.finditer(text or ""))

def _extract_policy_numbers(text: str) -> List[str]:
    return _dedupe_preserve(_norm_upper_hyphen(m.group(0)) for m in _POLICY_NO_RE.finditer(text or ""))

def _extract_order_numbers(text: str) -> List[str]:
    return _dedupe_preserve(_norm_upper_hyphen(m.group(0)) for m in _ORDER_NO_RE.finditer(text or ""))

# ---------------------------
# Intent-map (instruction lookup)
# ---------------------------
_INTENT_MAP_CACHE: Dict[str, Dict[str, str]] = {}
_INTENT_MAP_LAST_LOAD_TS: int = 0

def _now_s() -> int:
    import time
    return int(time.time())

def _fetch_from_redis() -> Dict[str, Dict[str, str]]:
    """Raw fetch from Redis and normalize keys → lower-case."""
    data: Dict[str, Dict[str, str]] = {}
    try:
        r = get_redis()
        raw = r.get(settings.REGISTRY_INTENT_MAP_KEY) or b"{}"
        parsed = json.loads(raw.decode("utf-8")) if isinstance(raw, (bytes, bytearray)) else (json.loads(raw) if raw else {})
        data = {str(k).lower(): {"intent": v.get("intent",""), "instruction": v.get("instruction","")}
                for k, v in (parsed or {}).items()}
    except Exception:
        data = {}
    return data

def _load_intent_map() -> Dict[str, Dict[str, str]]:
    """Fetch intent-map with memoization + periodic refresh based on INTENT_MAP_REFRESH_SEC."""
    global _INTENT_MAP_CACHE, _INTENT_MAP_LAST_LOAD_TS
    now_ts = _now_s()
    # Refresh on first call or after TTL
    if (not _INTENT_MAP_CACHE) or (
        settings.INTENT_MAP_REFRESH_SEC > 0 and (now_ts - _INTENT_MAP_LAST_LOAD_TS) >= settings.INTENT_MAP_REFRESH_SEC
    ):
        _INTENT_MAP_CACHE = _fetch_from_redis()
        _INTENT_MAP_LAST_LOAD_TS = now_ts
    return _INTENT_MAP_CACHE

def get_intent_instruction(map_key: str) -> Optional[str]:
    """Return instruction string for map_key if present; else None."""
    m = _load_intent_map()
    if not map_key:
        return None
    row = m.get(str(map_key).lower())
    return (row or {}).get("instruction") if row else None

def reload_intent_map() -> Tuple[int, int]:
    """Force a reload; returns (keys, ts). Useful for debug endpoints."""
    global _INTENT_MAP_CACHE, _INTENT_MAP_LAST_LOAD_TS
    _INTENT_MAP_CACHE = _fetch_from_redis()
    _INTENT_MAP_LAST_LOAD_TS = _now_s()
    return (len(_INTENT_MAP_CACHE), _INTENT_MAP_LAST_LOAD_TS)

def snapshot_intent_map() -> Dict[str, str]:
    """Safe, redacted view for debug: show keys only and whether instruction exists."""
    m = _load_intent_map()
    out: Dict[str, str] = {}
    for k, v in (m or {}).items():
        out[k] = "yes" if (v.get("instruction") or "").strip() else "no"
    return out

class ArtifactRegistry:
    def __init__(self):
        self.artifacts: Dict[str, ArtifactSpec] = {}
        self._defaults: Dict[str, Dict[str, Any]] = {}
        self._last_refresh = 0
        # NEW: dynamic intent map (IOC key -> {intent, instruction})
        self.intent_map: Dict[str, Dict[str, Any]] = {}

    def register(self, spec: ArtifactSpec):
        self.artifacts[spec.key] = spec
        # Capture defaults for overridable fields
        self._defaults[spec.key] = {
            "enabled": getattr(spec, "enabled", True),
            "priority": spec.priority,
            "ask_enabled": spec.ask_enabled,
            "passive_only": spec.passive_only
        }

    # --- NEW: Helpers for dynamic specs ------------------------------------
    def _build_extract_fn(self, pattern: str) -> Callable[[str], List[str]]:
        pat = re.compile(pattern, re.IGNORECASE)
        return lambda t, _p=pat: _p.findall(t or "")

    def _resolve_normalize_fn(self, name_or_flag: Optional[str]) -> Optional[Callable[[str], str]]:
        if not name_or_flag:
            return None
        v = (name_or_flag or "").strip().lower()
        if v in ("lower", "to_lower"):
            return lambda s: (s or "").lower()
        if v in ("digits_only", "numbers_only", "strip_non_digits"):
            return lambda s: re.sub(r"\D", "", s or "")
        # allow referencing built-ins by name
        if v == "normalize_phone":
            return normalize_phone
        if v == "normalize_upi":
            return normalize_upi
        if v == "normalize_url":
            return normalize_url
        if v == "normalize_bank":
            return normalize_bank
        return None

    def _build_validate_fn(self, pattern: Optional[str]) -> Optional[Callable[[str], bool]]:
        if not pattern:
            return None
        vp = re.compile(pattern, re.IGNORECASE)
        return lambda s, _vp=vp: bool(_vp.fullmatch(s or ""))

    def _apply_dynamic(self, dyn: Dict[str, Any]):
        """
        Register or update dynamic artifacts from a dict:
        {
          "myKey": {
            "pattern": "\\babc\\d{3}\\b",
            "normalize": "lower|digits_only|normalize_url|...",
            "validate_pattern": "^[a-z]{3}\\d{3}$",
            "priority": 30,
            "enabled": true,
            "ask_enabled": true,
            "passive_only": false,
            "conflicts_with": ["someOtherKey"]
          },
          ...
        }
        """
        if not isinstance(dyn, dict):
            return
        for key, spec in dyn.items():
            if not isinstance(spec, dict):
                continue
            pattern = spec.get("pattern")
            if not pattern:
                continue
            extract_fn = self._build_extract_fn(pattern)
            normalize_fn = self._resolve_normalize_fn(spec.get("normalize"))
            validate_fn = self._build_validate_fn(spec.get("validate_pattern"))
            conflicts = list(spec.get("conflicts_with") or [])
            priority = int(spec.get("priority", 0) or 0)
            ask_enabled = bool(spec.get("ask_enabled", True))
            passive_only = bool(spec.get("passive_only", False))
            enabled = bool(spec.get("enabled", True))

            if key in self.artifacts:
                s = self.artifacts[key]
                s.extract_fn = extract_fn
                s.normalize_fn = normalize_fn
                s.validate_fn = validate_fn
                s.conflicts_with = conflicts
                s.priority = priority
                s.ask_enabled = ask_enabled
                s.passive_only = passive_only
                s.enabled = enabled
            else:
                self.register(ArtifactSpec(
                    key=key,
                    extract_fn=extract_fn,
                    normalize_fn=normalize_fn,
                    validate_fn=validate_fn,
                    conflicts_with=conflicts,
                    priority=priority,
                    ask_enabled=ask_enabled,
                    passive_only=passive_only,
                    enabled=enabled,
                ))

    def extract_all(self, text: str) -> Dict[str, List[str]]:
        self._maybe_refresh_overrides()

        # Preservation of basic normalization logic
        text = self._basic_normalize(text)
        
        all_matches: List[Dict[str, Any]] = []

        for key, spec in self.artifacts.items():
            if not spec.enabled:
                continue
            matches = spec.extract_fn(text)
            for m in matches:
                normalized = spec.normalize_fn(m) if spec.normalize_fn else m
                if spec.validate_fn and not spec.validate_fn(normalized):
                    continue
                all_matches.append({
                    "key": key,
                    "raw": m,
                    "normalized": normalized,
                    "priority": spec.priority,
                    "conflicts_with": spec.conflicts_with
                })

        # Results aggregation
        results: Dict[str, List[str]] = {key: [] for key in self.artifacts.keys()}
        
        # Sort by raw length (longest first) then priority to resolve overlapping matches
        all_matches.sort(key=lambda x: (len(x["raw"]), x["priority"]), reverse=True)
        
        for m in all_matches:
            val = m["normalized"]
            key = m["key"]
            
            # Conflict rule enforcement
            is_conflicted = False
            for other_key in m["conflicts_with"]:
                if val in results.get(other_key, []):
                    is_conflicted = True
                    break
            
            if not is_conflicted and val not in results[key]:
                results[key].append(val)

        # Final canonicalization within the Registry aggregator
        # Ensures URLs are normalized/deduped even if upstream finders disagree
        if "phishingLinks" in results:
            results["phishingLinks"] = _canonicalize_urls(results.get("phishingLinks", []))

        return results

    def _basic_normalize(self, text: str) -> str:
        # Re-use logic from extractor.py
        text = re.sub(r'[\u2010-\u2015]', '-', text)
        text = re.sub(r'[\u200b-\u200d\ufeff]', '', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def _maybe_refresh_overrides(self):
        # Re-import settings at call time so tests can patch app.settings.settings
        from app.settings import settings as runtime_settings
        now = time.time()
        if now - self._last_refresh < runtime_settings.REGISTRY_TTL:
            return

        self._last_refresh = now
        try:
            from app.store.redis_conn import get_redis
            r = get_redis()

            # 1) Basic overrides for existing artifacts
            try:
                raw = r.get(runtime_settings.REGISTRY_OVERRIDES_KEY)
                overrides = {}
                if raw:
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        overrides = data
                self._apply_overrides(overrides)
            except Exception:
                pass

            # 2) Dynamic artifacts (add/update at runtime)
            try:
                dyn_raw = r.get(getattr(runtime_settings, "REGISTRY_DYNAMIC_KEY", "registry:dynamic"))
                if dyn_raw:
                    dyn = json.loads(dyn_raw)
                    self._apply_dynamic(dyn)
            except Exception:
                pass

            # 3) Intent map (IOC key -> {intent, instruction})
            try:
                im_raw = r.get(getattr(runtime_settings, "REGISTRY_INTENT_MAP_KEY", "registry:intent_map"))
                if im_raw:
                    im = json.loads(im_raw)
                    if isinstance(im, dict):
                        cleaned = {}
                        for k, v in im.items():
                            if isinstance(v, dict):
                                cleaned[k] = {
                                    "intent": v.get("intent"),
                                    "instruction": v.get("instruction"),
                                }
                        self.intent_map = cleaned
            except Exception:
                pass
        except Exception:
            # Maintain stability if Redis or JSON parsing fails
            pass

    def _apply_overrides(self, overrides: Dict[str, Any]):
        for key, spec in self.artifacts.items():
            # Revert to defaults first
            defaults = self._defaults.get(key, {})
            spec.enabled = defaults.get("enabled", True)
            spec.priority = defaults.get("priority", 0)
            spec.ask_enabled = defaults.get("ask_enabled", True)
            spec.passive_only = defaults.get("passive_only", False)

            # Apply overrides safely
            if key in overrides and isinstance(overrides[key], dict):
                ov = overrides[key]
                if "enabled" in ov:
                    spec.enabled = bool(ov["enabled"])
                if "priority" in ov:
                    spec.priority = int(ov["priority"])
                if "ask_enabled" in ov:
                    spec.ask_enabled = bool(ov["ask_enabled"])
                if "passive_only" in ov:
                    spec.passive_only = bool(ov["passive_only"])

artifact_registry = ArtifactRegistry()

# Extraction functions
def _extract_phones(text: str) -> List[str]:
    found = []
    for pat in _PHONE_PATTERNS:
        found.extend(pat.findall(text))
    # Add international matches; filter to plausible lengths
    try:
        for m in _PHONE_INTL_RE.findall(text or ""):
            if _valid_intl_phone(m):
                found.append(m)
    except Exception:
        pass
    return found

# Register core artifacts
artifact_registry.register(ArtifactSpec(
    key="phoneNumbers",
    extract_fn=_extract_phones,
    normalize_fn=normalize_phone,
    priority=10,
    conflicts_with=["bankAccounts"]
))

artifact_registry.register(ArtifactSpec(
    key="phishingLinks",
    extract_fn=lambda t: URL_RE.findall(t),
    normalize_fn=normalize_url,
    priority=20
))

artifact_registry.register(ArtifactSpec(
    key="upiIds",
    extract_fn=lambda t: UPI_RE.findall(t),
    normalize_fn=normalize_upi,
    priority=15
))

artifact_registry.register(ArtifactSpec(
    key="bankAccounts",
    extract_fn=lambda t: _ACCT_PATTERN.findall(t),
    normalize_fn=normalize_bank,
    priority=5,
    conflicts_with=["phoneNumbers"]
))

artifact_registry.register(ArtifactSpec(
    key="emailAddresses",
    extract_fn=lambda t: EMAIL_RE.findall(t or ""),
    normalize_fn=normalize_email,
    priority=9
))

# ✅ NEW: Case IDs / Policy Numbers / Order Numbers
artifact_registry.register(ArtifactSpec(
    key="caseIds",
    extract_fn=_extract_case_ids,
    normalize_fn=None, # Already normalized in extractor
    priority=8
))

artifact_registry.register(ArtifactSpec(
    key="policyNumbers",
    extract_fn=_extract_policy_numbers,
    normalize_fn=None, # Already normalized in extractor
    priority=7
))

artifact_registry.register(ArtifactSpec(
    key="orderNumbers",
    extract_fn=_extract_order_numbers,
    normalize_fn=None, # Already normalized in extractor
    priority=6
))
