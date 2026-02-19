import re
import time
import json
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Dict, Any
from app.settings import settings

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

# Regexes from existing extractor.py
UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32}\b")
# ✅ P1.2e v2: Robust single-pattern URL extractor (http(s)://… or www.…)
# Correct alternation: http(s)://... OR www....
URL_RE = re.compile(r"\b(?:https?://\S+|www\.\S+)", re.IGNORECASE)
_PHONE_PATTERNS = [
    re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}"),
    re.compile(r"1800[-\s]?\d{3}[-\s]?\d{3}"),
    re.compile(r"1800\d{6,7}"),
]
_ACCT_PATTERN = re.compile(r"\b(?:\d[ -]?){12,19}\b")

# Normalization utilities
def normalize_phone(s: str) -> str:
    # Remove spaces and hyphens but keep + and digits
    clean = re.sub(r"[^\d+]", "", s)
    if clean.startswith("1800") and len(clean) == 10:
        return f"{clean[:4]}-{clean[4:7]}-{clean[7:]}"
    return clean

def normalize_upi(s: str) -> str:
    return s.lower()

def normalize_url(u: str) -> str:
    u = u.strip().rstrip(').,]')
    if u.lower().startswith('www.'):
        u = 'https://' + u
    return u

def normalize_bank(s: str) -> str:
    return re.sub(r"\D", "", s)

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
