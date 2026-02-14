import re
import time
import json
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Dict, Any

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
URL_RE = re.compile(r"\bhttps?://[^\s]+\b|\bwww\.[^\s]+\b", re.IGNORECASE)
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

    def register(self, spec: ArtifactSpec):
        self.artifacts[spec.key] = spec
        # Capture defaults for overridable fields
        self._defaults[spec.key] = {
            "enabled": getattr(spec, "enabled", True),
            "priority": spec.priority,
            "ask_enabled": spec.ask_enabled,
            "passive_only": spec.passive_only
        }

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
        from app.settings import settings
        now = time.time()
        if now - self._last_refresh < settings.REGISTRY_TTL:
            return
        
        self._last_refresh = now
        try:
            from app.store.redis_conn import get_redis
            r = get_redis()
            raw = r.get(settings.REGISTRY_OVERRIDES_KEY)
            
            overrides = {}
            if raw:
                data = json.loads(raw)
                if isinstance(data, dict):
                    overrides = data
            
            self._apply_overrides(overrides)
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
