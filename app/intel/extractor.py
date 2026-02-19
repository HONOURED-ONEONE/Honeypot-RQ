from app.intel.artifact_registry import artifact_registry
from app.intel.keywords import extract_keywords  # ✅ P0.2: keyword signals
#
# ✅ Tier-1 deterministic extraction (Regex-hardened)
#    Integrate core_extraction.extract_all() without breaking Registry invariants.
#    Registry remains the single source of “what keys exist” in scoring,
#    but we opportunistically merge core_extraction findings into the model.
#
from app.intel.core_extraction import extract_all as core_extract_all

def _dedupe_extend(target_list, items):
    existing = set(target_list)
    for it in items:
        if it not in existing:
            target_list.append(it)
            existing.add(it)

def _dedupe_extend_map(target_map, key, items):
    if target_map is None:
        return
    if key not in target_map or not isinstance(target_map.get(key), list):
        target_map[key] = []
    _dedupe_extend(target_map[key], items)

def update_intelligence_from_text(session, text: str):
    """
    Registry-based intelligence extraction.
    Ensures single-source-of-truth governance.
    """
    # --- 1) Registry extraction (kept as authoritative key set)
    reg_results = artifact_registry.extract_all(text)
    for key, values in reg_results.items():
        if hasattr(session.extractedIntelligence, key):
            target = getattr(session.extractedIntelligence, key)
            _dedupe_extend(target, values)
        else:
            # ✅ Keep dynamic bucket for any registry runtime keys
            try:
                dyn = getattr(session.extractedIntelligence, "dynamicArtifacts", None)
                _dedupe_extend_map(dyn, key, values)
            except Exception:
                pass

    # --- 2) Tier-1 deterministic extraction (core_extraction)
    # Merge in hardened regex results (phones, urls, upi, bank, emails).
    # These keys align with evaluator’s expected categories.
    # NOTE: Registry still governs finalization thresholds/counting upstream.
    try:
        ce = core_extract_all(text or "")
    except Exception:
        ce = {}

    # Map core_extraction -> Intelligence fields
    # (these five keys match the evaluator’s categories)
    CORE_KEYS = ("phoneNumbers", "phishingLinks", "upiIds", "bankAccounts", "emailAddresses")
    for k in CORE_KEYS:
        vals = ce.get(k, [])
        if not vals:
            continue
        if hasattr(session.extractedIntelligence, k):
            target = getattr(session.extractedIntelligence, k)
            _dedupe_extend(target, vals)
        else:
            # When Intelligence lacks a formal field (older sessions),
            # fall back to dynamicArtifacts to avoid schema breaks.
            try:
                dyn = getattr(session.extractedIntelligence, "dynamicArtifacts", None)
                _dedupe_extend_map(dyn, k, vals)
            except Exception:
                pass

    # 3) ✅ P0.2: Also compute and store suspicious keyword signals
    # This field is required by the final callback payload used in evaluation.
    try:
        kws = extract_keywords(text or "")
        if hasattr(session.extractedIntelligence, "suspiciousKeywords"):
            _dedupe_extend(session.extractedIntelligence.suspiciousKeywords, kws)
    except Exception:
        # Maintain stability if keyword extraction fails (non-influential)
        pass

# Backwards compatibility / Patch support
def normalize_text(text: str) -> str:
    return artifact_registry._basic_normalize(text)

def extract_phone_numbers(text: str):
    results = artifact_registry.extract_all(text)
    return results.get("phoneNumbers", [])

def extract_upi_ids(text: str):
    results = artifact_registry.extract_all(text)
    return results.get("upiIds", [])

def extract_bank_accounts(text: str):
    results = artifact_registry.extract_all(text)
    return results.get("bankAccounts", [])

# Convenience shim for callers that may want consolidated results quickly
def extract_all(text: str) -> dict:
    """
    Consolidated extraction using both Registry and core_extraction,
    returning a dict with the evaluator’s primary keys.
    """
    out = {
        "phoneNumbers": [],
        "phishingLinks": [],
        "upiIds": [],
        "bankAccounts": [],
        "emailAddresses": [],
    }
    try:
        reg = artifact_registry.extract_all(text or "")
        for k in out.keys():
            _dedupe_extend(out[k], reg.get(k, []))
    except Exception:
        pass
    try:
        ce = core_extract_all(text or "")
        for k in out.keys():
            _dedupe_extend(out[k], ce.get(k, []))
    except Exception:
        pass
    return out
