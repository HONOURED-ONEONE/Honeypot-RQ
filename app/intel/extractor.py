from app.intel.artifact_registry import artifact_registry

def _dedupe_extend(target_list, items):
    existing = set(target_list)
    for it in items:
        if it not in existing:
            target_list.append(it)
            existing.add(it)

def update_intelligence_from_text(session, text: str):
    """
    Registry-based intelligence extraction.
    Ensures single-source-of-truth governance.
    """
    # 1. Extraction via Registry (The ONLY authority)
    intel_results = artifact_registry.extract_all(text)
    
    # 2. Update session state with registered artifacts ONLY
    for key, values in intel_results.items():
        if hasattr(session.extractedIntelligence, key):
            target = getattr(session.extractedIntelligence, key)
            _dedupe_extend(target, values)

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

