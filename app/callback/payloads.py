from app.store.models import SessionState
from app.settings import settings
from app.utils.time import now_ms, compute_engagement_seconds
import json, hashlib

def build_final_payload(session: SessionState) -> dict:
    intel = session.extractedIntelligence
    
    # Robust duration computed from persisted session timeline:
    engagement_duration_seconds = compute_engagement_seconds(session.conversation or [])

    extracted = {
        "sessionId": session.sessionId,
        "scamDetected": bool(session.scamDetected),
        "totalMessagesExchanged": int(session.totalMessagesExchanged),
        # ✅ NEW: Engagement duration now included (per Feb-19 example)
        "engagementDurationSeconds": engagement_duration_seconds,
        # Optional structure bonuses
        "scamType": (session.scamType or ""),
        "confidenceLevel": float(getattr(session, "confidence", 0.0) or 0.0),
    }
    ei = {
        "bankAccounts": intel.bankAccounts,
        "upiIds": intel.upiIds,
        "phishingLinks": intel.phishingLinks,
        "phoneNumbers": intel.phoneNumbers,
        # ✅ NEW: include emails in final payload (supported by evaluator schema)
        "emailAddresses": intel.emailAddresses,
        # ✅ NEW: ID-like categories now included by Feb-19 rubric
        "caseIds": intel.caseIds,
        "policyNumbers": intel.policyNumbers,
        "orderNumbers": intel.orderNumbers,
        "suspiciousKeywords": getattr(intel, "suspiciousKeywords", []),
    }
    
    # Ensure ID-like categories are present (empty lists if none) to avoid evaluator misses
    # (Though extractedIntelligence dataclass defaults are lists, ensure presence in dict output)
    if "caseIds" not in ei: ei["caseIds"] = []
    if "policyNumbers" not in ei: ei["policyNumbers"] = []
    if "orderNumbers" not in ei: ei["orderNumbers"] = []

    if getattr(settings, "INCLUDE_DYNAMIC_ARTIFACTS_CALLBACK", False):
        ei["dynamicArtifacts"] = getattr(intel, "dynamicArtifacts", {}) or {}
    extracted["extractedIntelligence"] = ei
    extracted["agentNotes"] = session.agentNotes or "Scammer used social engineering cues."

    # ---- Group D: add payload version + fingerprint (canonical, stable ordering)
    extracted["payloadVersion"] = getattr(settings, "CALLBACK_PAYLOAD_VERSION", "1.0.0")
    try:
        algo = getattr(settings, "PAYLOAD_FINGERPRINT_ALGO", "sha256").lower()
        canonical = json.dumps(extracted, sort_keys=True, separators=(",", ":"))
        h = hashlib.new(algo)
        h.update(canonical.encode("utf-8"))
        extracted["payloadFingerprint"] = f"{algo}:{h.hexdigest()}"
    except Exception:
        # keep payload even if hashing fails
        extracted["payloadFingerprint"] = "na"
    return extracted

def validate_final_payload(payload: dict) -> (bool, str):
    """
    Minimal, dependency-free schema validation to catch shape drift before POST.
    Returns (ok, reason).
    """
    try:
        # Required top-level keys
        req = [
            ("sessionId", str),
            ("scamDetected", bool),
            ("totalMessagesExchanged", int),
            ("engagementDurationSeconds", int),
            ("extractedIntelligence", dict),
            ("payloadVersion", str),
            ("payloadFingerprint", str),
        ]
        for k, v in req:
            if k not in payload:
                return False, f"missing:{k}"
            # allow int-like floats only for ints that are whole numbers
            val = payload[k]
            if v is int and isinstance(val, float) and val.is_integer():
                continue
            if not isinstance(val, v):
                return False, f"type:{k}"
        ei = payload.get("extractedIntelligence") or {}
        # EI should contain lists for known keys; tolerate empties
        for name in ("phoneNumbers", "phishingLinks", "upiIds", "bankAccounts", "emailAddresses"):
            if name in ei and not isinstance(ei.get(name), list):
                return False, f"type:ei.{name}"
        return True, "ok"
    except Exception as e:
        return False, f"exception:{type(e).__name__}"
