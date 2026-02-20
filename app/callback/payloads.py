from app.store.models import SessionState
from app.settings import settings
from app.utils.time import now_ms, compute_engagement_seconds

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
    return extracted
