from app.store.models import SessionState
from app.settings import settings

def build_final_payload(session: SessionState) -> dict:
    intel = session.extractedIntelligence
    extracted = {
        "sessionId": session.sessionId,
        "scamDetected": bool(session.scamDetected),
        "totalMessagesExchanged": int(session.totalMessagesExchanged),
        # ✅ NEW: Engagement duration now included (per Feb-19 example)
        "engagementDurationSeconds": int(getattr(session, "engagementDurationSeconds", 0) or 0),
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
    if getattr(settings, "INCLUDE_DYNAMIC_ARTIFACTS_CALLBACK", False):
        ei["dynamicArtifacts"] = getattr(intel, "dynamicArtifacts", {}) or {}
    extracted["extractedIntelligence"] = ei
    extracted["agentNotes"] = session.agentNotes or "Scammer used social engineering cues."
    return extracted
