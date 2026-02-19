from app.store.models import SessionState
from app.settings import settings

def build_final_payload(session: SessionState) -> dict:
    intel = session.extractedIntelligence
    extracted = {
        "bankAccounts": intel.bankAccounts,
        "upiIds": intel.upiIds,
        "phishingLinks": intel.phishingLinks,
        "phoneNumbers": intel.phoneNumbers,
        "suspiciousKeywords": getattr(intel, "suspiciousKeywords", []),
    }
    if getattr(settings, "INCLUDE_DYNAMIC_ARTIFACTS_CALLBACK", False):
        extracted["dynamicArtifacts"] = getattr(intel, "dynamicArtifacts", {}) or {}

    return {
        "sessionId": session.sessionId,
        "scamDetected": bool(session.scamDetected),
        "totalMessagesExchanged": int(session.totalMessagesExchanged),
        "extractedIntelligence": extracted,
        "agentNotes": session.agentNotes or "Scammer used social engineering cues.",
    }