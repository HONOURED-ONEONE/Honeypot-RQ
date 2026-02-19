from app.store.models import SessionState
from app.settings import settings

def build_final_payload(session: SessionState) -> dict:
    intel = session.extractedIntelligence
    extracted = {
        "sessionId": session.sessionId,
        "scamDetected": bool(session.scamDetected),
        "totalMessagesExchanged": int(session.totalMessagesExchanged),
    }
    ei = {
        "bankAccounts": intel.bankAccounts,
        "upiIds": intel.upiIds,
        "phishingLinks": intel.phishingLinks,
        "phoneNumbers": intel.phoneNumbers,
        "suspiciousKeywords": getattr(intel, "suspiciousKeywords", []),
    }
    if getattr(settings, "INCLUDE_DYNAMIC_ARTIFACTS_CALLBACK", False):
        ei["dynamicArtifacts"] = getattr(intel, "dynamicArtifacts", {}) or {}
    extracted["extractedIntelligence"] = ei
    extracted["agentNotes"] = session.agentNotes or "Scammer used social engineering cues."
    return extracted
