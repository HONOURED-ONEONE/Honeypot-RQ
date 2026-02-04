from app.store.models import SessionState


def build_final_payload(session: SessionState) -> dict:
    intel = session.extractedIntelligence
    return {
        "sessionId": session.sessionId,
        "scamDetected": bool(session.scamDetected),
        "totalMessagesExchanged": int(session.totalMessagesExchanged),
        "extractedIntelligence": {
            "bankAccounts": intel.bankAccounts,
            "upiIds": intel.upiIds,
            "phishingLinks": intel.phishingLinks,
            "phoneNumbers": intel.phoneNumbers,
            "suspiciousKeywords": intel.suspiciousKeywords,
        },
        "agentNotes": session.agentNotes or "Scammer used social engineering cues.",
    }
