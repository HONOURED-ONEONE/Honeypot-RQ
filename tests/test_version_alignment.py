from app.settings import settings
from app.callback.payloads import build_final_payload
from app.store.models import SessionState

def test_contract_version_alignment():
    s = SessionState(sessionId="sv1")
    s.scamDetected = True
    s.totalMessagesExchanged = 10
    # minimally populate one EI key to avoid empty structures
    s.extractedIntelligence.phoneNumbers.append("+911234567890")
    payload = build_final_payload(s)
    ei_meta = payload.get("extractedIntelligence", {}).get("_meta", {})
    assert ei_meta.get("payloadVersion") == settings.CALLBACK_PAYLOAD_VERSION
    assert ei_meta.get("contractVersion") == settings.CALLBACK_PAYLOAD_VERSION
