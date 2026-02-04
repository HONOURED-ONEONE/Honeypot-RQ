from fastapi import APIRouter, Depends, Body
from app.api.schemas import HoneypotRequest, HoneypotResponse
from app.api.auth import require_api_key
from app.core.orchestrator import handle_event
from app.api.normalize import normalize_honeypot_payload

router = APIRouter()


@router.post(
    "/api/honeypot",
    response_model=HoneypotResponse,
    dependencies=[Depends(require_api_key)],
)
def honeypot(payload: dict = Body(...)):
    """Accept a flexible payload and normalize it to our canonical HoneypotRequest."""
    normalized = normalize_honeypot_payload(payload)
    req = HoneypotRequest.model_validate(normalized)
    reply = handle_event(req)
    return HoneypotResponse(status="success", reply=reply)
