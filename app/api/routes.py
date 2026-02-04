from typing import Any

from fastapi import APIRouter, Depends, Body, Request

from app.api.schemas import HoneypotRequest, HoneypotResponse
from app.api.auth import require_api_key
from app.core.orchestrator import handle_event
from app.api.normalize import normalize_honeypot_payload

router = APIRouter()


@router.api_route(
    "/api/honeypot",
    methods=["POST", "GET"],
    response_model=HoneypotResponse,
    dependencies=[Depends(require_api_key)],
)
async def honeypot(request: Request, payload: Any = Body(None)):
    """
    GUVI tester may send:
      - POST with empty body
      - POST with non-object JSON
      - GET without body
    We accept all of these and normalize to our canonical HoneypotRequest.
    """

    # If FastAPI couldn't parse JSON into 'payload' (missing body), try reading it
    if payload is None:
        try:
            payload = await request.json()
        except Exception:
            payload = {}

    # Convert non-dict JSON to dict wrapper so our normalizer can handle it
    if not isinstance(payload, dict):
        # If it's a string, treat it as message text; else just empty
        if isinstance(payload, str):
            payload = {"message": payload}
        else:
            payload = {}

    normalized = normalize_honeypot_payload(payload)
    req = HoneypotRequest.model_validate(normalized)
    reply = handle_event(req)
    return HoneypotResponse(status="success", reply=reply)
