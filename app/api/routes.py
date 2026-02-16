from typing import Any

from fastapi import APIRouter, Depends, Body, Request
from starlette.concurrency import run_in_threadpool

from app.api.schemas import HoneypotRequest, HoneypotResponse
from app.api.auth import require_api_key
from app.core.orchestrator import handle_event
from app.api.normalize import normalize_honeypot_payload

router = APIRouter()


async def _handle_honeypot(request: Request, payload: Any) -> HoneypotResponse:
    """Accept ANY payload (or no payload) and normalize into HoneypotRequest."""

    # If body missing or couldn't be parsed into payload, try reading it manually
    if payload is None:
        try:
            payload = await request.json()
        except Exception:
            payload = {}

    # If payload is not a dict, wrap or ignore
    if not isinstance(payload, dict):
        if isinstance(payload, str):
            payload = {"message": payload}
        else:
            payload = {}

    normalized = normalize_honeypot_payload(payload)
    req = HoneypotRequest.model_validate(normalized)
    out = await run_in_threadpool(handle_event, req)

    reply_val = ""
    if isinstance(out, tuple) and len(out) == 1:
        out = out[0]
    if isinstance(out, dict):
        reply_val = out.get("reply") or ""
    elif isinstance(out, str):
        reply_val = out
    else:
        reply_val = str(out)

    return HoneypotResponse(status="success", reply=reply_val)



# ✅ Main endpoint (what the spec expects)
@router.api_route(
    "/api/honeypot",
    methods=["POST", "GET"],
    response_model=HoneypotResponse,
    dependencies=[Depends(require_api_key)],
)
async def honeypot_api(request: Request, payload: Any = Body(None)):
    return await _handle_honeypot(request, payload)

# ✅ Root alias (some endpoint testers keep calling only /)
@router.api_route(
    "/",
    methods=["POST"],
    response_model=HoneypotResponse,
    dependencies=[Depends(require_api_key)],
)

async def honeypot_root(request: Request, payload: Any = Body(None)):
    return await _handle_honeypot(request, payload)
