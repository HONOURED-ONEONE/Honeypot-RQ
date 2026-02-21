import json
from typing import Any

from fastapi import APIRouter, Depends, Body, Request
from starlette.concurrency import run_in_threadpool

from app.api.schemas import HoneypotRequest, HoneypotResponse
from app.api.auth import require_api_key
from app.core.orchestrator import handle_event
from app.api.normalize import normalize_honeypot_payload
from app.settings import settings
from app.intel.artifact_registry import snapshot_intent_map, reload_intent_map
from app.store.redis_conn import get_redis

router = APIRouter()

COMPAT_POST_PATHS = (
    "/api/honeypot",     # primary
    "/honeypot",         # common alias
    "/detect",           # evaluator example path style
    "/api/detect",       # extra safety
)


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


def _ping_reply() -> HoneypotResponse:
    # Safe “ping” response for GET requests; does not start a session.
    # The evaluator submission expects a publicly accessible endpoint and a stable JSON response.
    return HoneypotResponse(
        status="success",
        reply="Honeypot API is running. Send a POST request with {sessionId, message, conversationHistory, metadata}."
    )


# ---------------------------------------------------------------------------
# POST endpoints: accept compatible paths (submission/tooling variance)
# ---------------------------------------------------------------------------
for _path in COMPAT_POST_PATHS:
    @router.post(
        _path,
        response_model=HoneypotResponse,
        dependencies=[Depends(require_api_key)],
    )
    async def honeypot_post(request: Request, payload: Any = Body(None)):  # type: ignore
        return await _handle_honeypot(request, payload)


# ---------------------------------------------------------------------------
# GET endpoints: respond with a stable payload (no session creation)
# ---------------------------------------------------------------------------
for _path in COMPAT_POST_PATHS:
    @router.get(
        _path,
        response_model=HoneypotResponse,
        dependencies=[Depends(require_api_key)],
    )
    async def honeypot_get():  # type: ignore
        return _ping_reply()


# ✅ Root alias (some endpoint testers keep calling only /)
@router.api_route(
    "/",
    methods=["POST"],
    response_model=HoneypotResponse,
    dependencies=[Depends(require_api_key)],
)
async def honeypot_root(request: Request, payload: Any = Body(None)):
    return await _handle_honeypot(request, payload)


@router.get("/ping", response_model=HoneypotResponse, dependencies=[Depends(require_api_key)])
async def ping():
    return _ping_reply()


@router.get("/debug/feature-flags")
def debug_feature_flags(_=Depends(require_api_key)):
    """Read-only snapshot of runtime feature flags relevant to instruction-driven phrasing."""
    return {
        "BF_LLM_REPHRASE": bool(settings.BF_LLM_REPHRASE),
        "INTENT_MAP_REFRESH_SEC": int(settings.INTENT_MAP_REFRESH_SEC),
        "REGISTRY_INTENT_MAP_KEY": settings.REGISTRY_INTENT_MAP_KEY,
    }


@router.get("/debug/intent-map")
def debug_intent_map(_=Depends(require_api_key)):
    """Redacted view: shows keys present and whether an instruction is seeded for each."""
    return {"keys": snapshot_intent_map()}


@router.post("/debug/intent-map/reload")
def debug_intent_map_reload(_=Depends(require_api_key)):
    """Forces an in-process reload from Redis (useful after seeding)."""
    keys, ts = reload_intent_map()
    return {"reloadedKeys": keys, "reloadedAtEpoch": ts}


@router.get("/debug/last-callback/{session_id}")
def debug_last_callback_payload(session_id: str, _=Depends(require_api_key)):
    """
    Returns the last callback payload stored for this session (if enabled).
    Useful to compare your source-of-truth vs. any external summary views.
    """
    if not settings.STORE_LAST_CALLBACK_PAYLOAD:
        return {"enabled": False}
    try:
        r = get_redis()
        raw = r.get(f"session:{session_id}:last_callback_payload")
        return {"sessionId": session_id, "payload": (raw and json.loads(raw)) or None}
    except Exception:
        return {"sessionId": session_id, "payload": None}
