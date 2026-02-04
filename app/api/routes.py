from fastapi import APIRouter, Depends
from app.api.schemas import HoneypotRequest, HoneypotResponse
from app.api.auth import require_api_key
from app.core.orchestrator import handle_event

router = APIRouter()

@router.post("/api/honeypot", response_model=HoneypotResponse, dependencies=[Depends(require_api_key)])
def honeypot(req: HoneypotRequest):
    reply = handle_event(req)
    return HoneypotResponse(status="success", reply=reply)
