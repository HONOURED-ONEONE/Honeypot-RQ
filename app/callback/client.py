import httpx
import time
from typing import Dict, Tuple, Any, Optional
from app.settings import settings
from app.observability.logging import log

def send_final_result_http(payload: Dict[str, Any], headers: Dict[str, str], timeout: float = 5.0) -> Tuple[bool, int, Optional[str]]:
    """
    Pure HTTP sender for the final report.
    Returns (success, status_code, error_message).
    Does NOT handle persistence, retries, or ledger updates.
    """
    if not settings.GUVI_CALLBACK_URL:
        return False, 0, "No callback URL configured"

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(settings.GUVI_CALLBACK_URL, json=payload, headers=headers)
            
            if 200 <= resp.status_code < 300:
                return True, resp.status_code, None
            
            return False, resp.status_code, f"HTTP {resp.status_code}: {resp.text[:200]}"

    except Exception as e:
        return False, 0, str(e)
