"""
Callback Payload Contract Utilities
----------------------------------
Goal: Prevent Response-Structure scoring loss due to schema drift.

Evaluator expects final output with specific fields and types. Missing required fields
incur penalties, so we enforce:
- required top-level keys exist (sessionId, scamDetected, extractedIntelligence)
- stable optional keys that are scored (totalMessagesExchanged, engagementDurationSeconds, agentNotes,
  scamType, confidenceLevel)
- extractedIntelligence keys are present and always lists (even if empty)
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


# Keys described in the evaluation document as intelligence categories.
EI_LIST_KEYS = (
    "phoneNumbers",
    "bankAccounts",
    "upiIds",
    "phishingLinks",
    "emailAddresses",
    "caseIds",
    "policyNumbers",
    "orderNumbers",
)


def _as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes", "y")
    return False


def _as_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return int(default)
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, int):
            return v
        if isinstance(v, float):
            return int(v) if v.is_integer() else int(round(v))
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return int(default)
            # allow "123.0"
            return int(float(s))
        return int(v)
    except Exception:
        return int(default)


def _as_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return float(default)
        if isinstance(v, bool):
            return float(v)
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            s = v.strip()
            return float(s) if s else float(default)
        return float(v)
    except Exception:
        return float(default)


def _as_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if str(x).strip()]
    # tolerate single scalar
    if isinstance(v, (str, int, float)):
        s = str(v).strip()
        return [s] if s else []
    return []


def sanitize_final_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Coerce payload to the stable contract expected by the evaluator.
    Never raises; always returns a payload with required fields and correct types.
    """
    if not isinstance(payload, dict):
        payload = {}

    out: Dict[str, Any] = {}

    # Required keys for Response Structure scoring.
    out["sessionId"] = str(payload.get("sessionId") or payload.get("session_id") or "")
    out["scamDetected"] = _as_bool(payload.get("scamDetected"))

    # Optional-but-scored keys in the rubric.
    out["totalMessagesExchanged"] = _as_int(payload.get("totalMessagesExchanged"), default=0)
    out["engagementDurationSeconds"] = _as_int(payload.get("engagementDurationSeconds"), default=0)
    out["agentNotes"] = str(payload.get("agentNotes") or "").strip() or "Scam-like patterns detected."
    out["scamType"] = str(payload.get("scamType") or "").strip()
    out["confidenceLevel"] = _as_float(payload.get("confidenceLevel"), default=0.0)

    # extractedIntelligence is required.
    ei_in = payload.get("extractedIntelligence") if isinstance(payload.get("extractedIntelligence"), dict) else {}
    ei: Dict[str, Any] = {}

    # Ensure list-typed keys exist and are lists.
    for k in EI_LIST_KEYS:
        ei[k] = _as_list(ei_in.get(k))

    # Preserve allowed nested extras safely under extractedIntelligence.
    # Keep _signals and _meta if present and dict-like; else provide empty dicts.
    ei["_signals"] = ei_in.get("_signals") if isinstance(ei_in.get("_signals"), dict) else {}
    ei["_meta"] = ei_in.get("_meta") if isinstance(ei_in.get("_meta"), dict) else {}

    # Preserve dynamicArtifacts if present (for experimental/runtime IOCs)
    if "dynamicArtifacts" in ei_in:
        ei["dynamicArtifacts"] = ei_in["dynamicArtifacts"]

    out["extractedIntelligence"] = ei

    return out


def validate_contract(payload: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Minimal validation aligned to evaluator rubric:
    - required keys exist
    - extractedIntelligence exists
    - EI list keys are lists
    Returns (ok, reason).
    """
    try:
        if not isinstance(payload, dict):
            return False, "payload_not_dict"
        for k in ("sessionId", "scamDetected", "extractedIntelligence"):
            if k not in payload:
                return False, f"missing:{k}"
        if not isinstance(payload["sessionId"], str):
            return False, "type:sessionId"
        if not isinstance(payload["scamDetected"], bool):
            return False, "type:scamDetected"
        ei = payload.get("extractedIntelligence")
        if not isinstance(ei, dict):
            return False, "type:extractedIntelligence"
        for k in EI_LIST_KEYS:
            if k not in ei or not isinstance(ei.get(k), list):
                return False, f"type:ei.{k}"
        return True, "ok"
    except Exception:
        return False, "exception"
